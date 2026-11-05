# frozen_string_literal: true

require_relative 'factorio_protocol'
require_relative 'factorio_protocol/actions/types'

# Console formatting for a decoded input action: positions, entity refs,
# quickbar slots, item names. Pure presentation — no state changes, no
# player database. Kept out of the packet host so a new action's display
# (and its item/entity DB lookups) does not grow process_packet's file.
class ActionPresenter
  def initialize(item_db: nil, entity_db: nil, dump_raw_types: false)
    @item_db = item_db
    @entity_db = entity_db
    @dump_raw_types = dump_raw_types
  end

  def format(act)
    return '' unless act[:data] && act[:data].bytesize > 0
    d = act[:data]

    case act[:name]
    when :start_walking
      dir = FactorioProtocol::Actions::Position.direction(act)
      if dir && dir.size >= 2
        x, y = dir
        dirs = [
          [[1.0, 0.0], 'east'], [[-1.0, 0.0], 'west'],
          [[0.0, 1.0], 'south'], [[0.0, -1.0], 'north'],
          [[0.707, 0.707], 'southeast'], [[0.707, -0.707], 'northeast'],
          [[-0.707, 0.707], 'southwest'], [[-0.707, -0.707], 'northwest'],
        ]
        name = dirs.find { |(dx, dy), _| (x - dx).abs < 0.05 && (y - dy).abs < 0.05 }&.last
        if name
          return " dir=#{name}"
        else
          return " dir=(#{'%.1f' % x}, #{'%.1f' % y})"
        end
      end
    when :begin_mining_terrain
      pos = FactorioProtocol::Actions::Position.decode(act)
      return " pos=(#{'%.3f' % pos[0]}, #{'%.3f' % pos[1]})" if pos
    when :drop_item
      # 8-byte payload is a DIRECTION double, not a position (verified
      # 2026-08-16). Print it as a direction to avoid emitting a bogus
      # position from the raw i32s.
      dir = FactorioProtocol::Actions::Position.direction(act)
      return " dir=(#{'%.2f' % dir[0]})" if dir
    when :deconstruct
      area = FactorioProtocol::Actions::Position.decode(act)
      if area
        x1, y1, x2, y2 = area
        return " area=(#{'%.3f' % x1}, #{'%.3f' % y1})-(#{'%.3f' % x2}, #{'%.3f' % y2})"
      end
    when :open_item, :use_item, :start_repair
      if d.bytesize >= 4
        eid = d.unpack1('V')
        return " entity=##{eid}"
      end
    when :change_shooting_state
      pos = FactorioProtocol::Actions::Position.decode(act)
      if pos && d.bytesize >= 9
        return " shooting=#{d.getbyte(0)} pos=(#{'%.3f' % pos[0]}, #{'%.3f' % pos[1]})"
      end
    when :build
      pos = FactorioProtocol::Actions::Position.decode(act)
      if pos && d.bytesize >= 9
        dir = d.getbyte(8)
        dname = FactorioProtocol::Actions::Types::DIR_NAMES[dir] || dir
        return " pos=(#{'%.3f' % pos[0]}, #{'%.3f' % pos[1]}) dir=#{dname}"
      end
    when :move_on_pan
      pos = FactorioProtocol::Actions::Position.decode(act)
      return " pan=(#{'%.3f' % pos[0]}, #{'%.3f' % pos[1]})" if pos
    when :rotate_entity
      return " dir=#{d.getbyte(0)}"
    when :flush_opened_entity_specific_fluid
      # 1-byte selector (0x00/0x01 observed). Whether it is a fluid
      # prototype ID (prototypes.fluid order: 1=water, 4=petroleum-gas,
      # 5=light-oil …) is unverified — the fluid may be resolved by the
      # simulation (on_player_flushed_fluid event, Lua-only). Test: flush
      # a KNOWN fluid and compare the byte.
      return " selector=0x#{d.getbyte(0).to_s(16)}" if d.bytesize >= 1
    when :flush_opened_entity_fluid
      return " flush" if d.bytesize >= 1
    when :fast_entity_split
      return " slot=#{d.getbyte(0)}"
    when :fast_entity_transfer
      dir = d.getbyte(0) == 1 ? 'put' : 'take'
      return " #{dir}"
    when :change_riding_state
      return " vehicle=#{d.unpack1('v')}" if d.bytesize >= 2
    when :craft
      return " recipe_id=#{d.unpack1('V')}" if d.bytesize >= 4
    when :cursor_transfer
      if d.bytesize >= 9
        item_id = d.unpack1('v')
        item_name = @item_db ? @item_db.name(item_id) : "item_#{item_id}"
        action = d.unpack1('V', offset: 2)
        act = action == 1 ? 'put' : 'clear'
        return " #{item_name} #{act}"
      end
    when :open_gui
      if d.bytesize >= 14
        gt = d.getbyte(0)
        flag = d.getbyte(1)
        # Bytes 2-5: stable entity reference (tag + instance ID)
        ref_tag = d.getbyte(2)
        ref_hi = d.getbyte(3)
        ref_lo = d.unpack1('v', offset: 4)
        ref_id = (ref_hi << 16) | ref_lo
        # Bytes 6-9: per-call token (changes each invocation, not entity ID)
        token = d.unpack1('V', offset: 6)
        tick = d.unpack1('V', offset: 10) + 1
        gui_names = { 0x30 => 'entity', 0x31 => 'entity_close' }
        gname = gui_names[gt] || "type_#{gt}"
        state = flag == 0 ? 'open' : 'close'
        return " #{state} #{gname} ref=#{ref_tag}:#{ref_id} tok=#{token} tick=#{tick}"
      elsif d.bytesize >= 6
        # Client form (8 bytes): [gui_type][flags][tick(4)][pad(2)]
        gt = d.getbyte(0)
        flag = d.getbyte(1)
        tick = d.unpack1('V', offset: 2)
        gui_names = { 0x30 => 'entity', 0x31 => 'entity_close' }
        gname = gui_names[gt] || "type_#{gt}"
        state = flag == 0 ? 'open' : 'close'
        return " #{state} #{gname} tick=#{tick}"
      end
    when :selected_entity_changed_very_close,
         "selected_entity_changed_very_close_precise",
         "selected_entity_changed_relative"
      # NOT a decoded layout: hovering a known coal patch shows a payload
      # (0x56 = pumpjack in the entity table) that disagrees with the hovered
      # entity, so the leading byte is NOT the entity proto id. The real ref
      # is buried in the body and varies with the entity's content; don't
      # mislabel it. Show raw bytes for review.
      return " #{d[0, 18].unpack1('H*')}"
    when :selected_entity_cleared
      # Client: [tick(4)][pad(4)]; server echo: [55 ff ff ff][token(4)] (or
      # [41 ff ff ff]). The 0x54-echo heuristic the old code used was wrong —
      # real echoes start 55 ff ff ff — so unconsumed S→C echoes printed the
      # ref as if it were a tick (0xffffff55 -> 4294967125).
      if d.bytesize >= 8 && d.getbyte(0) == 0x55
        return " tok=#{d.unpack1('V', offset: 5)}"
      elsif d.bytesize >= 8
        tick = d.unpack1('V', offset: 0)
        return " tick=#{tick}"
      end
    when :zoom_around_point
      if d.bytesize >= 24
        a, b, c = d.unpack('E3')
        return " (#{'%.2f' % a}, #{'%.2f' % b}, #{'%.2f' % c})"
      end
    when :render_mode_changed
      return " mode=#{d.getbyte(0)}" if d.bytesize >= 1
    when :remote_view_surface
      if d.bytesize >= 4
        surf_id = d[0, 4].unpack1('N')
        return " surface=#{surf_id}"
      end
    when :setup_assembling_machine
      return " recipe=#{d.unpack1('v')}" if d.bytesize >= 2
    when :connect_rolling_stock, :disconnect_rolling_stock
      return " ref=#{d.unpack1('V')}" if d.bytesize >= 4
    when :pipette
      if d.bytesize >= 9
        src = d.getbyte(0)
        ref = d.unpack1('V', offset: 1)
        qual = d.getbyte(8)
        # src=0 (inventory/quickbar): ref is the ITEM prototype id
        # (`prototypes.item` order). src=4 (world entity): ref is the ENTITY
        # prototype id (`prototypes.entity` order) — capture-verified against
        # the live server: refs like 87=stone-furnace, 149=iron-ore,
        # 148=copper-ore. NOT an item id (item 87=nuclear-reactor,
        # 149=carbon — those never appear pipetted from the world) and NOT an
        # entity unit_number.
        if src == 0 && @item_db
          return " #{@item_db.name(ref)} qual=#{qual}"
        elsif src == 4 && @entity_db
          return " entity=#{@entity_db.name(ref)} qual=#{qual}"
        end
        return " src=#{src} ref=#{ref} qual=#{qual}"
      end
    when :stack_transfer, :inventory_transfer
      if d.bytesize >= 5
        item_id = d.unpack1('v')
        item_name = @item_db ? @item_db.name(item_id) : "item_#{item_id}"
        count = d.unpack1('v', offset: 2)
        return " #{item_name} count=#{count}"
      end
    when :quick_bar_set_slot, :quick_bar_pick_slot,
         :quick_bar_set_selected_page, :change_active_quick_bar
      qb = FactorioProtocol::Actions::QuickBar.decode(act)
      return " #{quickbar_str(qb)}" if qb.is_a?(Hash)
    when :copy
      return " flags=#{d.unpack1('v')}" if d.bytesize >= 2
    when :cheat
      return ''
    end

    return '' unless @dump_raw_types
    hex = d.bytes.first(8).map { |b| '%02x' % b }.join
    " [#{hex}#{d.bytesize > 8 ? '..' : ''}]"
  end

  def quickbar_str(qb)
    return " page=#{qb[:page]}" if qb.key?(:page)
    s = +" slot=#{qb[:slot]}"
    if qb.key?(:src) && qb[:op] != 0
      s << ' (cleared)'
    else
      s << " item=#{qb[:item]}"
      s << " from inv##{qb[:src]}" if qb[:src]
    end
    s
  end
end
