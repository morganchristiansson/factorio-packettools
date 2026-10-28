# frozen_string_literal: true

require_relative 'factorio_packet'

module FactorioProtocol
  # ClientToServerHeartbeat (6) / ServerToClientHeartbeat (7).
  #
  # Everything about the heartbeat message lives here: the heartbeat flags +
  # sequence number framing, tick closures (which carry the input actions),
  # synchronizer actions, and heartbeat requests. The tick-closure/action
  # parsers are private to this class because no other message type uses
  # them — "all heartbeat knowledge in one place".
  class HeartbeatPacket < FactorioPacket
    # Largest defines.input_action in either version's dump (2.1: 355). An
    # input-action type above this cannot be real, so a 0xFF that "escapes" to
    # more than this is the literal type 255 instead.
    MAX_INPUT_ACTION = 400

    # build_terrain's layout (see parse_action): a 10-byte record per tile, the
    # 5-byte separator 00 00 00 AB 00 between records, and a 3-byte zero tail
    # after the last one (absent in the 25-byte form). NB 0xAB = 171, the
    # action's own ID.
    BT_RECORD = 10
    # C→S separator: 00 00 00 <id> 00, then a 00 00 00 tail. S→C echoes use
    # 01 01 00 <id> 00 between records and an 01 01 00 tail (the 01 01 is the
    # echo flag, not the record's data). Measured on client-20261028-102801
    # pkt 13/18/23: two records + 01 01 00 b5 00 + record + 01 01 00, then
    # the next real action. Reading only the C→S marker stopped after one
    # record and re-parsed the rest as stop_walking/nothing phantoms.
    BT_RECORD_MARK = "\x00\x00\x00\xAB\x00".b.freeze
    BT_RECORD_MARK_SC = "\x01\x01\x00".b.freeze
    BT_TAIL = "\x00\x00\x00".b.freeze
    BT_TAIL_SC = "\x01\x01\x00".b.freeze

    attr_reader :heartbeat

    private

    def parse_body
      _, @heartbeat = parse_heartbeat(@data, 1, is_server: @header[:msg_type] == 7)
      @result[:heartbeat] = @heartbeat
    end

    # ── Heartbeat ──────────────────────────────────────────────────

    def parse_heartbeat(data, offset, is_server: false)
      return [offset, nil] if offset >= data.bytesize

      hb = {
        flags: data.getbyte(offset),
        has_heartbeat_requests: false,
        has_tick_closures: false,
        has_single_tick_closure: false,
        all_tick_closures_are_empty: false,
        has_synchronizer_action: false,
        seq: nil,
        tick_closures: [],
        sync_actions: [],
        heartbeat_requests: [],
        hit_unknown: false,
      }

      f = hb[:flags]
      hb[:has_heartbeat_requests]       = (f & 0x01) != 0
      hb[:has_tick_closures]            = (f & 0x02) != 0
      hb[:has_single_tick_closure]      = (f & 0x04) != 0
      hb[:all_tick_closures_are_empty]  = (f & 0x08) != 0
      hb[:has_synchronizer_action]      = (f & 0x10) != 0
      offset += 1

      return [offset, hb] if offset + 4 > data.bytesize
      hb[:seq] = data.unpack1('V', offset: offset)
      offset += 4

      # Tick closures
      if hb[:has_tick_closures]
        count = hb[:has_single_tick_closure] ? 1 : data.getbyte(offset)
        offset += 1 unless hb[:has_single_tick_closure]
        tc_count = count.to_i

        tc_count.times do |i|
          break if offset >= data.bytesize || hb[:hit_unknown]
          # The C→S [tick][pad] trailer comes once per HEARTBEAT, after the
          # LAST closure — so only the final closure may hand its last action
          # the +8 trailer. Earlier closures end right after their actions;
          # consuming 8 bytes there swallows the next closure's 8-byte tick
          # (multi-closure heartbeat: phantom drag_train_wait_condition
          # Player_63 from a 266 in a non-final closure).
          is_last_closure = (i == tc_count - 1)
          offset, tc = parse_tick_closure(data, offset, hb[:all_tick_closures_are_empty],
                                          is_server: is_server, is_last_closure: is_last_closure)
          hb[:tick_closures] << tc if tc
          hb[:hit_unknown] = tc[:hit_unknown] if tc
        end
      end

      # Client-only: nextToReceiveServerTickClosure (8 bytes)
      if !is_server && !hb[:hit_unknown] && offset + 8 <= data.bytesize
        hb[:next_receive] = data.unpack1('Q<', offset: offset)
        offset += 8
      end

      # Synchronizer actions
      if hb[:has_synchronizer_action] && !hb[:hit_unknown]
        sync_start = offset
        offset, count = decode_uint32v(data, offset)
        # Sanity check: each sync action needs at least 3 bytes for server (1 type + 2 peer_id)
        # or 1 byte for client (1 type). If count is impossibly large, skip.
        min_per_sync = is_server ? 3 : 1
        if count && count > 0 && offset + (count * min_per_sync) > data.bytesize
          # Sync count is implausible — likely due to TC action length mismatch
          offset = sync_start  # reset to try other parsing paths
        else
          count.to_i.times do
            break if offset >= data.bytesize
            offset, sa = parse_synchronizer_action(data, offset, is_server)
            break unless sa
            hb[:sync_actions] << sa
            break if sa[:hit_unknown]
          end
        end
      end

      # Heartbeat requests
      if hb[:has_heartbeat_requests] && !hb[:hit_unknown] && offset < data.bytesize
        req_count = data.getbyte(offset)
        offset += 1
        req_count.times do
          break if offset + 4 > data.bytesize
          hb[:heartbeat_requests] << data.unpack1('V', offset: offset)
          offset += 4
        end
      end

      [offset, hb]
    end

    # ── Tick Closure ───────────────────────────────────────────────

    def parse_tick_closure(data, offset, is_empty, is_server: false, is_last_closure: true)
      return [offset, nil] if offset + 8 > data.bytesize
      tc = { tick: data.unpack1('Q<', offset: offset), actions: [], hit_unknown: false }
      offset += 8
      return [offset, tc] if is_empty

      # Action count with segment flag
      offset, count_flagged = decode_uint32v(data, offset)
      return [offset, tc] if count_flagged.nil?

      count = count_flagged >> 1
      has_segments = (count_flagged & 1) == 1
      tc[:action_count] = count

      # In drag-mode, the tick has more than 1 action and the first build action
      # has 11 bytes instead of 9 (includes position+dir+2 byte drag marker)
      is_drag = (count > 1)

      last_index = 0xFFFF
      # `count` counts non-padding actions. A `nothing` (type 0) is wire
      # padding: it still has a header to consume, but it must not use up one
      # of the counted slots and it must NOT move last_index (its delta is not
      # a player change). client-20261028-102801 pkt 1270: Build + nothing +
      # 2x266 decoded as Build + nothing + one 266, losing the second player
      # and shifting the first 16 places when the padding delta was applied.
      i = 0
      while i < count
        break if offset >= data.bytesize || tc[:hit_unknown]
        # In S→C echoes, the closure ends with a trailer: an optional
        # selection-echo `[55 ff ff ff ff][u32 ref]` followed by an 8-byte
        # per-closure tick (the previous tick, i.e. closure_tick - 1) that
        # `count` also counts. When the final bytes are that trailer it is NOT
        # an action — consume only from the trailer's start (the last
        # `55 ffffffff` marker, else just the trailing tick) so the real
        # echoed actions before it survive, and stop. Without this the
        # selection-echo/previous-tick become phantom actions (Player_44
        # send_stack_to_trash, Player_78 cursor_split, Player_86
        # paste_entity_settings after the real build/cleared echo).
        if is_server && i > 0 && (count - i) == 1 && offset + 8 <= data.bytesize
          tail_tick = data.unpack1('Q<', offset: data.bytesize - 8)
          if tail_tick == (tc[:tick] || 0) - 1 || tail_tick == (tc[:tick] || 0)
            marker = data.index("\x55\xff\xff\xff\xff".b, offset)
            offset = marker || data.bytesize - 8
            break
          end
        end
        # The C→S [tick][pad] closure trailer sits after the LAST action of
        # the LAST closure in the heartbeat (or after the segments when
        # present). Only that action may consume it — see parse_action.
        # Without this, the parser would eat the next action's header (or the
        # next closure's tick) as trailer bytes and invent phantom actions
        # with bogus player deltas (Player_192 swap_tile_slots,
        # Player_63 drag_train_wait_condition).
        is_last = is_last_closure && (i == count - 1) && !has_segments
        offset, act = parse_action(data, offset, last_index,
                                   is_drag: is_drag, is_server: is_server, is_last: is_last)
        break unless act
        tc[:actions] << act
        # Keep the wire (0-indexed) index only for the next delta calculation;
        # public action hashes expose the Lua-style 1-indexed game index.
        # S→C `nothing` is padding (it is not one of the closure's counted
        # slots and its delta is not a player change). In C→S it is a real
        # counted action, as in client_build_terrain_then_nothing_20.
        padding = is_server && act[:type].zero?
        last_index = act[:game_player] - 1 unless padding
        tc[:hit_unknown] = true if act[:hit_unknown]
        i += 1 unless padding
      end

      # Server-to-client heartbeats: the tick closure always starts with a
      # server_tick_info wrapper (type 85 in 2.1; stop_movement_in_the_next_tick
      # at 82 in 2.0) that carries the player/context for the echoed action(s).
      # It is NOT an input action — strip it (and any trailing metadata) so
      # only the real echoed C->S actions survive. The wrapper's delta already
      # decoded the player context during parse_action, so dropping it here is
      # safe: downstream code sees only real actions.
      if is_server
        # Strip the server_tick_info wrapper (type 85) but KEEP parse_action's
        # +1: the wire player is 0-indexed, while Lua/user-facing indexes are
        # 1-indexed. Subtracting 1 here made every S→C action name the player
        # one below the actor (client-20261028-105633: morganc/voltflake/
        # EMB_music/n700hybs appeared as the offline Toxmi/RojaRosa/
        # ummwhocares/klwht6). The action validator converts back to the
        # log's 0-indexed convention itself.
        tc[:actions].reject! { |a| a[:name] == 'server_tick_info' }
        tc[:hit_unknown] = false
      end

      # Parse segments — they contain action payloads (also adds actions not in input list)
      if has_segments && offset < data.bytesize && !tc[:hit_unknown]
        seg_count = data.getbyte(offset)
        offset += 1
        # Collect raw segments first: split chat messages span MULTIPLE
        # input-action segments (seg_no/total_segs), often across separate
        # packets. Same-closure segments are merged here (ordered by
        # seg_no); cross-packet groups carry seg_no/total_segs on the
        # action for the sniffer to reassemble (see
        # FactorioPacketTools#chat_action_data).
        segs = []
        seg_count.times do
          break if offset >= data.bytesize
          seg_type = data.getbyte(offset); offset += 1
          seg_blue = data.unpack1('V', offset: offset) rescue 0; offset += 4
          v_off, seg_green = decode_uint16v(data, offset); offset = v_off
          v_off, total_len = decode_uint32v(data, offset); offset = v_off
          v_off, seg_number = decode_uint32v(data, offset); offset = v_off
          # Payload: uint32v length + data
          v_off, pay_len = decode_uint32v(data, offset); offset = v_off
          next unless pay_len && pay_len > 0 && offset + pay_len <= data.bytesize
          segs << { type: seg_type, raw_player: seg_green, total: total_len,
                    no: seg_number, payload: data[offset, pay_len] }
          offset += pay_len
        end
        segs.group_by { |s| s[:type] }.each do |seg_type, parts|
          parts.sort_by! { |s| s[:no] }
          payload = parts.map { |s| s[:payload] }.join
          total_segs = parts.first[:total]
          seg_no = parts.first[:no]
          existing = tc[:actions]&.find { |a| a[:type] == seg_type }
          if existing
            existing[:data] = payload
            existing[:total_segs] = total_segs if total_segs
            existing[:seg_no] = seg_no
          else
            # Add new action from segment. Segment types follow the
            # server version's defines.input_action (see
            # FactorioProtocol.segment_types) — NOT the version-stable
            # main-action table. 2.0.77: chat arrives as a segment with
            # type 104 (write_to_console); 2.1 stable (build 87750): type 107.
            seg_name = FactorioProtocol.segment_action_name(seg_type)
            tc[:actions] << {
              type: seg_type, name: seg_name,
              game_player: parts.first[:raw_player] + 1,
              delta: 0, data: payload, hit_unknown: false,
              total_segs: total_segs, seg_no: seg_no
            }
          end
        end
      end

      [offset, tc]
    end

    # ── Input Action ───────────────────────────────────────────────

    def parse_action(data, offset, last_index, is_drag: false, is_server: false, is_last: false)
      type_offset = offset
      # 0xFF is BOTH the uint16v escape marker and the literal value 255: the
      # wire writes 0..255 in a single byte, so 255 (type
      # set_combinator_description, and any player delta of 255) is one byte
      # and only 256+ pays the 3-byte escape. factorio_dissector's
      # decode_uint16v (and this one, originally) treat 0xFF as an escape
      # unconditionally. Two ways out, both needed:
      # Only the TYPE is disambiguated, by magnitude: no real input action
      # exceeds 355 in either version's dump. The DELTA has no such bound — a
      # delta of 0xFFFF is a legitimate escape, and "the escape would reach
      # past the closure" is not proof either, because open_gui legitimately
      # swallows the trailer (3 fixtures depend on it). A trailing `FF FF`
      # therefore decodes with a 3-byte escape delta; the action count and the
      # trailer still land correctly, only the player index of that one action
      # is wrong. Not worth breaking three fixtures for.
      offset, type = decode_uint16v(data, offset)
      return [offset, nil] if type.nil?
      if type > MAX_INPUT_ACTION
        type = 0xFF
        offset = type_offset + 1
      end
      delta_offset = offset
      offset, delta = decode_uint16v(data, offset)
      return [offset, nil] if delta.nil?

      raw_player = (last_index + delta) & 0xFFFF
      game_player = raw_player + 1
      data_start = offset
      # Version-dependent table (ACTIONS_20 for 2.0, ACTIONS_21 for 2.1 stable) —
      # names AND data lengths come from the selected map. Stable 2.1.23
      # (build 87750) renumbered write_to_console from 106 → 107 and
      # shifted drop_item/build/start_walking by +1 (67→68, 68→69, 69→70).
      entry = FactorioProtocol.actions[type]
      name = entry ? entry[0] : "Unknown(#{type})"
      alen = entry ? entry[1] : nil

      # Build: 9 bytes base (x+y+dir), 10 with ghost flag, 11 in drag mode.
      # Version-agnostic: matched by NAME (2.0: build=66, 2.1 stable: 69).
      # The `unless alen.nil?` guard skips name-based rewrites when the
      # table explicitly has no length (types whose layout the parser
      # computes from structure, not a byte count) — otherwise a nil alen
      # would be overwritten to 11/10 and the action would consume bytes
      # that belong to the next one.
      if name == 'build' && !alen.nil?
        # The marker (01 01) means a drag build: 21 bytes in both directions
        # (S→C echoes the same two records — fixture s2c_drag_build_then_chat).
        # The ghost flag (00) makes 10. "is_drag" is only "this closure has
        # >1 action", so it must NOT imply an 11-byte build: a normal build
        # sent alongside hover/selection echoes was read as 11 bytes, eating
        # the next action's type byte and fabricating players from the header
        # (client-20261028-102801.pcap pkt 1270: Build + nothing + 2x266
        # became Build + paste_entity_settings Player_496 + Unknown(39)
        # Player_679).
        alen = if offset + 11 <= data.bytesize &&
                  data.getbyte(offset + 9) == 0x01 &&
                  data.getbyte(offset + 10) == 0x01
                 (offset + 21 <= data.bytesize) ? 21 : 11
               elsif offset + 10 <= data.bytesize && data.getbyte(offset + 9) == 0x00
                 10 # ghost
               else
                 9  # plain
               end
        # S→C echoes append a tail after a non-drag build body: 2 bytes for
        # a ghost build (base 10, `00 10`-style; pkt 1270/7509) and 4 bytes
        # for a normal build (base 9, `01 00 01 00`-style; pkt 17876 tick
        # 27602342 — the old +2 left `01 00` as a phantom StopWalking and
        # swallowed SelectedEntityChanged). Drag echoes already carry their
        # tail inside the 21-byte two-record form.
        alen += (alen == 10 ? 2 : 4) if is_server && alen < 21
      end

      # S→C-only echo bodies for actions whose C→S form is empty. The echo
      # carries the surface/inventory reference the other clients need, and
      # the log has one RemoteViewSurface/OpenLogisticsGui line per echo.
      # Without these the body was read as a run of `nothing`/destroy phantom
      # actions and the following real action (Zoom/266/StopWalking) was
      # shifted or turned into Unknown(255)/Unknown(51)
      # (client-20261028-102801 pkt 13792, 14067, 23175).
      if name == 'remote_view_surface'
        alen = 24
      elsif name == 'open_logistics_gui'
        alen = 28 # same body in both directions (C→S pkt 153329)
      elsif is_server && name == 'send_stacks_to_trash'
        alen = 17
      elsif is_server && name == 'deconstruct'
        alen = 23 # 16-byte area + 7-byte echo metadata (00000180000001)
      elsif is_server && name == 'selected_entity_changed_based_on_unit_number'
        alen = 8 # S→C echo carries the unit-number reference
      elsif is_server && name == 'player_join_game'
        # Join echo: 6-byte peer/mode header, [u8 name len], the name, then
        # 2 trailing bytes => 9 + name length (16 for a 7-char name, pkt
        # 17772; 19 for a 10-char name, pkt 30236).
        name_len = offset + 6 < data.bytesize ? data.getbyte(offset + 6) : 0
        alen = 9 + name_len
      elsif is_server && name == 'set_logistic_filter_item'
        # S→C echo body is 22B, plus a 1B zero tail when present (the next
        # byte is 0; pkt 53819: 22B body + 00, then StopMovement type 32).
        # pkt 37042's next byte is zoom's 0x81, so that body is just 22.
        alen = (offset + 23 <= data.bytesize && data.getbyte(offset + 22) == 0x00) ? 23 : 22
      elsif is_server && name == 'upgrade'
        alen = 23 # S→C echo body (23B upgrade record)
      elsif is_server && name == 'go_to_train_station'
        alen = 13 # S→C echo body (station reference)
      elsif is_server && name == 'set_ghost_cursor'
        alen = 3 # S→C echo body
      elsif name == 'set_circuit_condition'
        alen = 11 # condition record, both directions (C→S pkt 212842)
      elsif is_server && name == 'cancel_upgrade'
        alen = 22 # S→C echo body (upgrade record)
      elsif is_server && name == 'cursor_transfer'
        # S→C echo is 16B (C→S table length), except when the 16th byte is
        # the 0xFF escape that starts the next action header: then it is 15B
        # (pkt 36236 cursor + 268 vs pkt 11188 cursor + 266).
        # 15 when the 16th byte starts the next action: a 0xFF escape (266)
        # or a bare close_gui type 0x3d (pkt 126774).
        nxt = offset + 16 <= data.bytesize ? data.getbyte(offset + 15) : nil
        alen = (nxt == 0xFF || nxt == 0x3D) ? 15 : 16
      elsif is_server && name == 'inventory_transfer'
        alen = 17 # S→C echo body (C→S table is 16)
      elsif is_server && name == 'change_train_wait_condition'
        alen = 19 # S→C echo body (pkt 4353, next action at +19)
      elsif is_server && name == 'change_train_wait_condition_data'
        alen = 33 # S→C echo body (pkt 3692/5583)
      elsif is_server && name == 'remove_train_station'
        alen = 13 # S→C echo body (pkt 81262, next 266 at +13)
      elsif is_server && name == 'set_inventory_bar'
        alen = 5 # S→C echo body (C→S table is 6; pkt 6437)
      elsif is_server && name == 'start_research'
        alen = 2 # S→C echo body (pkt 15831)
      elsif is_server && name == 'remove_pin'
        alen = 4 # S→C echo body (pkt 118232)
      elsif is_server && name == 'move_research'
        alen = 10 # S→C echo body (pkt 222493)
      elsif is_server && name == 'build_rail'
        alen = 20 # S→C echo body (pkt 211190/216116)
      elsif is_server && name == 'modify_decider_combinator_condition'
        alen = 19 # S→C echo body (pkt 2989, next 266 at +19)
      elsif name == 'set_circuit_mode_of_operation'
        alen = 2 # both directions (C→S table 12 is wrong; S→C pkt 15607, C→S pkt 212212)
      elsif is_server && name == 'request_missing_construction_materials'
        alen = 1 # S→C echo body (pkt 22665)
      elsif is_server && name == 'cursor_split'
        # S→C echo body: 15 bytes, plus a 1-byte tail unless the next byte
        # already starts an escaped action type (0xFF; pkt 38324 tick
        # 27622321). The 16-byte form was pkt 115862.
        alen = (offset + 15 < data.bytesize && data.getbyte(offset + 15) != 0xFF) ? 16 : 15
      elsif name == 'set_entity_color'
        alen = 4 # RGBA bytes, repeated per action (C→S pkt 171, no cache entry at +4)
      elsif name == 'remote_view_entity'
        alen = 19 # C→S body (pkt 27418705; next is the +8 closure trailer)
      elsif is_server && name == 'quick_bar_pick_slot'
        alen = 4 # S→C echo carries page/slot (f6 58 00 07 01 00; pkt 19200)
      elsif is_server && name == 'select_mapper_slot_to'
        alen = 9 # S→C echo body (pkt 97857)
      elsif name == 'cancel_deconstruct'
        alen = 23 # C→S body (pkt 57175, next 266 at +23)
      elsif name == 'spawn_item'
        alen = 2 # C→S body (pkt 159065, next 266 at +2)
      elsif name == 'trash_not_requested_items'
        alen = 1 # C→S bool body (pkt 6714)
      elsif name == 'player_music_changed'
        if is_server
          # S→C echo: [u8 length][track id string] ("fulgora-3", "gleba-10");
          # a zero length is the bare 1-byte form (pkt 13977).
          len = data.getbyte(offset)
          alen = (len && offset + 1 + len <= data.bytesize) ? 1 + len : 1
        else
          alen = 1
        end
      elsif name == 'edit_display_panel'
        # [u8 string length][string] — the panel title/path (pkt 200908:
        # 0x0c + "Armor Chest\n", then CloseGui).
        len = data.getbyte(offset)
        alen = (len && offset + 1 + len <= data.bytesize) ? 1 + len : nil
      elsif name == 'copy'
        alen = 22 # echo body in BOTH directions (C→S pkt 158050, S→C pkt 158058)
      elsif is_server && name == 'select_item_filter'
        alen = 6 # S→C echo body (filter slot record)
      elsif name == 'player_locale_changed'
        # [uint32v len][locale bytes] — variable length, locale codes differ.
        v_off, len = decode_uint32v(data, offset)
        alen = (len && v_off + len <= data.bytesize) ? v_off - offset + len : nil
      elsif name == 'player_clicked_gps_tag'
        # [x u32][y u32][uint32v len][surface] — variable string.
        v_off, len = decode_uint32v(data, offset + 8)
        alen = (len && v_off + len <= data.bytesize) ? v_off - offset + len : nil
      end

      # open_gui: variable length, depends on direction.
      #   Client → server: 8 bytes [gui_type(1)][flags(1)][tick(4)][pad(2)].
      #     The tick is the local game tick when the click happened (hb tick - 3
      #     in captures). Reading 2 bytes here used to leave the 6-byte tail to
      #     be misparsed as phantom actions (e.g. add_decider_combinator_condition
      #     with a bogus player delta).
      #   Server echo: 14 bytes when it appends entity ref + token + tick,
      #     else the bare 2-byte form [gui_type][flags] (no entity info).
      if name == 'open_gui'
        # S→C: the GUI open echo carries NO body — the next action starts right
        # after the delta (server-observed pkt 21540: open_gui p88 then
        # stop_drag_build p88; pkt 41860: open_gui p88 then 266 p269). The old
        # "14 bytes if enough remain" read the following action headers as
        # entity/token metadata and produced Unknown(160)/Player_318.
        alen = is_server ? 0 : 8
      end

      # open_character_gui (2.0: 6 / 2.1: 61) / open_blueprint_library_gui
      # (2.0: 63 / 2.1: 64): the 1-byte GUI type in BOTH directions. Unlike
      # open_gui, the S→C echo appends NO entity/token/tick metadata — measured
      # on clean S→C echoes (client-20261027-201904 pkt 2250 ends `3e 24 01`:
      # type+delta+1 body byte, packet complete). The old `is_server ? 15 : 1`
      # over-consumed 14 bytes, overran the closure, and the unconditional
      # `tc[:hit_unknown] = false` reset then read the packet tail as a phantom
      # PeerDisconnect sync (giant peer_id → bogus "Player_49xxx left the game").
      if name == 'open_character_gui' || name == 'open_blueprint_library_gui'
        alen = 1
      end

      # selected_entity_cleared (2.0/2.1 both 9): the 8 bytes ACTIONS lists are
      # the C→S closure [tick][pad] trailer — the game sends the action with NO
      # data of its own, and the closure trailer follows the LAST action (hb
      # tick - 8 in captures). Intermediate actions carry no bytes; consuming 8
      # here used to eat the next action's header (phantom Player_192/etc.).
      # S→C echo is 0 bytes like the C→S form (empirically 13917/16346 echoes
      # at 0, the rest short packets) — the [ref(4)][token(4)] "selection echo"
      # is a separate closure trailer handled by the `55 ff ff ff ff` detection,
      # not part of this action. Assuming 8 overruns the closure into a phantom
      # sync action (selected_entity_cleared → bogus "Player_34177 left the
      # game", client-20261027-211335 pkt 8568).
      # S→C echo: 8 bytes [ref(4)][token(4)] when it carries the selection echo
      # (leading 0x55 marker, fixture s2c_cleared_echo_trailer), else 0 — the
      # same marker the per-closure trailer detection looks for. A blanket 8
      # (or blanket 0) is wrong: assuming 8 overruns a short leave broadcast
      # into a phantom sync action (→ bogus "Player_34177 left the game",
      # client-20261027-211335 pkt 8568).
      if name == 'selected_entity_cleared'
        alen = if is_server
          (data.getbyte(offset) == 0x55 && offset + 8 <= data.bytesize) ? 8 : 0
        else
          is_last ? 8 : 0
        end
      end

      # Hover/selection/zoom family (2.0/2.1 IDs differ; matched by name): the
      # ACTIONS len is the C→S payload only. C→S tick closures carry ONE
      # 8-byte [tick(4)][pad(4)] trailer after the LAST action (hb tick - 3
      # in captures); intermediate actions carry no trailer. Adding +8 to
      # every action used to swallow the next action's header and re-parse
      # payload bytes as phantom actions (zoom→swap_tile_slots Player_192,
      # selected_entity_changed→drag_train_wait_condition Player_64).
      # S→C echoes append [ref(4)][token(4)][tick-1(4)][pad(4)] = +16.
      # render_mode_changed is NOT in this family: its S→C echo carries the
      # same 1-byte payload as C→S. Adding +16 here over-consumed a render
      # mode echo (client-20261027-201904 pkt 6174) so the trailer's `02`
      # byte was skipped and the following well-formed sync
      # `01 0f <closure_tick> 0000` (SkippedTickClosure) read, one byte in,
      # as `count=2` + a phantom PeerDisconnect with peer_id=0xAE60=44640
      # ("Player_44641 left the game").
      if alen && %w[close_gui zoom_around_point move_on_pan close_remote_view
                    change_picking_state selected_entity_changed_very_close
                    selected_entity_changed_very_close_precise
                    selected_entity_changed_relative
                    selected_entity_changed_based_on_unit_number
                    set_use_inserter_filters].include?(name)
        alen = if is_server
          # +16 metadata exists only on a selection echo, and it starts with
          # the 55 ff ff ff marker AFTER the action body. "Enough bytes
          # remain" is not evidence: a multi-action S→C closure has plenty of
          # bytes after every action, so that test over-consumed each bare
          # echo and re-parsed the next action headers as body bytes (zoom →
          # phantom cheat/set_logistic_filter_item, and a 266 run that exploded
          # into fake players 499/636/773/... in client-20261028-101422).
          echo = offset + alen + 4 <= data.bytesize &&
                 data[offset + alen, 4] == "\x55\xff\xff\xff".b
          (echo && offset + alen + 16 <= data.bytesize) ? alen + 16 : alen
        else
          is_last ? alen + 8 : alen
        end
      end

      adata = nil
      hit_unknown = false

      # build_terrain (2.0: 171) — a LIST of 10-byte terrain records, each
      # record after the first preceded by the 5-byte separator 00 00 00 AB 00
      # (0xAB = 171, its own ID), then a 3-byte zero tail. The length tracks
      # the record count — 25 (two records), 28 (two with tail), 43 (three) —
      # so no table value fits it.
      # The tail belongs to the CLOSURE, not to the action, so it may only be
      # taken when 171 is the last action: otherwise those zero bytes are the
      # header of the `nothing` that follows it, and eating them desyncs the
      # rest of the closure (685 of the tail's flagged packets).
      # Matched on the 2.0 wire ID, not the name: 2.1 has the same layout at
      # wire 181 (0xB5) — the separator that follows each record re-uses the
      # action's own id as its marker byte.
      if (type == 171 || type == 181) && name == 'build_terrain'
        mark = ([0, 0, 0, type].pack('C4') + "\x00").b
        o = offset
        alen = 0
        while o + BT_RECORD <= data.bytesize
          alen += BT_RECORD
          o += BT_RECORD
          if is_server
            # S→C separators appear in both shapes: `01 ?? 00 <id> 00` (the
            # early echo form) and `00 00 00 <id> 00` (pkt 27122863). The
            # middle byte of the 01 form is the echo flag (00 or 01).
            b0 = data.getbyte(o)
            ok = if b0 == 0x00
                   data[o, 5] == mark
                 else
                   b0 == 0x01 &&
                     (data.getbyte(o + 1) || 0) <= 0x01 &&
                     data.getbyte(o + 2).zero? &&
                     data.getbyte(o + 3) == type &&
                     data.getbyte(o + 4).zero?
                 end
            break unless ok
          else
            break unless data[o, 5] == mark
          end
          alen += 5
          o += 5
        end
        # S→C always appends the 3-byte echo tail after the last record, even
        # when another action follows in the same closure. C→S only takes its
        # zero tail on the last action (otherwise the zeros ARE the next
        # `nothing` header).
        if is_server
          b0 = data.getbyte(o)
          tail_ok = b0 == 0x00 ? data[o, 3] == BT_TAIL
                               : b0 == 0x01 && (data.getbyte(o + 1) || 0) <= 0x01 && data.getbyte(o + 2).zero?
          alen += 3 if tail_ok
        elsif is_last && data[o, 3] == BT_TAIL && (data.getbyte(o + 3) || 0) != 0x00
          alen += 3
        end
      end

      # translate_string (2.0: 240) — [u8 count] then `count` localised
      # strings: [u8v key][01][00][u8v translation][9 bytes]. The 9 trailing
      # bytes are the argument block; it is 9 in 60 of the 68 occurrences in
      # captures/ and longer when an entry carries a nested localised string
      # as an argument (those 8 desync and get flagged — the same bargain
      # every majority length in the table makes). 2.0 wire ID, same
      # reason as build_terrain above.
      if type == 240 && name == 'translate_string'
        o = offset
        n = data.getbyte(o)
        alen = 0
        if n
          o += 1
          alen = 1
          complete = true
          n.times do
            kl = data.getbyte(o)
            # Fewer entries than `count` claims (or an entry cut short) means
            # the layout disagrees with us: the length below cannot be
            # trusted, so the action is unknown and parsing stops there. Read
            # kl BEFORE using it — adding 3 to a nil (past the end of the
            # payload) raised out of the decode and killed the packet.
            if kl.nil?
              complete = false
              break
            end
            tl = data.getbyte(o + kl + 3)
            unless tl
              complete = false
              break
            end
            alen += 1 + kl + 2 + 1 + tl + 9
            o += 1 + kl + 2 + 1 + tl + 9
          end
          alen = nil unless complete && alen == o - offset
        end
        alen = nil unless n && alen == o - offset
      end

      if alen && alen > 0 && offset + alen <= data.bytesize
        adata = data[offset, alen]
        offset += alen
      elsif alen == 0
        adata = ''.b
      elsif alen.nil?
        case name
        when 'remote_view_surface' # read 4 bytes for surface ID, then stop
          if offset + 4 <= data.bytesize
            adata = data[offset, 4]
            offset += 4
          end
          hit_unknown = true  # stop parsing further actions in this tick
        when 'write_to_console'
          s_off, s_len = decode_uint32v(data, offset)
          if s_len && s_off + s_len <= data.bytesize
            adata = data[offset, s_off - offset + s_len]
            offset = s_off + s_len
          else
            adata = nil
            hit_unknown = true
          end
        else
          adata = nil
          hit_unknown = true
        end
      else
        # alen > 0 but not enough data available
        adata = nil
        hit_unknown = true
      end

      [offset, {
        type: type, name: name, game_player: game_player,
        delta: delta, data: adata, hit_unknown: hit_unknown,
        type_offset: type_offset, data_offset: data_start,
      }]
    end

    # ── Synchronizer Action ────────────────────────────────────────

    def parse_synchronizer_action(data, offset, is_server)
      return [offset, nil] if offset >= data.bytesize
      type = data.getbyte(offset)
      offset += 1
      info = SYNCHRONIZER_ACTIONS[type] || "Unknown(0x#{type.to_s(16)})"

      sa = { type: type, name: info, data: nil, hit_unknown: false }

      case type
      when 0x01 # PeerDisconnect — 1 byte reason
        if offset < data.bytesize
          sa[:reason] = data.getbyte(offset)
          offset += 1
        end
      when 0x02 # NewPeerInfo — username string (uint32v-prefixed)
        s_off, s_len = decode_uint32v(data, offset)
        if s_len && s_off + s_len <= data.bytesize
          raw = data[s_off, s_len]
          # Guard against stream desyncs: a misaligned parse reads binary
          # (e.g. tick bytes) as the "username" and the sniffer would print
          # a garbage "joined the game" line. Real names never contain C0
          # controls/DEL (Unicode multibyte bytes are all >= 0x80); binary
          # data always does — reject it instead of emitting a phantom join.
          if raw.bytes.any? { |b| b < 0x20 || b == 0x7F }
            sa[:hit_unknown] = true
          else
            # Force UTF-8: a Unicode name must not stay binary-flagged (that
            # taints the hivemind prompt / players-cache.json / console output).
            sa[:username] = raw.force_encoding('UTF-8').scrub('?')
            offset = s_off + s_len
          end
        else
          sa[:hit_unknown] = true
        end
      when 0x03 # ClientChangedState
        if !is_server && offset < data.bytesize
          sa[:state] = data.getbyte(offset)
          offset += 1
        end
      when 0x0f, 0x10 # SkippedTickClosure / Confirm — 8-byte (uint64) tick
        # (the dissector decodes a 4-byte tick; live 2.x traffic carries the
        # full 8-byte updateTick — verified byte-exact on server-34197.pcap).
        if offset + 8 <= data.bytesize
          sa[:tick] = data.unpack1('Q<', offset: offset)
          offset += 8
        else
          sa[:hit_unknown] = true
        end
      when 0x04 # ClientShouldStartSendingTickClosures
        if offset + 8 <= data.bytesize
          sa[:data] = data[offset, 8]
          offset += 8
        end
      when 0x05 # MapReadyForDownload
        if is_server && offset + 8 <= data.bytesize
          sa[:data_size] = data.unpack1('Q<', offset: offset)
          offset += 8
          if offset + 8 <= data.bytesize
            sa[:aux_size] = data.unpack1('Q<', offset: offset)
            offset += 8
          end
          # Skip crc(4) + autosave_interval(4) +
          # autosave_slots(4) + autosave_only_on_server(1) + non_blocking_saving(1) = 14
          # …but keep update_tick(8): it is the map snapshot's game tick, the
          # anchor the SERVER derives our expected closure ticks from.
          if offset + 4 <= data.bytesize
            sa[:update_tick] = data.unpack1('Q<', offset: offset + 4) if offset + 12 <= data.bytesize
            offset += 22
          end
          # Consume script_checksums: count(u8) + count * (mod_name + crc(u32))
          if offset < data.bytesize
            sc_count = data.getbyte(offset)
            offset += 1
            sc_count.times do
              _, _ = decode_uint32v(data, offset)
              s_off, s_len = decode_uint32v(data, offset)
              if s_len && s_off + s_len <= data.bytesize
                offset = s_off + s_len + 4
              else
                sa[:hit_unknown] = true
                break
              end
            end
          end
          # Consume script_events: count(u8) + entries (complex)
          # Each entry: mod_name + standard_events_count(u8) + count*u32 +
          # nth_tick_events_count(u8) + count*u32 + standard_event_filters_count(u8) +
          # count*(u32*2) + bool + u8 + u8
          if !sa[:hit_unknown] && offset < data.bytesize
            se_count = data.getbyte(offset)
            offset += 1
            se_count.times do
              s_off, s_len = decode_uint32v(data, offset)
              if !s_len || s_off + s_len > data.bytesize
                sa[:hit_unknown] = true
                break
              end
              offset = s_off + s_len
              break if offset >= data.bytesize
              std_count = data.getbyte(offset)
              offset += 1
              offset += std_count * 4
              break if offset >= data.bytesize
              nth_count = data.getbyte(offset)
              offset += 1
              offset += nth_count * 4
              break if offset >= data.bytesize
              filt_count = data.getbyte(offset)
              offset += 1
              offset += filt_count * 8
              break if offset >= data.bytesize
              offset += 3  # bool + 2 u8s
            end
          end
          # Consume script_commands: count(u8) + entries (mod_name + count + mods)
          if !sa[:hit_unknown] && offset < data.bytesize
            cmd_count = data.getbyte(offset)
            offset += 1
            cmd_count.times do
              s_off, s_len = decode_uint32v(data, offset)
              if !s_len || s_off + s_len > data.bytesize
                sa[:hit_unknown] = true
                break
              end
              offset = s_off + s_len
              break if offset >= data.bytesize
              cmd_sub_count = data.getbyte(offset)
              offset += 1
              cmd_sub_count.times do
                s_off2, s_len2 = decode_uint32v(data, offset)
                break if !s_len2 || s_off2 + s_len2 > data.bytesize
                offset = s_off2 + s_len2
              end
            end
          end
          if sa[:hit_unknown]
            sa[:data_size] = nil  # parsing failed, discard
            sa[:aux_size] = nil
          end
        end
      when 0x12 # IncreasedLatencyConfirm — tick(8) + latency(1)
        if offset + 9 <= data.bytesize
          sa[:tick] = data.unpack1('Q<', offset: offset)
          sa[:latency] = data.getbyte(offset + 8)
          offset += 9
        else
          sa[:hit_unknown] = true
        end
      else
        # Use known lengths from SYNC_ACTION_LENS, or stop processing
        slen = SYNC_ACTION_LENS[type]
        if slen && offset + slen <= data.bytesize
          sa[:data] = data[offset, slen] if slen > 0
          offset += slen
        else
          sa[:hit_unknown] = true
        end
      end

      # Server-to-client messages append a 2-byte sender peer_id after action data
      if is_server && offset + 2 <= data.bytesize
        sa[:peer_id] = data.unpack1('v', offset: offset)
        offset += 2
      end

      [offset, sa]
    end
  end
end
