# frozen_string_literal: true

require_relative 'packet'
require_relative '../disconnect_reason'

module FactorioProtocol
  # ClientToServerHeartbeat (6) / ServerToClientHeartbeat (7).
  #
  # Everything about the heartbeat message lives here: the heartbeat flags +
  # sequence number framing, tick closures (which carry the input actions),
  # synchronizer actions, and heartbeat requests. The tick-closure/action
  # parsers are private to this class because no other message type uses
  # them — "all heartbeat knowledge in one place".
  class HeartbeatPacket < FactorioProtocol::Packet
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
    # three marker bytes + <id> 00 between records; the marker is 01 01 00 on
    # the older 2.1 captures and 01 00 01 on the current stable wire
    # (client-20261029-111409 pkt 32; the old exact 01 01 00 test stopped
    # after one record and re-parsed the rest as stop_walking/nothing).
    BT_RECORD_MARK = "\x00\x00\x00\xAB\x00".b.freeze
    BT_RECORD_MARK_SC = "\x01\x01\x00".b.freeze
    BT_TAIL = "\x00\x00\x00".b.freeze
    BT_TAIL_SC = "\x01\x01\x00".b.freeze

    # S→C player_leave_game metadata: the server follows the 0-byte action
    # with a counted `[reason u8][55 ff][(-game_index) u8][ff][ref u32]`
    # block. The reason byte is `defines.disconnect_reason` (DisconnectReason),
    # NOT a 0/1 "dropped" flag: 0 = quit, 1 = dropped, 7 = kicked, 9 = banned…
    # Accepting only 0/1 left every kick's block unconsumed and desynced the
    # rest of that tick closure (the 2026-11-05 BURM leave decoded as a phantom
    # close_gui instead of a metadata block). The block is counted as an action
    # slot, so consuming it also stops the phantom nothing/Unknown(255) parses.
    LEAVE_META_SIZE = 9

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
        offset, count = FactorioProtocol.decode_uint32v(data, offset)
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
            if sa[:hit_unknown]
              hb[:hit_unknown] = true
              break
            end
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

    # S→C player_leave_game metadata (see LEAVE_META_SIZE). The wire shape is
    # `[reason u8][55 ff][(-index) u8][ff][ref u32]`, where reason is any
    # defines.disconnect_reason value. The 55 ff / ff / negated-index shape is
    # what makes a chance match in an ordinary payload practically impossible;
    # the reason byte itself carries no structural constraint.
    def leave_metadata(data, offset, player)
      return nil unless offset + LEAVE_META_SIZE <= data.bytesize
      b = data.byteslice(offset, LEAVE_META_SIZE)
      return nil unless b.getbyte(1) == 0x55 && b.getbyte(2) == 0xFF &&
                        b.getbyte(4) == 0xFF &&
                        b.getbyte(3) == ((0x100 - (player & 0xFF)) & 0xFF)
      { reason: b.getbyte(0), ref: b.unpack1('V', offset: 5) }
    end

    # ── Tick Closure ───────────────────────────────────────────────

    def parse_tick_closure(data, offset, is_empty, is_server: false, is_last_closure: true)
      return [offset, nil] if offset + 8 > data.bytesize
      tc = { tick: data.unpack1('Q<', offset: offset), actions: [], hit_unknown: false }
      offset += 8
      return [offset, tc] if is_empty

      # Action count with segment flag
      offset, count_flagged = FactorioProtocol.decode_uint32v(data, offset)
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
        if is_server && act[:type] == 248
          if (meta = leave_metadata(data, offset, act[:game_player]))
            act[:leave_reason] = meta[:reason]
            act[:leave_reason_name] = DisconnectReason.name(meta[:reason])
            act[:leave_dropped] = meta[:reason] == 1
            act[:leave_ref] = meta[:ref]
            offset += LEAVE_META_SIZE
            i += 1 # the metadata occupies one of the counted action slots
          end
        end
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
        tc[:actions].reject! { |a| a[:name] == :server_tick_info }
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
          v_off, seg_green = FactorioProtocol.decode_uint16v(data, offset); offset = v_off
          v_off, total_len = FactorioProtocol.decode_uint32v(data, offset); offset = v_off
          v_off, seg_number = FactorioProtocol.decode_uint32v(data, offset); offset = v_off
          # Payload: uint32v length + data
          v_off, pay_len = FactorioProtocol.decode_uint32v(data, offset); offset = v_off
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
      offset, type = FactorioProtocol.decode_uint16v(data, offset)
      return [offset, nil] if type.nil?
      if type > MAX_INPUT_ACTION
        type = 0xFF
        offset = type_offset + 1
      end
      delta_offset = offset
      offset, delta = FactorioProtocol.decode_uint16v(data, offset)
      return [offset, nil] if delta.nil?

      raw_player = (last_index + delta) & 0xFFFF
      game_player = raw_player + 1
      data_start = offset
      # 2.1 stable names AND data lengths come from the one table.
      entry = FactorioProtocol.actions[type]
      name = entry ? entry[0] : "Unknown(#{type})"
      alen = entry ? entry[1] : nil
      # Length policy lives in ActionLengths (fixed table + echo/variable
      # overrides). Keep the content-defined build_terrain walk below.
      alen, join_name = FactorioProtocol::Actions::ActionLengths.for(
        data, offset, type: type, name: name, base: alen,
        is_server: is_server, is_last: is_last
      )

      adata = nil
      hit_unknown = false

      # build_terrain (2.1: 181) — a LIST of 10-byte terrain records, each
      # record after the first preceded by the 5-byte separator 00 00 00 B5 00
      # (0xB5 = 181, its own ID), then a 3-byte zero tail. The length tracks
      # the record count — 25 (two records), 28 (two with tail), 43 (three) —
      # so no table value fits it.
      # The tail belongs to the CLOSURE, not to the action, so it may only be
      # taken when 171 is the last action: otherwise those zero bytes are the
      # header of the `nothing` that follows it, and eating them desyncs the
      # rest of the closure (685 of the tail's flagged packets).
      # The separator that follows each record re-uses the action's own id
      # as its marker byte.
      if type == 181 && name == :build_terrain
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
                     (data.getbyte(o + 2) || 0) <= 0x01 &&
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
                               : b0 == 0x01 && (data.getbyte(o + 1) || 0) <= 0x01 &&
                                 (data.getbyte(o + 2) || 0) <= 0x01
          alen += 3 if tail_ok
        elsif is_last && data[o, 3] == BT_TAIL && (data.getbyte(o + 3) || 0) != 0x00
          alen += 3
        end
      end

      if alen && alen > 0 && offset + alen <= data.bytesize
        adata = data[offset, alen]
        offset += alen
      elsif alen == 0
        adata = ''.b
      elsif alen.nil?
        case name
        when :remote_view_surface # read 4 bytes for surface ID, then stop
          if offset + 4 <= data.bytesize
            adata = data[offset, 4]
            offset += 4
          end
          hit_unknown = true  # stop parsing further actions in this tick
        when :write_to_console
          s_off, s_len = FactorioProtocol.decode_uint32v(data, offset)
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

      act = {
        type: type, name: name, game_player: game_player,
        delta: delta, data: adata, hit_unknown: hit_unknown,
        type_offset: type_offset, data_offset: data_start,
      }
      act[:join_name] = join_name if join_name
      [offset, act]
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
          sa[:reason_name] = DisconnectReason.name(sa[:reason])
          offset += 1
        end
      when 0x02 # NewPeerInfo — username string (uint32v-prefixed)
        s_off, s_len = FactorioProtocol.decode_uint32v(data, offset)
        if s_len && s_off + s_len <= data.bytesize
          raw = data[s_off, s_len]
          # Guard against stream desyncs: a misaligned parse reads binary
          # (e.g. tick bytes) as the "username" and the sniffer would print
          # a garbage "joined the game" line. Real names never contain C0
          # controls/DEL (Unicode multibyte bytes are all >= 0x80); binary
          # data always does — reject it instead of emitting a phantom join.
          name = raw.dup.force_encoding(Encoding::UTF_8)
          if raw.bytes.any? { |b| b < 0x20 || b == 0x7F } || !name.valid_encoding?
            # Binary garbage or invalid UTF-8 is a misdecode, not a name:
            # hit_unknown makes the frame land in unknown.packets. Scrubbing
            # here would silently invent a different player.
            sa[:hit_unknown] = true
          else
            sa[:username] = name
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
              _, _ = FactorioProtocol.decode_uint32v(data, offset)
              s_off, s_len = FactorioProtocol.decode_uint32v(data, offset)
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
              s_off, s_len = FactorioProtocol.decode_uint32v(data, offset)
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
              s_off, s_len = FactorioProtocol.decode_uint32v(data, offset)
              if !s_len || s_off + s_len > data.bytesize
                sa[:hit_unknown] = true
                break
              end
              offset = s_off + s_len
              break if offset >= data.bytesize
              cmd_sub_count = data.getbyte(offset)
              offset += 1
              cmd_sub_count.times do
                s_off2, s_len2 = FactorioProtocol.decode_uint32v(data, offset)
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
