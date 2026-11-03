# frozen_string_literal: true

module FactorioProtocol
  # Input-action data-length policy. The fixed lengths come from ACTIONS_21;
  # this module handles the shapes the table cannot express: direction-dependent
  # echoes, variable name/string bodies, and a few trailing metadata forms.
  #
  # One place for "how many bytes does this action consume", so
  # HeartbeatPacket#parse_action stays a reader rather than a 300-line chain of
  # name checks. A wrong answer here is a desync: every later action in the
  # closure is misread, so each override carries its capture evidence.
  module ActionLengths
    extend WireDecode

    # => [length_or_nil, join_name_or_nil]
    def self.for(data, offset, type:, name:, base:, is_server:, is_last:)
      alen = base
      join_name = nil

      # Build: 9 bytes base (x+y+dir), 10 with ghost flag, 11 in drag mode.
      # Matched by NAME, not wire id.
      # The `unless alen.nil?` guard skips name-based rewrites when the
      # table explicitly has no length (types whose layout the parser
      # computes from structure, not a byte count) — otherwise a nil alen
      # would be overwritten to 11/10 and the action would consume bytes
      # that belong to the next one.
      if name == :build && !alen.nil?
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
      if name == :remote_view_surface
        alen = 24
      elsif name == :open_logistics_gui
        alen = 28 # same body in both directions (C→S pkt 153329)
      elsif is_server && name == :send_stacks_to_trash
        alen = 17
      elsif is_server && name == :deconstruct
        alen = 23 # 16-byte area + 7-byte echo metadata (00000180000001)
      elsif is_server && name == :selected_entity_changed_based_on_unit_number
        alen = 8 # S→C echo carries the unit-number reference
      elsif is_server && name == :player_join_game
        # Join echo: a [peer/mode header], [u8 name len], the name, then 2
        # trailing bytes. Older 2.1 captures use a 6-byte header (9+len;
        # pkt 17772, pkt 30236); stable 2.1.24 uses 4 (7+len; s2c-check-1
        # pkt 324 at tick 22976419: peer id 243, name morganc). Try the old
        # layout first, then the new one; a candidate name must be printable.
        [6, 4].each do |header|
          name_len = data.getbyte(offset + header).to_i
          next unless name_len.positive? && name_len <= FactorioProtocol::PlayerJoin::NAME_MAX
          next unless offset + header + 1 + name_len <= data.bytesize
          raw = data.byteslice(offset + header + 1, name_len).to_s.force_encoding(Encoding::UTF_8)
          next unless raw.valid_encoding? && !raw.strip.empty?
          next if raw.bytes.any? { |b| b < 0x20 || b == 0x7F }
          alen = 3 + header + name_len
          join_name = raw
          break
        end
      elsif is_server && name == :set_logistic_filter_item
        # S→C echo body is 22B, plus a 1B zero tail when present (the next
        # byte is 0; pkt 53819: 22B body + 00, then StopMovement type 32).
        # pkt 37042's next byte is zoom's 0x81, so that body is just 22.
        alen = (offset + 23 <= data.bytesize && data.getbyte(offset + 22) == 0x00) ? 23 : 22
      elsif is_server && name == :upgrade
        alen = 23 # S→C echo body (23B upgrade record)
      elsif is_server && name == :go_to_train_station
        alen = 13 # S→C echo body (station reference)
      elsif is_server && name == :set_ghost_cursor
        alen = 3 # S→C echo body
      elsif name == :set_circuit_condition
        alen = 11 # condition record, both directions (C→S pkt 212842)
      elsif is_server && name == :cancel_upgrade
        alen = 22 # S→C echo body (upgrade record)
      elsif is_server && name == :cursor_transfer
        # S→C echo is 16B (C→S table length), except when the 16th byte is
        # the 0xFF escape that starts the next action header: then it is 15B
        # (pkt 36236 cursor + 268 vs pkt 11188 cursor + 266).
        # 15 when the 16th byte starts the next action: a 0xFF escape (266)
        # or a bare close_gui type 0x3d (pkt 126774).
        nxt = offset + 16 <= data.bytesize ? data.getbyte(offset + 15) : nil
        alen = (nxt == 0xFF || nxt == 0x3D) ? 15 : 16
      elsif is_server && name == :inventory_transfer
        alen = 17 # S→C echo body (C→S table is 16)
      elsif is_server && name == :change_train_wait_condition
        alen = 19 # S→C echo body (pkt 4353, next action at +19)
      elsif is_server && name == :change_train_wait_condition_data
        alen = 33 # S→C echo body (pkt 3692/5583)
      elsif is_server && name == :remove_train_station
        alen = 13 # S→C echo body (pkt 81262, next 266 at +13)
      elsif is_server && name == :set_inventory_bar
        alen = 5 # S→C echo body (C→S table is 6; pkt 6437)
      elsif is_server && name == :start_research
        alen = 2 # S→C echo body (pkt 15831)
      elsif is_server && name == :remove_pin
        alen = 4 # S→C echo body (pkt 118232)
      elsif is_server && name == :move_research
        alen = 10 # S→C echo body (pkt 222493)
      elsif is_server && name == :build_rail
        alen = 20 # S→C echo body (pkt 211190/216116)
      elsif is_server && name == :modify_decider_combinator_condition
        alen = 19 # S→C echo body (pkt 2989, next 266 at +19)
      elsif name == :set_circuit_mode_of_operation
        alen = 2 # both directions (C→S table 12 is wrong; S→C pkt 15607, C→S pkt 212212)
      elsif is_server && name == :request_missing_construction_materials
        alen = 1 # S→C echo body (pkt 22665)
      elsif is_server && name == :cursor_split
        # S→C echo body: 15 bytes, plus a 1-byte tail unless the next byte
        # already starts an escaped action type (0xFF; pkt 38324 tick
        # 27622321). The 16-byte form was pkt 115862.
        alen = (offset + 15 < data.bytesize && data.getbyte(offset + 15) != 0xFF) ? 16 : 15
      elsif name == :set_entity_color
        alen = 4 # RGBA bytes, repeated per action (C→S pkt 171, no cache entry at +4)
      elsif name == :remote_view_entity
        alen = 19 # C→S body (pkt 27418705; next is the +8 closure trailer)
      elsif is_server && name == :quick_bar_pick_slot
        alen = 4 # S→C echo carries page/slot (f6 58 00 07 01 00; pkt 19200)
      elsif is_server && name == :select_mapper_slot_to
        alen = 9 # S→C echo body (pkt 97857)
      elsif name == :cancel_deconstruct
        alen = 23 # C→S body (pkt 57175, next 266 at +23)
      elsif name == :spawn_item
        alen = 2 # C→S body (pkt 159065, next 266 at +2)
      elsif name == :trash_not_requested_items
        alen = 1 # C→S bool body (pkt 6714)
      elsif name == :player_music_changed
        if is_server
          # S→C echo: [u8 length][track id string] ("fulgora-3", "gleba-10");
          # a zero length is the bare 1-byte form (pkt 13977).
          len = data.getbyte(offset)
          alen = (len && offset + 1 + len <= data.bytesize) ? 1 + len : 1
        else
          alen = 1
        end
      elsif name == :edit_display_panel
        # [u8 string length][string] — the panel title/path (pkt 200908:
        # 0x0c + "Armor Chest\n", then CloseGui).
        len = data.getbyte(offset)
        alen = (len && offset + 1 + len <= data.bytesize) ? 1 + len : nil
      elsif name == :copy
        alen = 22 # echo body in BOTH directions (C→S pkt 158050, S→C pkt 158058)
      elsif is_server && name == :select_item_filter
        alen = 6 # S→C echo body (filter slot record)
      elsif name == :player_locale_changed
        # [uint32v len][locale bytes] — variable length, locale codes differ.
        v_off, len = decode_uint32v(data, offset)
        alen = (len && v_off + len <= data.bytesize) ? v_off - offset + len : nil
      elsif name == :player_clicked_gps_tag
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
      if name == :open_gui
        # S→C: the GUI open echo carries NO body — the next action starts right
        # after the delta (server-observed pkt 21540: open_gui p88 then
        # stop_drag_build p88; pkt 41860: open_gui p88 then 266 p269). The old
        # "14 bytes if enough remain" read the following action headers as
        # entity/token metadata and produced Unknown(160)/Player_318.
        alen = is_server ? 0 : 8
      end

      # open_character_gui (2.1: 62) / open_blueprint_library_gui (2.1: 65):
      # the 1-byte GUI type in BOTH directions. Unlike
      # open_gui, the S→C echo appends NO entity/token/tick metadata — measured
      # on clean S→C echoes (client-20261027-201904 pkt 2250 ends `3e 24 01`:
      # type+delta+1 body byte, packet complete). The old `is_server ? 15 : 1`
      # over-consumed 14 bytes, overran the closure, and the unconditional
      # `tc[:hit_unknown] = false` reset then read the packet tail as a phantom
      # PeerDisconnect sync (giant peer_id → bogus "Player_49xxx left the game").
      if name == :open_character_gui || name == :open_blueprint_library_gui
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
      if name == :selected_entity_cleared
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
      if alen && %i[close_gui zoom_around_point move_on_pan close_remote_view
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

      [alen, join_name]
    end
  end
end
