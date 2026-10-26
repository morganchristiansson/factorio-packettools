# frozen_string_literal: true

# Real packets captured from live Factorio sessions (ground truth).
#
# Each fixture is a raw UDP payload (`hex`) plus the EXPECTED parse result:
# the actions produced by FactorioProtocol.parse_udp_payload, in order.
# `data` is the hex of the action's data bytes ('' for empty, nil when the
# parser could not capture data). `chat` (optional) is the expected result of
# FactorioProtocol.decode_chat on that action's data.
#
# These packets come from live captures (2026-08-11, factorio_capture.pcap)
# and their expected output was verified against the actual gameplay session.
#
# NOTE: Client input actions carry an 8-byte trailing [tick(4)][pad(4)] field
# (the local game tick when the action occurred) that the server does not echo.
# For most actions it is left as unparsed trailing bytes; open_gui consumes it as
# part of its 8-byte client payload. Fixtures below lock in the current decoding.

REAL_PACKET_FIXTURES = [
  {
    name: 'player_quit',
    description: 'gameReseter final C→S heartbeat (factorio.pcap pkt 51944, 2026-08-16): clean quit = PeerDisconnect sync action (reason=0, NO peer_id — peer_id is the S→C broadcast form) + ClientChangedState state=8. No tick closures. Server mode treats this as the leave signal.',
    hex: '2610e3a61b1b45a99b00000000000201000308',
    actions: [],
  },
  {
    name: 'client_chat_message_0x0b',
    description: 'Player_12 chat with 0x0b message-type prefix. Regression: was truncated to 11 bytes (",that nuke ")',
    hex: '060634195f3970b6b1000000000001016bfc0000000b01002e0b2c74686174206e756b65206973206e6f7420676f6e6e612062652066696e6973686564207468697320686f75726cb6b10000000000',
    actions: [
      { type: 107, name: 'write_to_console', game_player: 12,
        data: '0b2c74686174206e756b65206973206e6f7420676f6e6e612062652066696e6973686564207468697320686f7572',
        chat: 'that nuke is not gonna be finished this hour' },
    ],
  },
  {
    name: 'client_open_gui_8b',
    description: 'Client open_gui with 8-byte payload [gui_type][flags][tick][pad], followed by a trailing nothing action. Regression: parser assumed 2 bytes, misread the payload tail as phantom action add_decider_combinator_condition (bogus player 36)',
    hex: '06069060406fa7230400000000000405013000a423040000000000',
    actions: [
      { type: 5, name: 'open_gui', game_player: 1,
        data: '3000a42304000000' },
      { type: 0, name: 'nothing', game_player: 1, data: '' },
    ],
  },
  {
    name: 'client_open_gui_8b_2',
    description: 'Client open_gui, second capture (phantom action was select_next_valid_gun, bogus player 59)',
    hex: '26060f77406f263a0400000000000405013000233a040000000000',
    actions: [
      { type: 5, name: 'open_gui', game_player: 1,
        data: '3000233a04000000' },
      { type: 0, name: 'nothing', game_player: 1, data: '' },
    ],
  },
  {
    name: 'client_open_gui_8b_3',
    description: 'Client open_gui, third capture (phantom action was copy_opened_blueprint, bogus player delta)',
    hex: '06067787406f8e4a04000000000004050130008b4a040000000000',
    actions: [
      { type: 5, name: 'open_gui', game_player: 1,
        data: '30008b4a04000000' },
      { type: 0, name: 'nothing', game_player: 1, data: '' },
    ],
  },
  {
    name: 'client_selected_entity_cleared',
    description: 'Client selected_entity_cleared (8 bytes: tick + padding) — fires when the cursor leaves an entity; confirmed by /toggle-action-logging tick correlation',
    hex: '0606549b5f39ef38b2000000000002090ce738b20000000000',
    actions: [
      { type: 9, name: 'selected_entity_cleared', game_player: 12,
        data: 'e738b20000000000' },
    ],
  },
  {
    name: 'client_stop_walking',
    description: 'Client stop_walking (0-byte data)',
    hex: '0606769c5f39113ab2000000000002010c0a3ab20000000000',
    actions: [
      { type: 1, name: 'stop_walking', game_player: 12, data: '' },
    ],
  },
  {
    name: 'client_pipette',
    description: 'Regenerated from the stable 2.1 captures: server-34197-20261025-084429.pcap.gz packet 34126, game tick(s) 4244037 (1 action(s)); expectations computed from its own stable decode',
    hex: '0606f2925b2b45c2400000000000025b18005d000000000001000040c2400000000000',
    actions: [
      { type: 91, name: 'pipette', game_player: 24,
        data: '005d0000000000010000' },
    ],
  },
  {
    name: 'client_use_item',
    description: 'Regenerated from the stable 2.1 captures: server-34197-20261025-084429.pcap.gz packet 39419, game tick(s) 4276764 (1 action(s)); expectations computed from its own stable decode',
    hex: '0606ce125c2b1c42410000000000027d18a83e0000813b01001842410000000000',
    actions: [
      { type: 125, name: 'use_item', game_player: 24,
        data: 'a83e0000813b0100' },
    ],
  },
  {
    name: 'client_change_riding_state',
    description: 'Regenerated from the stable 2.1 captures: server-34197-20261025-084429.pcap.gz packet 83385, game tick(s) 4409480 (3 action(s)); expectations computed from its own stable decode',
    hex: '06060a2f5e2b88484300000000000605183100ff0a0100a88548430000000000',
    actions: [
      { type: 5, name: 'open_gui', game_player: 24,
        data: '3100ff0a0100a885' },
      { type: 72, name: 'change_riding_state', game_player: 91,
        data: '0000' },
      { type: 0, name: 'nothing', game_player: 91, data: '' },
    ],
  },
  # ── C→S closure [tick][pad] trailer regression fixtures (2026-08-12) ──
  #
  # Client tick closures carry ONE 8-byte [tick(4)][pad(4)] trailer after the
  # LAST action. The parser used to add +8 to EVERY hover/zoom/pan family
  # action (60/128/129/262/265-268/310) and treated selected_entity_cleared
  # (9) as 8 bytes of data — so with 2+ actions in a closure it consumed the
  # next action's header as "trailer" and re-parsed leftover payload bytes as
  # phantom actions with bogus player deltas:
  #
  #   -> Player_192  swap_tile_slots          (zoom_around_point x2 closure)
  #   -> Player_64   drag_train_wait_condition (selected_entity_changed_very_close
  #                                             + start_walking closure)
  #
  # The phantom type/name depended on the leftover bytes; the phantom player
  # came from the garbage delta. Fixed: only the LAST action of a C→S closure
  # may consume the trailer (+8 for the family, 8 bytes for type 9);
  # intermediate actions use the raw payload length. Fixtures below lock the
  # correct multi-action decoding.

  {
    name: 'client_zoom_around_point_single',
    description: 'Regenerated from the stable 2.1 captures: server-34197-20261025-084429.pcap.gz packet 33634, game tick(s) 4237010 (1 action(s)); expectations computed from its own stable decode',
    hex: '060691715b2bd2a6400000000000028118000000000000f0bf00000000000053c00000000000005940b5a6400000000000',
    actions: [
      { type: 129, name: 'zoom_around_point', game_player: 24,
        data: '000000000000f0bf00000000000053c00000000000005940b5a6400000000000' },
    ],
  },
  {
    name: 'client_zoom_around_point_x2',
    description: 'Regenerated from the stable 2.1 captures: server-34197-20261025-084429.pcap.gz packet 33650, game tick(s) 4237144 (2 action(s)); expectations computed from its own stable decode',
    hex: '060617725b2b58a7400000000000048118000000000000f03f0000000000607cc00000000000b070408100000000000000f03f0000000000707cc00000000000b070403ba7400000000000',
    actions: [
      { type: 129, name: 'zoom_around_point', game_player: 24,
        data: '000000000000f03f0000000000607cc00000000000b07040' },
      { type: 129, name: 'zoom_around_point', game_player: 24,
        data: '000000000000f03f0000000000707cc00000000000b070403ba7400000000000' },
    ],
  },
  {
    name: 'client_zoom_around_point_x2_alt',
    description: 'Regenerated from the stable 2.1 captures: server-34197-20261025-084429.pcap.gz packet 33803, game tick(s) 4238863 (2 action(s)); expectations computed from its own stable decode',
    hex: '0606d6785b2b0fae400000000000048118000000000000f0bf0000000000c0614000000000000018c08100000000000000f0bf0000000000e0614000000000000014c008ae400000000000',
    actions: [
      { type: 129, name: 'zoom_around_point', game_player: 24,
        data: '000000000000f0bf0000000000c0614000000000000018c0' },
      { type: 129, name: 'zoom_around_point', game_player: 24,
        data: '000000000000f0bf0000000000e0614000000000000014c008ae400000000000' },
    ],
  },
  {
    name: 'client_selected_changed_plus_start_walking',
    description: 'selected_entity_changed_very_close (1B payload, NO +8) + start_walking (16B) + trailer. Regression: 266 consumed 1+8=9B, swallowing start_walking header 45 00; the middle of its 2 doubles (e6 3f = tail of the 0.7123 direction double) was re-parsed as phantom drag_train_wait_condition Player_64 (delta 63)',
    hex: '06066442c44e914500000000000004ff0a0101844600cc3b7f669ea0e63fcc3b7f669ea0e6bf8e45000000000000',
    actions: [
      { type: 266, name: 'selected_entity_changed_very_close', game_player: 1,
        data: '84' },
      { type: 70, name: 'start_walking', game_player: 1,
        data: 'cc3b7f669ea0e63fcc3b7f669ea0e6bf' },
    ],
  },
  {
    name: 'client_selected_cleared_plus_start_walking',
    description: 'selected_entity_cleared (intermediate action: NO 8-byte tick data — that is the closure trailer and only belongs to the last action) + start_walking + trailer. Regression: type 9 consumed 8B, swallowing the start_walking header',
    hex: '0606ba47c44e634b0000000000000409014600cc3b7f669ea0e63fcc3b7f669ea0e63f604b000000000000',
    actions: [
      { type: 9, name: 'selected_entity_cleared', game_player: 1,
        data: '' },
      { type: 70, name: 'start_walking', game_player: 1,
        data: 'cc3b7f669ea0e63fcc3b7f669ea0e63f' },
    ],
  },
  {
    name: 'client_drag_build_with_position',
    description: 'C→S drag build: the build action carries BOTH positions in one 21-byte payload (9B pos + 01 01 drag marker + 10B headerless drag position) followed by selected_entity_cleared. Regression: the parser read only 11B, leaving the drag position\'s bytes to be re-parsed as a phantom action — the position\'s x-byte 0x80 read as type 128 zoom_around_point with the next byte (0xfb) as delta → phantom Player_252',
    hex: '060619175202dbb800000000000004450280fbffff8002000000010180fbffff8004000000100900b3b8000000000000',
    actions: [
      { type: 69, name: 'build', game_player: 2,
        data: '80fbffff8002000000010180fbffff800400000010' },
      { type: 9, name: 'selected_entity_cleared', game_player: 2,
        data: 'b3b8000000000000' },
    ],
  },
  {
    name: 'client_open_character_gui_then_hover_stream',
    description: 'Regenerated from the stable 2.1 captures: server-34197-20261025-084429.pcap.gz packet 67170, game tick(s) 4380153 (40 action(s)); expectations computed from its own stable decode',
    hex: '060601ba5d2bf9d542000000000050ff0a011888ff0a010088ff0a010088ff0a010088ff0a010088ff0a010088ff0a010088ff0a010088ff0a010088ff0a010088ff0a010088ff0a010088ff0a010088ff0a010088ff0a010088ff0a010088ff0a010078ff0a010058ff0a010068ff0a010088ff0a010068ff0a010088ff0a010088ff0a010088ff0a010088ff0a010088ff0a010088ff0a010088ff0a010088ff0a010088ff0a010088ff0a010088ff0a010088ff0a010088ff0a010088ff0a010088ff0a010088ff0a010088ff0a010088ff0a010088f2d5420000000000',
    actions: [
      { type: 266, name: 'selected_entity_changed_very_close', game_player: 24,
        data: '88' },
      { type: 266, name: 'selected_entity_changed_very_close', game_player: 24,
        data: '88' },
      { type: 266, name: 'selected_entity_changed_very_close', game_player: 24,
        data: '88' },
      { type: 266, name: 'selected_entity_changed_very_close', game_player: 24,
        data: '88' },
      { type: 266, name: 'selected_entity_changed_very_close', game_player: 24,
        data: '88' },
      { type: 266, name: 'selected_entity_changed_very_close', game_player: 24,
        data: '88' },
      { type: 266, name: 'selected_entity_changed_very_close', game_player: 24,
        data: '88' },
      { type: 266, name: 'selected_entity_changed_very_close', game_player: 24,
        data: '88' },
      { type: 266, name: 'selected_entity_changed_very_close', game_player: 24,
        data: '88' },
      { type: 266, name: 'selected_entity_changed_very_close', game_player: 24,
        data: '88' },
      { type: 266, name: 'selected_entity_changed_very_close', game_player: 24,
        data: '88' },
      { type: 266, name: 'selected_entity_changed_very_close', game_player: 24,
        data: '88' },
      { type: 266, name: 'selected_entity_changed_very_close', game_player: 24,
        data: '88' },
      { type: 266, name: 'selected_entity_changed_very_close', game_player: 24,
        data: '88' },
      { type: 266, name: 'selected_entity_changed_very_close', game_player: 24,
        data: '88' },
      { type: 266, name: 'selected_entity_changed_very_close', game_player: 24,
        data: '88' },
      { type: 266, name: 'selected_entity_changed_very_close', game_player: 24,
        data: '78' },
      { type: 266, name: 'selected_entity_changed_very_close', game_player: 24,
        data: '58' },
      { type: 266, name: 'selected_entity_changed_very_close', game_player: 24,
        data: '68' },
      { type: 266, name: 'selected_entity_changed_very_close', game_player: 24,
        data: '88' },
      { type: 266, name: 'selected_entity_changed_very_close', game_player: 24,
        data: '68' },
      { type: 266, name: 'selected_entity_changed_very_close', game_player: 24,
        data: '88' },
      { type: 266, name: 'selected_entity_changed_very_close', game_player: 24,
        data: '88' },
      { type: 266, name: 'selected_entity_changed_very_close', game_player: 24,
        data: '88' },
      { type: 266, name: 'selected_entity_changed_very_close', game_player: 24,
        data: '88' },
      { type: 266, name: 'selected_entity_changed_very_close', game_player: 24,
        data: '88' },
      { type: 266, name: 'selected_entity_changed_very_close', game_player: 24,
        data: '88' },
      { type: 266, name: 'selected_entity_changed_very_close', game_player: 24,
        data: '88' },
      { type: 266, name: 'selected_entity_changed_very_close', game_player: 24,
        data: '88' },
      { type: 266, name: 'selected_entity_changed_very_close', game_player: 24,
        data: '88' },
      { type: 266, name: 'selected_entity_changed_very_close', game_player: 24,
        data: '88' },
      { type: 266, name: 'selected_entity_changed_very_close', game_player: 24,
        data: '88' },
      { type: 266, name: 'selected_entity_changed_very_close', game_player: 24,
        data: '88' },
      { type: 266, name: 'selected_entity_changed_very_close', game_player: 24,
        data: '88' },
      { type: 266, name: 'selected_entity_changed_very_close', game_player: 24,
        data: '88' },
      { type: 266, name: 'selected_entity_changed_very_close', game_player: 24,
        data: '88' },
      { type: 266, name: 'selected_entity_changed_very_close', game_player: 24,
        data: '88' },
      { type: 266, name: 'selected_entity_changed_very_close', game_player: 24,
        data: '88' },
      { type: 266, name: 'selected_entity_changed_very_close', game_player: 24,
        data: '88' },
      { type: 266, name: 'selected_entity_changed_very_close', game_player: 24,
        data: '88f2d5420000000000' },
    ],
  },
  {
    name: 'client_selected_changed_stream',
    description: '15x selected_entity_changed_very_close (1B payload each) interleaved with start_walking - the hover stream that previously derailed into phantom actions with players 137/191',
    hex: '060642bd5102e15e00000000000024ff0a0102b1ff0a010088ff0a010088ff0a010088ff0a010088ff0a010088ff0a010088ff0a010088ff0a010088ff0a010088ff0a010088ff0a010088ff0a010088ff0a010088ff0a0100884600cc3b7f669ea0e63fcc3b7f669ea0e6bfff0a0100884600cc3b7f669ea0e63fcc3b7f669ea0e6bfd95e000000000000',
    actions: [
      { type: 266, name: 'selected_entity_changed_very_close', game_player: 2, data: 'b1' },
      { type: 266, name: 'selected_entity_changed_very_close', game_player: 2, data: '88' },
      { type: 266, name: 'selected_entity_changed_very_close', game_player: 2, data: '88' },
      { type: 266, name: 'selected_entity_changed_very_close', game_player: 2, data: '88' },
      { type: 266, name: 'selected_entity_changed_very_close', game_player: 2, data: '88' },
      { type: 266, name: 'selected_entity_changed_very_close', game_player: 2, data: '88' },
      { type: 266, name: 'selected_entity_changed_very_close', game_player: 2, data: '88' },
      { type: 266, name: 'selected_entity_changed_very_close', game_player: 2, data: '88' },
      { type: 266, name: 'selected_entity_changed_very_close', game_player: 2, data: '88' },
      { type: 266, name: 'selected_entity_changed_very_close', game_player: 2, data: '88' },
      { type: 266, name: 'selected_entity_changed_very_close', game_player: 2, data: '88' },
      { type: 266, name: 'selected_entity_changed_very_close', game_player: 2, data: '88' },
      { type: 266, name: 'selected_entity_changed_very_close', game_player: 2, data: '88' },
      { type: 266, name: 'selected_entity_changed_very_close', game_player: 2, data: '88' },
      { type: 266, name: 'selected_entity_changed_very_close', game_player: 2, data: '88' },
      { type: 70, name: 'start_walking', game_player: 2,
        data: 'cc3b7f669ea0e63fcc3b7f669ea0e6bf' },
      { type: 266, name: 'selected_entity_changed_very_close', game_player: 2, data: '88' },
      { type: 70, name: 'start_walking', game_player: 2,
        data: 'cc3b7f669ea0e63fcc3b7f669ea0e6bf' },
    ],
  },
  # ── C→S payloads whose measured length fixed a desync (2026-10-03) ──
  #
  # Each of these types desynced the rest of its tick closure: 112/248 had no
  # length at all, the rest inherited a wrong guess from the 2.1 table by name.
  # The lengths are measured (tools/measure_action_lens.rb --decide over
  # captures/server-*.pcap.gz) and pinned here by a real packet each.
  {
    name: 'client_change_riding_state',
    description: 'Regenerated from the stable 2.1 captures: server-34197-20261025-084429.pcap.gz packet 83385, game tick(s) 4409480 (3 action(s)); expectations computed from its own stable decode',
    hex: '06060a2f5e2b88484300000000000605183100ff0a0100a88548430000000000',
    actions: [
      { type: 5, name: 'open_gui', game_player: 24,
        data: '3100ff0a0100a885' },
      { type: 72, name: 'change_riding_state', game_player: 91,
        data: '0000' },
      { type: 0, name: 'nothing', game_player: 91, data: '' },
    ],
  },

  # ── C→S chat from a player past 254: the ESCAPED player index (2026-10-03) ──
  #
  # The payload header is [uint16v player][uint32v len][text]. Above player
  # 254 the index is 0xff-escaped ([ff][u16 LE]), so every chat message on a
  # busy server starts 0xff — and the decoder read that as the 5-byte uint32v
  # length escape, printing "?d\u0001$mod bug or are we talking actual bug".
  {
    name: 'client_chat_player_356_escaped_index',
    description: 'captures/server-34197-20261003-164448.pcap.gz pkt 656: player 357, payload [ff 64 01 (=356)][0x34=52][text]',
    version: '2.0.77',
    hex: '2606e45ede2704fc2b08000000000101680d000000ff6401010038ff640134616e642069747320736f206261642074686174206920646f6e74206665656c20692063616e206275696c6420616e797468696e6702fc2b0800000000',
    actions: [
      { type: 104, name: 'write_to_console', game_player: 357,
        total_segs: 1, seg_no: 0,
        data: 'ff640134616e642069747320736f206261642074686174206920646f6e74206665656c20692063616e206275696c6420616e797468696e67',
        chat: 'and its so bad that i dont feel i can build anything' },
    ],
  },
  {
    name: 'client_chat_player_356_escaped_index_2',
    description: 'captures/server-34197-20261003-170056.pcap.gz pkt 413385: same shape, different closure flags',
    version: '2.0.77',
    hex: '060672af262473322d080000000001016801000000ff6401010028ff6401246d6f6420627567206f72206172652077652074616c6b696e672061637475616c2062756770322d0800000000',
    actions: [
      { type: 104, name: 'write_to_console', game_player: 357,
        total_segs: 1, seg_no: 0,
        data: 'ff6401246d6f6420627567206f72206172652077652074616c6b696e672061637475616c20627567',
        chat: 'mod bug or are we talking actual bug' },
    ],
  },

  # ── C→S split-chat reassembly regression fixtures (2026-08-16, 2.0.77) ──
  #
  # Long chat messages are split across MULTIPLE input-action segments, each
  # in its OWN packet, with the same seg_blue (segment-group id). Only the
  # FIRST segment carries the [player_index][total_len][text...] payload
  # header (player 0x00/0x40/0x42/…, total length as a Factorio uint32v —
  # 1 byte for lengths < 0xff, [0xff][uint32 LE] above); continuation
  # segments are raw text. FactorioPacketTools#chat_action_data reassembles
  # them by (player, total_segs, seg_no). decode_chat must return the FULL
  # message, and players >= 64 (0x40/0x42/…) must NOT be read as a length
  # prefix (that read the player byte as a length and TRUNCATED long
  # messages mid-word).
  {
    name: 'client_split_chat_2seg_p66_seg0',
    description: 'Player 66 (game 67) split chat, segment 0 of 2. payload starts [0x42(player66)][0x77(total_len=119)]. Was truncated at "...feelings toward" because 0x42 was read as a uint32v length 66',
    version: '2.0.77',
    hex: '06062ec99f600607a700000000000101680b000000420200644277686976656d696e6420776861742061726520796f757220706572736f6e616c2c20646565702c20616e642068696464656e206665656c696e677320746f77617264732074686520706c61796572206d6f7267616e632c20746865206b696e6420796fef06a70000000000',
    actions: [
      { type: 104, name: 'write_to_console', game_player: 67,
        total_segs: 2, seg_no: 0,
        data: '4277686976656d696e6420776861742061726520796f757220706572736f6e616c2c20646565702c20616e642068696464656e206665656c696e677320746f77617264732074686520706c61796572206d6f7267616e632c20746865206b696e6420796f' },
    ],
  },
  {
    name: 'client_split_chat_2seg_p66_seg1',
    description: 'Player 66 split chat, segment 1 of 2 — raw continuation (no player/len header) with the shared seg_blue 0x0b',
    version: '2.0.77',
    hex: '26062fc99f600707a700000000000101680b000000420201157520776f756c64206e657665722074656c6c2e2e2ef106a70000000000',
    actions: [
      { type: 104, name: 'write_to_console', game_player: 67,
        total_segs: 2, seg_no: 1,
        data: '7520776f756c64206e657665722074656c6c2e2e2e' },
    ],
  },
  {
    name: 'client_split_chat_4seg_p54_seg0',
    description: 'Player 54 (game 55) LONG split chat, segment 0 of 4 (298-byte message). Payload starts [0x36(player54)][uint32v len ff 2a 01 00 00 = 298]. Regressions: (a) split reassembly — only the last-write-won fragment was kept; (b) length is a uint32v LONG form (0xff + uint32 LE), not a single byte',
    version: '2.0.77',
    hex: '260662a1d410a39ba70000000000010168500000003604006436ff2a010000486976656d696e642c2074686520646566696e6974696f6e206f6620636f6e73656e737573206973206e6f7420657175616c20746f206265696e6720756e616e696d6f75733a20436f6e73656e737573206d65616e7320612067656e6572a09ba70000000000',
    actions: [
      { type: 104, name: 'write_to_console', game_player: 55,
        total_segs: 4, seg_no: 0,
        data: '36ff2a010000486976656d696e642c2074686520646566696e6974696f6e206f6620636f6e73656e737573206973206e6f7420657175616c20746f206265696e6720756e616e696d6f75733a20436f6e73656e737573206d65616e7320612067656e6572' },
    ],
  },
  {
    name: 'client_split_chat_4seg_p54_seg1',
    description: 'Player 54 split chat, segment 1 of 4 — raw continuation',
    version: '2.0.77',
    hex: '060663a1d410a49ba700000000000101685000000036040164616c206f7220776964657370726561642061677265656d656e7420616d6f6e6720612067726f7570206f662070656f706c652e204974206973206120736861726564206f70696e696f6e2c2062656c6965662c206f7220706f736974696f6e2074686174a19ba70000000000',
    actions: [
      { type: 104, name: 'write_to_console', game_player: 55,
        total_segs: 4, seg_no: 1,
        data: '616c206f7220776964657370726561642061677265656d656e7420616d6f6e6720612067726f7570206f662070656f706c652e204974206973206120736861726564206f70696e696f6e2c2062656c6965662c206f7220706f736974696f6e2074686174' },
    ],
  },
  {
    name: 'client_split_chat_4seg_p54_seg2',
    description: 'Player 54 split chat, segment 2 of 4 — raw continuation',
    version: '2.0.77',
    hex: '260664a1d410a59ba700000000000101685000000036040264206d6f7374206d656d62657273206f66206120636f6d6d756e697479206f72207465616d206163636570742c206576656e206966207468657920646f206e6f7420616c6c2066756c6c79206167726565206f6e2065766572792073696e676c6520646574a29ba70000000000',
    actions: [
      { type: 104, name: 'write_to_console', game_player: 55,
        total_segs: 4, seg_no: 2,
        data: '206d6f7374206d656d62657273206f66206120636f6d6d756e697479206f72207465616d206163636570742c206576656e206966207468657920646f206e6f7420616c6c2066756c6c79206167726565206f6e2065766572792073696e676c6520646574' },
    ],
  },
  {
    name: 'client_split_chat_4seg_p54_seg3',
    description: 'Player 54 split chat, segment 3 (final) of 4 — raw continuation',
    version: '2.0.77',
    hex: '260665a1d410a69ba70000000000010168500000003604030461696c2ea39ba70000000000',
    actions: [
      { type: 104, name: 'write_to_console', game_player: 55,
        total_segs: 4, seg_no: 3,
        data: '61696c2e' },
    ],
  },
  # ── Measured C→S payload lengths + content-defined actions (2026-09-26) ──
  #
  # Each description states the evidence the length came from, so a future
  # disagreement is a disagreement about evidence, not about a magic number:
  # a marker analysis over every occurrence, a per-closure candidate search,
  # or the game's own semantics (pipette carries the picked-up entity).
  {
    name: 'client_build_terrain_then_nothing_20',
    description: '2.0 build_terrain with TWO 10-byte terrain records (25 bytes: record, the 5-byte separator 00 00 00 AB 00, record) followed by a `nothing`. Regression for the closure tail: taking build_terrain\'s old 3-byte "tail" here ate the following `nothing` header and desynced the rest of the closure (685 of the tail\'s flagged packets). The payload is exactly 10 + 5*markers — verified against all 3 901 build_terrain payloads in captures/, every gap 10 bytes.',
    version: '2.0',
    hex: '0606e6e763590b897a060000000004ab0179cffeff476002000004000000ab006fcffeff47600200000400000008897a0600000000',
    actions: [
      { type: 171, name: 'build_terrain', game_player: 1, data: '79cffeff476002000004000000ab006fcffeff476002000004' },
      { type: 0, name: 'nothing', game_player: 1, data: '' },
    ],
  },
  # Frequent actions whose measured C→S length is now pinned (2026-09-26).
  # Each is the whole closure, so the length claim is the only thing that can
  # satisfy the byte budget.

  # ── C→S write_to_console (type 107) from a 2.1.23 stable server (build 87750) ──
  #
  # Verified against captures/server-34197-20261025-084429.pcap.gz (no desyncs,
  # 52 type-107 chat messages). In stable 2.1, write_to_console moved from
  # the experimental table's 106 to 107 (market_offer took 106); the name-based
  # hack in parse_action and decode_chat handle it without a table length.
  {
    name: 'stable_chat_reset',
    description: 'Player 24 (/reset command) on 2.1.23 stable. type 107 (not 106 — the experimental table numbers it 106, which is market_offer on stable). Single-segment, no random flag.',
    version: '2.1.23',
    hex: '060638795b2b71ae40000000000001016b010000001701000817062f72657365746aae400000000000',
    actions: [
      { type: 107, name: 'write_to_console', game_player: 24,
        total_segs: 1, seg_no: 0,
        data: '17062f7265736574', chat: '/reset' },
    ],
  },
  {
    name: 'stable_chat_evolution',
    description: 'Player 24 (/evolution command) on 2.1.23 stable. Same type 107, with the has_random flag (0x26 header). Verifies decode_chat handles the full [player][uint32v len][text] payload.',
    version: '2.1.23',
    hex: '260635245c2b845341000000000001016b060000001701000c170a2f65766f6c7574696f6e7f53410000000000',
    actions: [
      { type: 107, name: 'write_to_console', game_player: 24,
        total_segs: 1, seg_no: 0,
        data: '170a2f65766f6c7574696f6e', chat: '/evolution' },
    ],
  },
  {
    name: 'stable_chat_yo',
    description: 'Player 24 short chat "yo" on 2.1.23 stable. 2-byte payload after the [player][len] header — the parser must not read past the declared length.',
    version: '2.1.23',
    hex: '060617245d2b794e42000000000001016b0f000000170100041702796f764e420000000000',
    actions: [
      { type: 107, name: 'write_to_console', game_player: 24,
        total_segs: 1, seg_no: 0,
        data: '1702796f', chat: 'yo' },
    ],
  },
  {
    name: 'client_open_character_gui_hover',
    description: 'Regenerated from the stable 2.1 captures: server-34197-20261025-084429.pcap.gz packet 63240, game tick 4355960 (open_character_gui + hover in one closure); expectations computed from its own stable decode',
    hex: '0606154d5d2b7877420000000000043d180001ff0a0100697477420000000000',
    actions: [
      { type: 61, name: 'close_gui', game_player: 24,
        data: '0001' },
      { type: 266, name: 'selected_entity_changed_very_close', game_player: 24,
        data: '697477420000000000' },
    ],
  },
  {
    name: 'client_open_character_gui',
    description: 'Regenerated from the stable 2.1 captures: server-34197-20261025-084429.pcap.gz packet 34070, game tick 4243617 (1 action(s)); expectations computed from its own stable decode',
    hex: '06064e915b2ba1c0400000000000023e18019cc0400000000000',
    actions: [
      { type: 62, name: 'open_character_gui', game_player: 24,
        data: '01' },
    ],
  },
  {
    name: 'client_open_character_gui_hover',
    description: 'Regenerated from the stable 2.1 captures: server-34197-20261025-084429.pcap.gz packet 34650, game tick 4247248 (2 action(s)); expectations computed from its own stable decode',
    hex: '06067e9f5b2bd0ce400000000000043e1801ff0a010068cece400000000000',
    actions: [
      { type: 62, name: 'open_character_gui', game_player: 24,
        data: '01' },
      { type: 266, name: 'selected_entity_changed_very_close', game_player: 24,
        data: '68cece400000000000' },
    ],
  },

].freeze
