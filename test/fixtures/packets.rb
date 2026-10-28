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

  {
    # S→C closure with SEVERAL bare echo actions. The +16 selection-echo
    # trailer only exists on an echo that carries the 55 ff ff ff ff marker;
    # testing "enough bytes remain" instead made the first zoom consume the
    # following action headers and invent cheat/set_logistic_filter_item
    # players (client-20261028-101422.pcap pkt 5794, tick 24731737).
    name: 's2c_zoom_then_bare_266_and_walk',
    description: 'S→C multi-action closure: zoom_around_point (24B, NO +16) then selected_entity_changed_very_close (1B) then start_walking (16B). Regression: every family action was given +16 when bytes remained, swallowing the next headers and fabricating players 190/348',
    hex: '0706632c7a01596079010000000008550143826ee65860790100000000813f000000000000f03f00000000008070c00000000000c061c0ff0a01068746c8cc3b7f669ea0e63fcc3b7f669ea0e63f',
    actions: [
      { type: 129, name: 'zoom_around_point', game_player: 63,
        data: '000000000000f03f00000000008070c00000000000c061c0' },
      { type: 266, name: 'selected_entity_changed_very_close', game_player: 69,
        data: '87' },
      { type: 70, name: 'start_walking', game_player: 269,
        data: 'cc3b7f669ea0e63fcc3b7f669ea0e63f' },
    ],
  },
  {
    # S→C echo of a selected_entity_cleared: the closure's `count` includes the
    # trailing 8-byte previous-tick (closure_tick - 1, here d0 7f = 0x7fd0 =
    # 98256 = 98257 - 1). Regression: that tick was misread as a second action
    # (Player_448 send_stack_to_trash / Player_152 selected_entity_cleared).
    name: 's2c_cleared_echo_trailer',
    description: 'S→C selected_entity_cleared echo (client-20261027-195346.pcap) — trailing previous-tick consumed, no phantom action',
    hex: '0706d37f0100d17f01000000000004090155ffffff290c4973d07f010000000000',
    actions: [
      { type: 9, name: 'selected_entity_cleared', game_player: 1,
        data: '55ffffff290c4973' },
    ],
  },

  {
    # S→C echo of a selected_entity_changed_very_close: proto + echo marker +
    # ref + trailing previous-tick all inside the 17-byte echo (+16 family
    # tail), `count` = real actions + 1. Regression: a phantom stop_walking /
    # cursor_split was spawned after the real echo.
    name: 's2c_very_close_echo',
    description: 'S→C selected_entity_changed_very_close echo (client-20261027-195346.pcap), 17-byte payload, no trailing phantom',
    hex: '27063b7f0100397f01000000000004ff0a01015655ffffff44e1d160387f010000000000',
    actions: [
      { type: 266, name: 'selected_entity_changed_very_close', game_player: 1,
        data: '5655ffffff44e1d160387f010000000000' },
    ],
  },

  {
    # S→C echo of a build (placing an entity): the echoed build is followed by
    # a selection-echo `[55 ff ff ff ff][u32 ref]` then the previous-tick, all
    # counted by `count`. Regression: the selection-echo/previous-tick were
    # misread as Player_86 paste_entity_settings.
    name: 's2c_build_echo',
    description: 'S→C build echo (client-20261027-200449.pcap, infinity-chest placement) — selection-echo + previous-tick trailer consumed, no paste_entity_settings phantom',
    hex: '2706222c0200202c02000000000004450180f2ffff800800000000001055ffffff68eef8101f2c020000000000',
    actions: [
      { type: 69, name: 'build', game_player: 1,
        data: '80f2ffff8008000000000010' },
    ],
  },

  {
    # S→C echo of open_character_gui: the echoed body is the SAME 1-byte GUI
    # type as the C→S form — it does NOT append open_gui's 14-byte entity/
    # token/tick metadata. Regression: assuming 15 bytes overran the closure
    # and the packet tail was read as a phantom PeerDisconnect with a huge
    # peer_id (bogus "Player_49xxx left the game", client-20261027-211335
    # pkt 8676/8635). The packet ends right after the 1-byte body — clean.
    name: 's2c_open_character_gui_echo_1byte',
    description: 'S→C open_character_gui echo (client-20261027-201904.pcap pkt 2250) — 1-byte GUI body, packet complete, no phantom PeerDisconnect',
    hex: '270613434c01929f4b0100000000045501e93ca32c919f4b01000000003e2401',
    actions: [
      { type: 62, name: 'open_character_gui', game_player: 36,
        data: '01' },
    ],
  },
  {
    # S→C echo of set_use_inserter_filters: a selected-entity action whose
    # echo carries a 1-byte parameter (C→S len was wrongly 0). Regression:
    # reading 0 bytes overran the closure and the tail was read as a phantom
    # PeerDisconnect (bogus "Player_49311 left the game", client-20261027-211335
    # pkt 9625). Packet ends right after the body byte — clean.
    name: 's2c_set_use_inserter_filters_echo_1byte',
    description: 'S→C set_use_inserter_filters echo (client-20261027-201904.pcap) — 1-byte parameter, packet complete, no phantom PeerDisconnect',
    hex: '270693754c0112d24b01000000000455014275f85211d24b0100000000ff12010c01',
    actions: [
      { type: 274, name: 'set_use_inserter_filters', game_player: 12,
        data: '01' },
    ],
  },

  {
    # C→S build_terrain (2.1 wire 181) placing one tile: 10-byte record +
    # 3-byte closure tail = 13-byte payload, then the [tick][pad] trailer.
    # Regression: only 2.0's wire 171 had the record-list parser, so 181 read
    # 0 bytes and desynced into Player_243 change_train_wait_condition.
    name: 'client_build_terrain_181',
    description: 'C→S build_terrain (181, single stone/concrete tile, 13B) from client-20261027-200842.pcap',
    hex: '0606048cfa75f17702000000000002b501edf0ffff9a0a00000002000000f077020000000000',
    actions: [
      { type: 181, name: 'build_terrain', game_player: 1,
        data: 'edf0ffff9a0a00000002000000' },
    ],
  },
  {
    # S→C echo of render_mode_changed followed by a SkippedTickClosure sync.
    # Regression: render_mode_changed was in the S→C "+16 byte trailer" family
    # (client-20261027-201904.pcap pkt 6174), so it over-consumed, the trailer's
    # one-byte `02` payload was skipped, and the well-formed sync
    # `01 0f <closure_tick> 0000` was read, one byte in, as `count=2` + a phantom
    # PeerDisconnect with peer_id=0xAE60=44640 → bogus "Player_44641 left the game".
    name: 's2c_render_mode_changed_sync_not_phantom_peer',
    description: 'S→C render_mode_changed (gp107, 1-byte mode=02) + SkippedTickClosure sync (tick 21737056), NOT a phantom PeerDisconnect (client-20261027-201904.pcap pkt 6174)',
    hex: '0716e1514c0160ae4b01000000000455018eefa06e5fae4b0100000000ff36016b02010f60ae4b01000000000000',
    actions: [
      { type: 310, name: 'render_mode_changed', game_player: 107,
        data: '02' },
    ],
  },
  {
    # Real segments from the cross-message chat-corruption bug
    # (client-20261027-201904.pcap, 2026-10-27): three write_to_console
    # segments of split 2.1 chat from Player_8, all sharing the
    # (player, total=2) reassembly key. The S→C echo of the EARLIER message
    # strands a continuation-only group (its seg0 was never parsed); 30s later
    # the next message starts under the same key. chat_action_data must drop
    # the stale group (>15s) rather than merge it into the new message.
    # See test_stale_chat_segment_not_merged_into_next_message (client mode,
    # replays these real bytes).
    name: 's2c_chat_hittingbots_stale_seg1',
    description: 'S→C echo of the earlier message\'s split chat, continuation-only segment 1/2 (a stranded orphan: its seg0 never arrived). Keys [Player_8, 2], must be aged out before the next Player_8 total=2 message. client-20261027-201904.pcap pkt 69632.',
    version: '2.1',
    hex: '0706fe454d01dba14c0100000000035501685bbcecdaa14c0100000000016b240000000702011361742068697474696e672074686520626f7473',
    actions: [
      { type: 107, name: 'write_to_console', game_player: 8, total_segs: 2, seg_no: 1,
        data: '61742068697474696e672074686520626f7473' },
    ],
  },
  {
    name: 'client_chat_uranium_seg0',
    description: 'C→S split chat seg 0/2 (header + first 18 chars) — the real message "uranium will be back soon patience". client-20261027-201904.pcap pkt 71563.',
    version: '2.1',
    hex: '06066b0d784307a94c010000000001016b250000000702001407227572616e69756d2077696c6c206265206261fea84c0100000000',
    actions: [
      { type: 107, name: 'write_to_console', game_player: 8, total_segs: 2, seg_no: 0,
        data: '07227572616e69756d2077696c6c206265206261' },
    ],
  },
  {
    name: 'client_chat_uranium_seg1',
    description: 'C→S split chat seg 1/2 (raw continuation, last 16 chars) of the same message. client-20261027-201904.pcap pkt 71565.',
    version: '2.1',
    hex: '26066c0d784308a94c010000000001016b2500000007020110636b20736f6f6e2070617469656e6365ffa84c0100000000',
    actions: [
      { type: 107, name: 'write_to_console', game_player: 8, total_segs: 2, seg_no: 1,
        data: '636b20736f6f6e2070617469656e6365' },
    ],
  },
  {
    # S→C echo of a drag build (two tile records) followed by a chat segment.
    # Regression: the drag-build echo read only 11 of its 21 bytes, so the
    # second record was misparsed and the following chat SEGMENT was read from
    # mid-record — "do we have large mining drills?" (EMB_music, scenario-log
    # tick 21830506) came out as a phantom instead. client-20261027-201904
    # pkt 101714/101715.
    name: 's2c_drag_build_then_chat_seg0',
    description: 'S→C echo of a drag build + the first half (seg 0/2) of EMB_music\'s chat. Segment must be extracted after the 21-byte drag-build echo. client-20261027-201904.pcap pkt 101714.',
    version: '2.1',
    hex: '2706d5c04d01691b4d01000000000555012fa10294681b4d010000000045678029000080e7ffff0c01018020000080e7ffff0010016b0100000058020014581f646f2077652068617665206c61726765206d',
    actions: [
      { type: 69, name: 'build', game_player: 103,
        data: '8029000080e7ffff0c01018020000080e7ffff0010' },
      { type: 107, name: 'write_to_console', game_player: 89, total_segs: 2, seg_no: 0,
        data: '581f646f2077652068617665206c61726765206d' },
    ],
  },
  {
    name: 's2c_drag_build_then_chat_seg1',
    description: 'S→C echo of the same drag build + the second half (seg 1/2) of the chat. client-20261027-201904.pcap pkt 101715.',
    version: '2.1',
    hex: '2706d6c04d016a1b4d010000000005550199c4440a691b4d01000000004567802a000080e7ffff0c01018020000080e7ffff0010016b010000005802010d696e696e67206472696c6c733f',
    actions: [
      { type: 69, name: 'build', game_player: 103,
        data: '802a000080e7ffff0c01018020000080e7ffff0010' },
      { type: 107, name: 'write_to_console', game_player: 89, total_segs: 2, seg_no: 1,
        data: '696e696e67206472696c6c733f' },
    ],
  },

  # ── S→C echo lengths that the C→S table cannot express (2026-10-28) ──
  # Every body below is a real client-20261028-102801.pcap packet, log-verified:
  # the echo body length is what makes the NEXT action's type/delta land.
  {
    name: 's2c_build_tail_two_266',
    description: 'S→C Build + 2x selected_entity_changed_very_close (pkt 1270, tick 24776126). Build echo is a 10B body plus its 2B S→C tail; it is NOT 11B just because the closure has >1 action. Regression: Build ate the next type byte, then the tail delta shifted 266 from players 269/326 to 285/342 (invalid Player_496/679).',
    hex: '0706d1da7a01be0d7a0100000000085501de39bb31bd0d7a010000000045e68030ffff80fb00000c000010ff0a0127b7ff0a013987',
    actions: [
      { type: 69, name: 'build', game_player: 230, data: '8030ffff80fb00000c000010' },
      { type: 266, name: 'selected_entity_changed_very_close', game_player: 269, data: 'b7' },
      { type: 266, name: 'selected_entity_changed_very_close', game_player: 326, data: '87' },
    ],
  },
  {
    name: 's2c_build_terrain_two_records',
    description: 'S→C build_terrain with TWO 10-byte records separated by 01 01 00 b5 00 and ending 01 01 00, then a 266 (pkt 13, tick 24774869). Regression: only the C→S 00 00 00 b5 00 separator was known, so parsing stopped after one record and invented stop_walking/nothing actions.',
    hex: '2706e8d57a01d5087a0100000000085501b4605616d4087a0100000000b5e6942e00003d2700000008010100b5002c2f00003d2700000008010100ff0a010098',
    actions: [
      { type: 181, name: 'build_terrain', game_player: 230,
        data: '942e00003d2700000008010100b5002c2f00003d2700000008010100' },
      { type: 266, name: 'selected_entity_changed_very_close', game_player: 230, data: '98' },
    ],
  },
  {
    name: 's2c_remote_view_surface_two_echoes',
    description: 'S→C two RemoteViewSurface echoes (24B each) then 266 (pkt 13792, tick 24788457). Regression: table length 0 for C→S read the body as nothing/destroy phantoms and ended on Unknown(255) Player_43052.',
    hex: '27064d0b7b01e93d7a010000000008550161cbaa19e83d7a0100000000ff04010700001126ffffffa72f000000a01b8cf9a228044000000000ff04010000001126ffffffa72f000000a01b8cf9a228044000000000ff0a01dfb9',
    actions: [
      { type: 260, name: 'remote_view_surface', game_player: 7,
        data: '00001126ffffffa72f000000a01b8cf9a228044000000000' },
      { type: 260, name: 'remote_view_surface', game_player: 7,
        data: '00001126ffffffa72f000000a01b8cf9a228044000000000' },
      { type: 266, name: 'selected_entity_changed_very_close', game_player: 230, data: 'b9' },
    ],
  },
  {
    name: 's2c_open_logistics_gui_then_zoom',
    description: 'S→C OpenLogisticsGui (28B echo body) then zoom_around_point (pkt 14067, tick 24788696). Regression: the 28B body was read as Unknown(255) player 62 instead of the following zoom at player 230.',
    hex: '07063c0c7b01d83e7a0100000000065501cbabfab7d73e7a0100000000403fffffffffffffffffffffffff7fffffff7f000000000000000000000181a7000000000000f0bf00000000004050c00000000000c05fc0',
    actions: [
      { type: 64, name: 'open_logistics_gui', game_player: 63,
        data: 'ffffffffffffffffffffffff7fffffff7f0000000000000000000001' },
      { type: 129, name: 'zoom_around_point', game_player: 230,
        data: '000000000000f0bf00000000004050c00000000000c05fc0' },
    ],
  },
  {
    name: 's2c_copy_22b_then_266',
    description: 'S→C Copy (22B echo body) then 266 (pkt 8209, tick 24782992). Regression: table length 0 decoded the body as craft Player_472 and lost the 269 selection echo.',
    hex: '2706a3f57a0190287a01000000000655016a39e6598f287a010000000086ff0d0156cb0000b53400009fc8000075310000000001800000ff0a010043',
    actions: [
      { type: 134, name: 'copy', game_player: 269,
        data: '56cb0000b53400009fc8000075310000000001800000' },
      { type: 266, name: 'selected_entity_changed_very_close', game_player: 269, data: '43' },
    ],
  },
  {
    name: 's2c_cycle_clipboard_backwards_31',
    description: 'S→C Copy then CycleClipboardBackwards (wire 31) (pkt 8606, tick 24783389, factorio-current.log). Pins 2.1 wire 31 to cycle_clipboard_backwards (2.0 had it at 33). Regression: Unknown(31) Player_269.',
    hex: '070630f77a011d2a7a0100000000065501f6d80ccf1c2a7a0100000000863fa75d00004356ffff9f5b00002b58ffff0000018000001fce',
    actions: [
      { type: 134, name: 'copy', game_player: 63,
        data: 'a75d00004356ffff9f5b00002b58ffff000001800000' },
      { type: 31, name: 'cycle_clipboard_backwards', game_player: 269, data: '' },
    ],
  },
  {
    name: 's2c_send_stacks_to_trash_17b',
    description: 'S→C SendStacksToTrash (17B echo body) then 266 (pkt 30089, tick 24803956). Regression: table length 0 read the body as Unknown(250) Player_230.',
    hex: '0706d8477b01747a7a0100000000065501b89eff11737a7a010000000053e6fa000146622502000000000001c2020400ff0a01278c',
    actions: [
      { type: 83, name: 'send_stacks_to_trash', game_player: 230,
        data: 'fa000146622502000000000001c2020400' },
      { type: 266, name: 'selected_entity_changed_very_close', game_player: 269, data: '8c' },
    ],
  },
  {
    name: 's2c_deconstruct_23b_then_hovers',
    description: 'S→C Deconstruct (16B area + 7B echo tail) then 266/266/267 (pkt 28272, tick 24802238). Regression: taking only the 16B table length read the tail as stop_walking/nothing and shifted the three hovers to invalid Player_457.',
    hex: '270622417b01be737a01000000000a5501e56d2dfabd737a01000000008407e6e3050041c30000e6e3050041c3000000000180000001ff0a010088ff0a01388dff0b01ff07018882',
    actions: [
      { type: 132, name: 'deconstruct', game_player: 7,
        data: 'e6e3050041c30000e6e3050041c3000000000180000001' },
      { type: 266, name: 'selected_entity_changed_very_close', game_player: 7, data: '88' },
      { type: 266, name: 'selected_entity_changed_very_close', game_player: 63, data: '8d' },
      { type: 267, name: 'selected_entity_changed_very_close_precise', game_player: 326, data: '8882' },
    ],
  },
  {
    name: 's2c_unit_number_then_precise',
    description: 'S→C SelectedEntityChangedBasedOnUnitNumber (8B echo body) then 267 (pkt 33567, tick 24807275). Regression: the 8B body was read as change_active_item_group_for_crafting Player_452, losing the 326 precise echo.',
    hex: '0706cf547b016b877a01000000000655016845429c6a877a0100000000ff0d01ff0d016eb75e0200000000ff0b01397882',
    actions: [
      { type: 269, name: 'selected_entity_changed_based_on_unit_number', game_player: 269,
        data: '6eb75e0200000000' },
      { type: 267, name: 'selected_entity_changed_very_close_precise', game_player: 326, data: '7882' },
    ],
  },
  {
    name: 's2c_open_gui_no_body',
    description: 'S→C open_gui echo carries NO body (pkt 21540, tick 24747243): next action starts right after the delta. Regression: the old "14 bytes if enough remain" read stop_drag_build/zoom headers as entity/token metadata and produced Unknown(160) Player_378.',
    hex: '2706a3697a01eb9c7901000000000a5501bdeb1187ea9c790100000000093f05193100818e000000000000f0bf00000000000050c00000000000a062c0',
    actions: [
      { type: 9, name: 'selected_entity_cleared', game_player: 63, data: '' },
      { type: 5, name: 'open_gui', game_player: 88, data: '' },
      { type: 49, name: 'stop_drag_build', game_player: 88, data: '' },
      { type: 129, name: 'zoom_around_point', game_player: 230,
        data: '000000000000f0bf00000000000050c00000000000a062c0' },
    ],
  },
  {
    name: 's2c_player_join_game_16b',
    description: 'S→C PlayerJoinGame (16B echo: peer/mode/name block) then 266 (pkt 17772, tick 24743475). Regression: table length 0 left the name block to be read as Unknown(255) Player_230 instead of the following 269 hover.',
    hex: '2716eb5a7a01338e7901000000000655015fac448d328e7901000000009fe6ff0003e60001076e65756d6173740000ff0a01272f0204538e79010000000000030aff0003',
    actions: [
      { type: 159, name: 'player_join_game', game_player: 230,
        data: 'ff0003e60001076e65756d6173740000' },
      { type: 266, name: 'selected_entity_changed_very_close', game_player: 269, data: '2f' },
    ],
  },
  {
    name: 's2c_music_then_relative_zoom',
    description: 'S→C PlayerMusicChanged (1B) then SelectedEntityChangedRelative then ZoomAroundPoint (pkt 13977, tick 24739759). Regression: treating the music echo as 15B swallowed the relative/zoom headers and invented Player_446.',
    hex: '07060c4c7a01af7f790100000000085501e57b88f9ae7f790100000000ff5c013f00ff0c0106d5227ceb8113000000000000f0bf00000000000066c00000000000c05640',
    actions: [
      { type: 348, name: 'player_music_changed', game_player: 63, data: '00' },
      { type: 268, name: 'selected_entity_changed_relative', game_player: 69, data: 'd5227ceb' },
      { type: 129, name: 'zoom_around_point', game_player: 88,
        data: '000000000000f0bf00000000000066c00000000000c05640' },
    ],
  },
  {
    name: 's2c_set_logistic_filter_item_22b',
    description: 'S→C SetLogisticFilterItem (22B echo) then ZoomAroundPoint + 266 (pkt 37042, tick 24810583). Regression: the 22B body was read as build/nothing/Unknown(224).',
    hex: '0706bb617b0157947a01000000000855012225231b56947a010000000066a10000000001000000ffffffff000000000000010001008145000000000000f0bf0000000000e06c400000000000a067c0ff0a016078',
    actions: [
      { type: 102, name: 'set_logistic_filter_item', game_player: 161,
        data: '0000000001000000ffffffff00000000000001000100' },
      { type: 129, name: 'zoom_around_point', game_player: 230,
        data: '000000000000f0bf0000000000e06c400000000000a067c0' },
      { type: 266, name: 'selected_entity_changed_very_close', game_player: 326, data: '78' },
    ],
  },
  {
    name: 's2c_upgrade_23b',
    description: 'S→C Upgrade (23B echo) then 266 (pkt 16083, tick 24790483). Regression: the body was read as gui_confirmed Player_470 instead of the 269 hover.',
    hex: '070637137b01d3457a01000000000a55014b13c1acd2457a01000000000507310085ff06016ac900007f3900006ac900007f39000000000180000000ff0a010088',
    actions: [
      { type: 5, name: 'open_gui', game_player: 7, data: '' },
      { type: 49, name: 'stop_drag_build', game_player: 7, data: '' },
      { type: 133, name: 'upgrade', game_player: 269,
        data: '6ac900007f3900006ac900007f39000000000180000000' },
      { type: 266, name: 'selected_entity_changed_very_close', game_player: 269, data: '88' },
    ],
  },
  {
    name: 's2c_go_to_train_station_13b',
    description: 'S→C GoToTrainStation (13B echo) then StartWalking + precise 267 (pkt 58659, tick 24831720). Regression: table length 0 read the station body as nothing/Unknown(255) Player_160.',
    hex: '07064cb47b01e8e67a01000000000a5501b8951246e7e67a0100000000463f000000000000f03f0000000000000000c26200000000ffffffff0147000000466c0000000000000000000000000000f0bfff0b01398882',
    actions: [
      { type: 70, name: 'start_walking', game_player: 63,
        data: '000000000000f03f0000000000000000' },
      { type: 194, name: 'go_to_train_station', game_player: 161,
        data: '00000000ffffffff0147000000' },
      { type: 70, name: 'start_walking', game_player: 269,
        data: '0000000000000000000000000000f0bf' },
      { type: 267, name: 'selected_entity_changed_very_close_precise', game_player: 326,
        data: '8882' },
    ],
  },
  {
    name: 's2c_set_ghost_cursor_3b',
    description: 'S→C SetGhostCursor (3B echo) then CloseGui + 266 (pkt 3630, tick 24881281). Regression: table length 0 read the cursor body as copy_entity_settings/stop_walking and lost the CloseGui + 326 hover.',
    hex: '270637767c0181a87b0100000000085501f6615bd980a87b010000000096a10f00013d000000ff0a01a578',
    actions: [
      { type: 150, name: 'set_ghost_cursor', game_player: 161, data: '0f0001' },
      { type: 61, name: 'close_gui', game_player: 161, data: '0000' },
      { type: 266, name: 'selected_entity_changed_very_close', game_player: 326, data: '78' },
    ],
  },
].freeze
