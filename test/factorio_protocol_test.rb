#!/usr/bin/env ruby
# frozen_string_literal: true

# Tests for Factorio protocol parsing using known byte sequences.
# Run: ruby -Ilib test/factorio_protocol_test.rb

require 'minitest/autorun'
require 'mocha/minitest'
require 'factorio_protocol'
require 'factorio_protocol/actions/types'

class TestFactorioProtocol < Minitest::Test
  def setup
    @item_db = nil
    # Actions come from the fixed 2.1 table. No per-test version state.
  end


  # ── TilePos / TileRect ─────────────────────────────────────────

  def test_tile_pos_parses_8_bytes
    data = [0x9d, 0x9f, 0xfe, 0xff, 0x1c, 0xae, 0x01, 0x00].pack('C*')
    pos = FactorioProtocol::Actions::Types::TilePos.from_data(data)
    refute_nil pos
    assert_equal(-90211, pos.x)  # int32 LE
    assert_equal(110108, pos.y)
    tx, ty = pos.to_tiles
    assert_in_delta(-352.387, tx, 0.001)
    assert_in_delta(430.109, ty, 0.001)
  end

  def test_tile_rect_parses_16_bytes
    data = [0x9d, 0x9f, 0xfe, 0xff, 0x1c, 0xae, 0x01, 0x00,
            0xf5, 0xa2, 0xfe, 0xff, 0xcc, 0xcf, 0x01, 0x00].pack('C*')
    rect = FactorioProtocol::Actions::Types::TileRect.from_data(data)
    refute_nil rect
    assert_equal(-90211, rect.top_left.x)
    assert_equal(118732, rect.bottom_right.y)
  end

  # ── Deconstruct (type 132 on stable 2.1) ───────────────────────

  def test_deconstruct_data_length
    entry = FactorioProtocol::Actions::ACTIONS_21[132]
    refute_nil entry
    assert_equal :deconstruct, entry[0]
    assert_equal 23, entry[1], 'deconstruct C→S body is 23 bytes (16-byte area + echo metadata)'
  end

  def test_deconstruct_decodes_area
    # Simulate a server heartbeat action: count_flagged=0x04 (2 elems),
    # type=132 (deconstruct), delta=2, data=23 bytes
    pkt = build_server_tc_packet([
      { type: 132, delta: 2, data: [0x9d, 0x9f, 0xfe, 0xff, 0x1c, 0xae, 0x01, 0x00,
                                      0xf5, 0xa2, 0xfe, 0xff, 0xcc, 0xcf, 0x01, 0x00,
                                      0x00, 0x00, 0x01, 0x80, 0x00, 0x00, 0x01] }
    ])
    result = FactorioProtocol.parse_udp_payload(pkt)
    actions = extract_actions(result)
    assert_equal 1, actions.size, 'metadata after first action should be filtered'
    assert_equal :deconstruct, actions[0][:name]
    assert_equal 2, actions[0][:game_player]

    d = actions[0][:data]
    assert_equal 23, d.bytesize
    rect = FactorioProtocol::Actions::Types::TileRect.from_data(d)
    refute_nil rect
    tx1, ty1 = rect.top_left.to_tiles
    tx2, ty2 = rect.bottom_right.to_tiles
    assert_in_delta(-352.387, tx1, 0.001)
    assert_in_delta(-349.043, tx2, 0.001)
  end

  # ── Server metadata filtering ──────────────────────────────────

  def test_server_echo_only_first_action_kept
    # count_flagged=0x04 (2 elems), first is real action, second is metadata
    pkt = build_server_tc_packet([
      { type: 132, delta: 2, data: [0x9d, 0x9f, 0xfe, 0xff, 0x1c, 0xae, 0x01, 0x00,
                                      0xf5, 0xa2, 0xfe, 0xff, 0xcc, 0xcf, 0x01, 0x00,
                                      0x00, 0x00, 0x01, 0x80, 0x00, 0x00, 0x01] },
      { type: 245, delta: 162, data: [0xfe, 0xff] }
    ])
    result = FactorioProtocol.parse_udp_payload(pkt)
    actions = extract_actions(result)
    assert_equal 2, actions.size, 'both real actions kept (no wrapper to strip)'
    assert_equal :deconstruct, actions[0][:name]
    assert_equal 2, actions[0][:game_player]
  end

  def test_server_echo_strips_wrapper
    pkt = build_server_tc_packet([
      { type: 85, delta: 1, data: Array.new(12, 0) },
      { type: 132, delta: 2, data: [0x9d, 0x9f, 0xfe, 0xff, 0x1c, 0xae, 0x01, 0x00,
                                      0xf5, 0xa2, 0xfe, 0xff, 0xcc, 0xcf, 0x01, 0x00,
                                      0x00, 0x00, 0x01, 0x80, 0x00, 0x00, 0x01] }
    ])
    result = FactorioProtocol.parse_udp_payload(pkt)
    actions = extract_actions(result)
    assert_equal 1, actions.size, 'server_tick_info wrapper should be stripped'
    assert_equal :deconstruct, actions[0][:name]
    # wire 0-indexed; decoded game_player is the user-facing 1-indexed Lua id
    assert_equal 3, actions[0][:game_player]
  end

  def test_client_heartbeat_keeps_all_actions
    # Client heartbeat should NOT filter metadata (is_server=false)
    pkt = build_client_tc_packet([
      { type: 132, delta: 2, data: [0x9d, 0x9f, 0xfe, 0xff, 0x1c, 0xae, 0x01, 0x00,
                                      0xf5, 0xa2, 0xfe, 0xff, 0xcc, 0xcf, 0x01, 0x00] },
      { type: 245, delta: 162, data: [0xfe, 0xff] }
    ])
    result = FactorioProtocol.parse_udp_payload(pkt)
    actions = extract_actions(result)
    assert_equal 2, actions.size, 'client heartbeat should keep all actions'
  end

  # ── C→S closure [tick][pad] trailer (phantom-player regressions) ──
  #
  # Client tick closures carry ONE 8-byte [tick(4)][pad(4)] trailer after the
  # LAST action. Previously the parser added +8 to EVERY hover/zoom/pan action
  # (60/128/129/262/265-268/310) and treated selected_entity_cleared (9) as
  # 8 bytes of data, so with 2+ actions it swallowed the next action's header
  # and re-parsed leftover payload bytes as phantom actions with bogus player
  # deltas (live captures: Player_192 swap_tile_slots, Player_64
  # drag_train_wait_condition). Only the last action may consume the trailer.

  def test_client_zoom_x2_no_phantom
    # Two zoom_around_point actions in one C→S closure. The first (intermediate)
    # action must NOT get the +8 trailer, or it eats the second zoom's header
    # (80 00) and the tail of its payload (f0 bf) becomes swap_tile_slots with a
    # bogus delta.
    data24 = [0] * 24
    pkt = build_client_tc_packet([
      { type: 129, delta: 1, data: data24 },
      { type: 129, delta: 0, data: data24 },
    ])
    result = FactorioProtocol.parse_udp_payload(pkt)
    actions = extract_actions(result)
    assert_equal 2, actions.size
    actions.each_with_index do |a, i|
      assert_equal 129, a[:type], "action #{i} type"
      assert_equal 1, a[:game_player], "action #{i} must stay on game player 1 (no phantom delta)"
      refute a.key?(:player), "action #{i} must not expose raw 0-indexed player"
    end
    assert_equal 24, actions[0][:data].bytesize, 'intermediate zoom: payload only, no +8'
  end

  def test_client_selected_entity_cleared_intermediate_has_no_data
    # selected_entity_cleared (9) has no data of its own in C→S — the 8 bytes
    # ACTIONS lists are the closure [tick][pad] trailer, which only belongs to
    # the last action. As an intermediate action it must consume 0 bytes or it
    # swallows the following action's header.
    pkt = build_client_tc_packet([
      { type: 9, delta: 1, data: [] },
      { type: 69, delta: 0, data: [0] * 16 },  # start_walking
    ])
    result = FactorioProtocol.parse_udp_payload(pkt)
    actions = extract_actions(result)
    assert_equal [9, 69], actions.map { |a| a[:type] }
    assert_equal '', actions[0][:data].unpack1('H*'), 'intermediate cleared has no data'
    assert actions.all? { |a| a[:game_player] == 1 }
    assert actions.all? { |a| !a.key?(:player) }
  end

  def test_client_266_followed_by_start_walking
    # selected_entity_changed_very_close (1B payload) + start_walking in one
    # closure. The 266 must not consume +8 or it eats start_walking's header.
    pkt = build_client_tc_packet([
      { type: 266, delta: 1, data: [0x84] },
      { type: 70, delta: 0, data: [0] * 16 },
    ])
    result = FactorioProtocol.parse_udp_payload(pkt)
    actions = extract_actions(result)
    assert_equal [266, 70], actions.map { |a| a[:type] }
    assert_equal '84', actions[0][:data].unpack1('H*')
    assert_equal 16, actions[1][:data].bytesize
    assert actions.all? { |a| a[:game_player] == 1 }
    assert actions.all? { |a| !a.key?(:player) }
  end

  def test_client_drag_build_carries_position
    # C→S drag build: 21-byte data = 9B pos + 01 01 marker + 10B headerless
    # drag position. Reading only 11B left the position to be re-parsed as a
    # phantom action (zoom Player_252 from the position's x-byte 0x80).
    pkt = build_client_tc_packet([
      { type: 69, delta: 2, data: [0x80, 0xfb, 0xff, 0xff, 0x80, 0x02, 0x00, 0x00, 0x00, 0x01, 0x01,
                                    0x80, 0xfb, 0xff, 0xff, 0x80, 0x04, 0x00, 0x00, 0x00, 0x10] },
      { type: 9, delta: 0, data: [] },
    ])
    result = FactorioProtocol.parse_udp_payload(pkt)
    actions = extract_actions(result)
    assert_equal [69, 9], actions.map { |a| a[:type] }
    assert_equal 21, actions[0][:data].bytesize, 'drag build carries both positions'
    assert actions.all? { |a| a[:game_player] == 2 }
    assert actions.all? { |a| !a.key?(:player) }
  end

  # ── Build action (type 68) ─────────────────────────────────────

  def test_build_data_length
    entry = FactorioProtocol::Actions::ACTIONS_21[69]
    assert_equal [:build, 16], entry
  end

  def test_build_decodes_position_and_dir
    # build data: x= -656.5 * 256 = -168064, y= -99.5 * 256 = -25472, dir=0 (north)
    x = (-656.5 * 256).to_i
    y = (-99.5 * 256).to_i
    data = [x].pack('i') + [y].pack('i') + [0].pack('C')
    assert_equal 9, data.bytesize

    pkt = build_client_tc_packet([
      { type: 69, delta: 2, data: data.bytes }
    ])
    result = FactorioProtocol.parse_udp_payload(pkt)
    actions = extract_actions(result)
    assert_equal 1, actions.size
    assert_equal :build, actions[0][:name]

    d = actions[0][:data]
    bx = d.unpack1('i', offset: 0)
    by = d.unpack1('i', offset: 4)
    dir = d.getbyte(8)
    assert_in_delta(-656.5, bx / 256.0, 0.01)
    assert_in_delta(-99.5, by / 256.0, 0.01)
    assert_equal 0, dir
  end

  # ── Chat message decoding (write_to_console) ──────────────────
  # These test the REAL implementation (FactorioProtocol.decode_chat),
  # not a private copy — regression guards against truncation bugs.

  def test_chat_segment_format
    # [0x05][meta][text...]
    data = [0x05, 0x2b] + 'missing some turret coverage in the middle?'.bytes
    msg = FactorioProtocol.decode_chat(data.pack('C*'))
    assert_equal 'missing some turret coverage in the middle?', msg
  end

  def test_chat_long_message_split
    # A split message: segment 0 carries [player][total_len][text...],
    # continuation segments raw text. The sniffer merges them before
    # decoding (chat_action_data), so decode_chat sees the MERGED payload —
    # the declared total_len then equals the remaining bytes exactly.
    first = 'I was also thinking of mod to unlock all qualities from start so there is more focus on quality. an'
    second = "d there's mods that add additional quality tiers after legendary."
    total_len = first.bytesize + second.bytesize
    assert_equal 164, total_len

    merged = ([5, total_len] + first.bytes.to_a + second.bytes.to_a).pack('C*')
    msg = FactorioProtocol.decode_chat(merged)
    assert_equal first + second, msg

    # A lone continuation segment, decoded standalone, is raw text (no prefix).
    msg2 = FactorioProtocol.decode_chat(second.bytes.to_a.pack('C*'))
    assert_equal second, msg2
  end

  def test_chat_0x0b_format
    # [0x0b][meta][text...] — observed live on 2026-08-11.
    # Truncation bug: 0x0b was unhandled, fell through to uint32v which
    # read 0x0b=11 as text length → ",that nuke " instead of full message.
    text = 'that nuke is not gonna be finished this hour'
    data = [0x0b, text.bytesize] + text.bytes
    msg = FactorioProtocol.decode_chat(data.pack('C*'))
    assert_equal text, msg
  end

  def test_chat_0x15_and_0x2d_prefixes
    # Live-observed chat tones: [0x15]/[0x2d][meta][text...] — previously
    # unhandled (returned raw bytes incl. the prefix).
    assert_equal 'i get the reference',
                 FactorioProtocol.decode_chat(([0x15, 19] + 'i get the reference'.bytes).pack('C*'))
    assert_equal 'good', FactorioProtocol.decode_chat(([0x2d, 4] + 'good'.bytes).pack('C*'))
  end

  def test_chat_0x1f_and_0x30_prefixes
    # More live-observed tones: GPS pings use 0x1f; 0x30 is '0'.
    assert_equal '[gps=-64.6,93.2]',
                 FactorioProtocol.decode_chat(([0x1f, 16] + '[gps=-64.6,93.2]'.bytes).pack('C*'))
    assert_equal 'hey', FactorioProtocol.decode_chat(([0x30, 3] + 'hey'.bytes).pack('C*'))
    # 0x30 is '0' — a raw message starting with '0' must NOT be stripped
    # unless byte1 is a plausible length.
    assert_equal "0\x00raw", FactorioProtocol.decode_chat("0\x00raw".b)
  end

  def test_chat_0x30_empty_message
    assert_nil FactorioProtocol.decode_chat("0\x00".b)
  end

  def test_chat_server_echo_3d_format
    # [0x3d][meta][text...]
    text = 'Do we need the legendary insect eggs?'
    data = [0x3d, text.bytesize] + text.bytes
    msg = FactorioProtocol.decode_chat(data.pack('C*'))
    assert_equal text, msg
  end

  def test_chat_server_echo_01_format
    # [0x01][meta][text...]
    text = 'spoilage may break the system'
    data = [0x01, text.bytesize] + text.bytes
    msg = FactorioProtocol.decode_chat(data.pack('C*'))
    assert_equal text, msg
  end

  def test_chat_uint32v_prefixed
    # Main action list format (not from segments): uint32v length + text
    text = 'short message'
    len = text.bytesize
    data = [len] + text.bytes
    msg = FactorioProtocol.decode_chat(data.pack('C*'))
    assert_equal text, msg
  end

  def test_chat_player_index_prefixed_no_truncation
    # The first byte of a C→S write_to_console payload is the SENDER'S
    # player index and the second byte is the total message length — NOT a
    # length prefix. Players >= 64 (0x40/0x42/0x41/…) fell through to the
    # uint32v-length branch, which read the player byte as a length and
    # TRUNCATED long messages (0x42=66 → returned only 66 bytes, cutting
    # "...feelings toward" off mid-word). Regression: the 2-byte header is
    # stripped and ALL text is returned.
    text = 'what version of leg is this?'
    msg = FactorioProtocol.decode_chat(([0x40, text.bytesize] + text.bytes).pack('C*'))
    assert_equal text, msg

    # Player 66 sending a 66-char message: must return all 66 chars, not 66B-of-{player,len+...}.
    text2 = 'personal, deep, and hidden feelings toward the player morganc'
    assert_equal text2.bytesize, text2.bytesize
    msg2 = FactorioProtocol.decode_chat(([0x42, text2.bytesize] + text2.bytes).pack('C*'))
    assert_equal text2, msg2
  end

  def test_chat_reassembled_split_message_full_text
    # Live capture (2.0), the exact message the sniffer wrongly printed as
    # "...feelings toward". seg0 = [0x42(player66)][total_len] + first 98B,
    # seg1 = raw continuation. After the sniffer merges the two segments
    # (chat_action_data), decode_chat must return the FULL text.
    seg0 = ([0x42] + [0x77] + 'hivemind what are your personal, deep, and hidden feelings towards the player morganc, the kind yo'.bytes).pack('C*')
    seg1 = 'u would never tell...'.b
    msg = FactorioProtocol.decode_chat(seg0 + seg1)
    assert_equal 'hivemind what are your personal, deep, and hidden feelings towards the player morganc, the kind you would never tell...', msg
    assert_equal 98, 'hivemind what are your personal, deep, and hidden feelings towards the player morganc, the kind yo'.bytesize, 'seg0 text must be 98B'
    assert_equal 119, msg.bytesize
  end

  def test_chat_raw_text
    # No prefix at all
    text = 'raw text here'
    msg = FactorioProtocol.decode_chat(text.bytes.to_a.pack('C*'))
    assert_equal text, msg
  end

  def test_chat_nil_on_empty
    assert_nil FactorioProtocol.decode_chat(''.b)
    assert_nil FactorioProtocol.decode_chat(nil)
  end

  # ── write_to_console on 2.1.23 stable (type 107, not 106) ──────

  def test_stable_wtc_type_107_not_market_offer
    # On 2.1.23 stable, write_to_console is type 107 (not 106, which is
    # market_offer). The experimental ACTIONS table numbers it 106; ACTIONS_21
    # corrects this via merge. Without the correction, the parser would name
    # type 107 "change_active_item_group_for_crafting" and never hit the
    # write_to_console name-based hack.
    assert_equal :write_to_console, FactorioProtocol.action_name(107)
    assert_equal :gui_confirmed, FactorioProtocol.action_name(106)
    assert_equal :market_offer, FactorioProtocol.action_name(108)
    assert_nil FactorioProtocol.action_len(107)
  end

  def test_stable_chat_reset_command
    # Real C→S packet from captures/server-34197-20261025-084429.pcap.gz
    # (2.1.23 stable, build 87750). Player 24 sends a /reset command chat.
    # Segment type 107 → write_to_console, with the name-based hack reading
    # the uint32v length-prefixed string payload.
    hex = '060638795b2b71ae40000000000001016b010000001701000817062f72657365746aae400000000000'
    result = FactorioProtocol.parse_udp_payload([hex].pack('H*'))
    refute_nil result
    hb = result[:heartbeat]
    refute hb[:hit_unknown], 'no desync on a clean chat packet'
    actions = extract_actions(result)
    assert_equal 1, actions.size
    assert_equal 107, actions[0][:type]
    assert_equal :write_to_console, actions[0][:name]
    assert_equal '/reset', FactorioProtocol.decode_chat(actions[0][:data])
  end

  def test_stable_chat_evolution_command
    # Real C→S packet from captures/server-34197-20261025-084429.pcap.gz
    # (2.1.23 stable). Player 24 sends a /evolution command. This packet
    # has the has_random flag (0x26 header) — verifies the random flag does
    # not interfere with segment parsing.
    hex = '260635245c2b845341000000000001016b060000001701000c170a2f65766f6c7574696f6e7f53410000000000'
    result = FactorioProtocol.parse_udp_payload([hex].pack('H*'))
    refute_nil result
    hb = result[:heartbeat]
    refute hb[:hit_unknown], 'no desync on a clean chat packet with random flag'
    actions = extract_actions(result)
    assert_equal 1, actions.size
    assert_equal 107, actions[0][:type]
    assert_equal :write_to_console, actions[0][:name]
    assert_equal '/evolution', FactorioProtocol.decode_chat(actions[0][:data])
  end

  # ── Player delta calculation ───────────────────────────────────

  def test_player_delta_calculation
    # last_index starts at 0xFFFF, delta=2 → raw=1, game=2
    pkt = build_client_tc_packet([
      { type: 131, delta: 2, data: [0] * 16 }
    ])
    result = FactorioProtocol.parse_udp_payload(pkt)
    actions = extract_actions(result)
    assert_equal 1, actions.size
    assert_equal 2, actions[0][:game_player]  # Lua-style 1-indexed
    refute actions[0].key?(:player), 'raw 0-indexed player field is not public'

    # Second action with delta=11: raw = 1+11 = 12, game = 13
    pkt2 = build_client_tc_packet([
      { type: 132, delta: 2, data: [0] * 23 },
      { type: 83, delta: 11, data: [0] * 5 }
    ])
    result2 = FactorioProtocol.parse_udp_payload(pkt2)
    actions2 = extract_actions(result2)
    assert_equal 2, actions2.size
    assert_equal 13, actions2[1][:game_player]  # Lua-style 1-indexed
    refute actions2[1].key?(:player), 'raw 0-indexed player field is not public'
  end

  # ── Network header parsing ─────────────────────────────────────

  def test_network_header_parsing
    # 0x07 = msg_type 7 (ServerToClientHeartbeat), no flags
    data = [0x07].pack('C')
    hdr = FactorioProtocol.parse_network_header(data)
    refute_nil hdr
    assert_equal 7, hdr[:msg_type]
    assert_equal 'ServerToClientHeartbeat', hdr[:msg_name]
    refute hdr[:has_random]
    refute hdr[:fragmented]
  end

  def test_network_header_with_random
    # 0x27 = msg_type 7 (ServerToClientHeartbeat), has_random=true
    data = [0x27].pack('C')
    hdr = FactorioProtocol.parse_network_header(data)
    refute_nil hdr
    assert_equal 7, hdr[:msg_type]
    assert hdr[:has_random]
  end

  def test_heartbeat_payload_detects_both_directions
    assert FactorioProtocol.heartbeat_payload?([0x06].pack('C')), 'bare C→S heartbeat'
    assert FactorioProtocol.heartbeat_payload?([0x26].pack('C')), 'C→S with has_random — type still 6'
    assert FactorioProtocol.heartbeat_payload?([0x07].pack('C')), 'S→C heartbeat'
    assert FactorioProtocol.heartbeat_payload?([0x27].pack('C')), 'S→C has_random'
    refute FactorioProtocol.heartbeat_payload?([0x05].pack('C')), 'map progress is not a heartbeat'
    refute FactorioProtocol.heartbeat_payload?(nil)
    refute FactorioProtocol.heartbeat_payload?(''.b)
  end

  # ── Action name / len lookup ───────────────────────────────────

  def test_action_name_known
    assert_equal :deconstruct, FactorioProtocol.action_name(132)
    assert_equal :build, FactorioProtocol.action_name(69)
    assert_equal :write_to_console, FactorioProtocol.action_name(107)
  end

  def test_action_name_unknown
    assert_equal 'Unknown(999)', FactorioProtocol.action_name(999)
  end

  def test_action_len_known
    assert_equal 23, FactorioProtocol.action_len(132)   # deconstruct
    assert_equal 16, FactorioProtocol.action_len(69)    # build (table value; hack adjusts to 9/10/11/21 by variant)
    assert_nil FactorioProtocol.action_len(107)         # write_to_console (variable, no table length)
  end

  # ── uint16v / uint32v decoding ────────────────────────────────

  def test_decode_uint16v_single_byte
    data = [0x2a].pack('C')
    off, val = FactorioProtocol.decode_uint16v(data, 0)
    assert_equal 1, off
    assert_equal 0x2a, val
  end

  def test_decode_uint16v_escape
    data = [0xff, 0x34, 0x12].pack('C*')
    off, val = FactorioProtocol.decode_uint16v(data, 0)
    assert_equal 3, off
    assert_equal 0x1234, val
  end

  def test_decode_uint32v_single_byte
    data = [0x7f].pack('C')
    off, val = FactorioProtocol.decode_uint32v(data, 0)
    assert_equal 1, off
    assert_equal 0x7f, val
  end

  def test_decode_uint32v_escape
    data = [0xff, 0x78, 0x56, 0x34, 0x12].pack('C*')
    off, val = FactorioProtocol.decode_uint32v(data, 0)
    assert_equal 5, off
    assert_equal 0x12345678, val
  end

  # ── String encoding (Unicode names must not stay binary-flagged) ──

  def test_decode_string_returns_utf8
    name = "héllo"
    data = [name.bytesize].pack('C') + name.b
    off, str = FactorioProtocol.decode_string(data, 0)
    assert_equal name, str
    assert_equal Encoding::UTF_8, str.encoding
    assert str.valid_encoding?
  end

  def test_new_peer_info_username_is_utf8
    # C2S heartbeat with one synchronizer action: NewPeerInfo (0x02)
    # carrying a Unicode name — must decode as clean UTF-8, not binary.
    name = "sévérin"
    raw = [0x06].pack('C') +            # msg_type 6 (C2S)
          [0x10].pack('C') +            # flags: has_synchronizer_action
          [1, 0, 0, 0].pack('V') +      # seq
          [0, 0, 0, 0, 0, 0, 0, 0].pack('Q<') +  # next_receive (client-only)
          [1].pack('C') +               # sync count (uint32v)
          [0x02].pack('C') +            # NewPeerInfo
          [name.bytesize].pack('C') + name.b

    result = FactorioProtocol::HeartbeatPacket.parse(raw)
    sa = result.heartbeat[:sync_actions].first
    refute_nil sa, 'NewPeerInfo sync action should parse'
    assert_equal name, sa[:username]
    assert_equal Encoding::UTF_8, sa[:username].encoding
    assert sa[:username].valid_encoding?
  end

  def test_new_peer_info_invalid_utf8_is_a_misdecode
    name = "bad\xFFname".b
    raw = [0x06].pack('C') +            # msg_type 6 (C2S)
          [0x10].pack('C') +            # flags: has_synchronizer_action
          [1, 0, 0, 0].pack('V') +      # seq
          [0, 0, 0, 0, 0, 0, 0, 0].pack('Q<') +
          [1].pack('C') +
          [0x02].pack('C') +            # NewPeerInfo
          [name.bytesize].pack('C') + name

    hb = FactorioProtocol::HeartbeatPacket.parse(raw).heartbeat
    sa = hb[:sync_actions].first
    assert sa[:hit_unknown], 'invalid UTF-8 must keep the frame'
    assert_nil sa[:username], 'no scrubbed name may become a player'
    assert hb[:hit_unknown]
  end

  # ── Synchronizer tick-confirm sizes (server-34197.pcap pkt 1311) ──
  # 0x0f/0x10 carry an 8-byte tick and 0x12 carries tick(8)+latency(1) —
  # the old 4-byte/5-byte sizes desynced the stream and fabricated a
  # NewPeerInfo "join" out of tick bytes (garbage "joined the game" line).

  # Build a C→S heartbeat carrying a single empty tick closure plus raw
  # sync-action bytes (mirrors pkt 1311's layout).
  def build_c2s_sync_packet(sync_bytes, tick: 50_026_211, next_receive: 50_026_259)
    [0x06].pack('C') +                 # msg_type 6 (C2S)
      [0x1e].pack('C') +               # tc + single + all-empty + sync
      [1, 0, 0, 0].pack('V') +         # seq
      [tick].pack('Q<') +              # empty tick closure's tick
      [next_receive].pack('Q<') +      # nextToReceiveServerTickClosure
      sync_bytes.b
  end

  def test_skipped_tick_closure_confirm_is_8_byte_tick
    sync = [2].pack('C') +             # sync count
      [0x10].pack('C') + [50_026_221].pack('Q<') +
      [0x10].pack('C') + [50_026_222].pack('Q<')
    result = FactorioProtocol::HeartbeatPacket.parse(build_c2s_sync_packet(sync))
    sas = result.heartbeat[:sync_actions]
    assert_equal 2, sas.size
    assert_equal 'SkippedTickClosureConfirm', sas[0][:name]
    assert_equal 50_026_221, sas[0][:tick]
    assert_equal 50_026_222, sas[1][:tick]
    assert sas.none? { |sa| sa[:hit_unknown] }, '8-byte ticks must parse cleanly'
    assert sas.none? { |sa| sa[:username] }, 'no phantom join may be decoded'
  end

  def test_skipped_tick_closure_is_8_byte_tick
    sync = [1].pack('C') +
      [0x0f].pack('C') + [50_026_221].pack('Q<')
    result = FactorioProtocol::HeartbeatPacket.parse(build_c2s_sync_packet(sync))
    sas = result.heartbeat[:sync_actions]
    assert_equal 1, sas.size
    assert_equal 'SkippedTickClosure', sas[0][:name]
    assert_equal 50_026_221, sas[0][:tick]
    refute sas[0][:hit_unknown]
  end

  def test_increased_latency_confirm_is_tick_plus_latency
    sync = [1].pack('C') +
      [0x12].pack('C') + [50_026_209].pack('Q<') + [0x02].pack('C')
    result = FactorioProtocol::HeartbeatPacket.parse(build_c2s_sync_packet(sync))
    sas = result.heartbeat[:sync_actions]
    assert_equal 1, sas.size
    assert_equal 'IncreasedLatencyConfirm', sas[0][:name]
    assert_equal 50_026_209, sas[0][:tick]
    assert_equal 2, sas[0][:latency]
    refute sas[0][:hit_unknown]
  end

  def test_mixed_latency_and_skip_confirms_no_phantom_join
    # Replica of server-34197.pcap pkt 1311's sync region: one
    # IncreasedLatencyConfirm followed by sequential SkippedTickClosureConfirms.
    # With the old sizes this desynced into GameEnds + a NewPeerInfo whose
    # "username" was binary tick data (the garbage join line).
    sync = [3].pack('C') +
      [0x12].pack('C') + [50_026_209].pack('Q<') + [0x02].pack('C') +
      [0x10].pack('C') + [50_026_221].pack('Q<') +
      [0x10].pack('C') + [50_026_222].pack('Q<')
    result = FactorioProtocol::HeartbeatPacket.parse(build_c2s_sync_packet(sync))
    sas = result.heartbeat[:sync_actions]
    assert_equal 3, sas.size
    assert_equal %w[IncreasedLatencyConfirm SkippedTickClosureConfirm SkippedTickClosureConfirm],
                   sas.map { |sa| sa[:name] }
    assert sas.none? { |sa| sa[:hit_unknown] }
    assert sas.none? { |sa| sa[:username] }, 'tick bytes must never decode as a join'
  end

  def test_new_peer_info_rejects_binary_garbage
    # A NewPeerInfo length pointing at binary (tick-like) bytes — as produced
    # by a desynced stream — must not yield a username (no phantom join).
    garbage = [0xed, 0x56, 0xfb, 0x02, 0x00, 0x00, 0x00, 0x00,
               0x10, 0xee, 0x56, 0xfb, 0x02, 0x00, 0x00, 0x00].pack('C*')
    raw = [0x06].pack('C') +
      [0x10].pack('C') +
      [1, 0, 0, 0].pack('V') +
      [0, 0, 0, 0, 0, 0, 0, 0].pack('Q<') +
      [1].pack('C') +
      [0x02].pack('C') +
      [garbage.bytesize].pack('C') + garbage
    result = FactorioProtocol::HeartbeatPacket.parse(raw)
    sa = result.heartbeat[:sync_actions].first
    refute_nil sa
    assert_nil sa[:username], 'binary garbage must not decode as a username'
    assert sa[:hit_unknown], 'desync must stop further sync parsing'
  end

  # ── 0xFF: escape marker AND the literal value 255 ──────────────────
  #
  # The wire writes uint16 values 0..255 in a SINGLE byte, so 255 is written
  # 0xFF and only 256+ pays the 3-byte escape. factorio_dissector's
  # decode_uint16v (and this parser, originally) treat 0xFF as an escape
  # unconditionally, so a closure ending in the two bytes FF FF decoded as a
  # bogus type and the rest of the closure was garbage — 118 flagged packets
  # before the fix. The real packet is 2.0's close_remote_view shape: the
  # 0xFF action (type 255 = set_combinator_description, no payload) is the last
  # one, followed by the closure's [tick][pad] trailer.
  #
  # Only the TYPE is disambiguated (by magnitude: no real input action exceeds
  # 355 in either version's defines dump). The DELTA of that trailing action
  # still decodes with its 3-byte escape form, so its player index is wrong —
  # documented, not silently fixed, because "the escape would read past the
  # closure" is no proof: open_gui legitimately swallows the trailer.
  # NOTE: the 2.0 real-packet pin for the FF-as-literal-type-255 case
  # (unknown.packets-20260925-193306) died with the 2.0 lens — its decode
  # desyncs under the lens-less 2.0 tables. The property itself is covered by
  # test_ff_byte_still_escapes_for_real_action_ids below (synthetic).
  def test_ff_byte_still_escapes_for_real_action_ids
    # 300 > 255 is a real action ID and MUST keep its 3-byte escape form
    data = [0x26, 0x06, 0, 0, 0, 0].pack('C*') +
           [0].pack('Q<') + [0x02].pack('C') + [0xFF, 0x2C, 0x01, 0x00].pack('C*') +
           [0, 0, 0, 0, 0, 0, 0, 0].pack('C*')
    acts = extract_actions(FactorioProtocol.parse_udp_payload(data))
    assert_equal 1, acts.size
    assert_equal 300, acts[0][:type]
    refute acts[0][:hit_unknown]
  end

  # S→C player_leave_game metadata, pinned from server-34197-20261103-232119:
  # the server follows the 0-byte leave action with a counted
  # `[reason u8][55 ff][(-index) u8][ff][ref u32]` block. MrHanniZap was
  # dropped (reason 1); Mista64/BasedDept left cleanly (reason 0).
  def test_player_leave_metadata_distinguishes_drop_from_clean_leave
    dropped = extract_actions(FactorioProtocol.parse_udp_payload(
      ['0706e2eefd00fddc6c010000000004f85e0155ffa2ff8a769975fcdc6c0100000000'].pack('H*')
    ))
    assert_equal 1, dropped.size, 'the metadata slot is consumed, not a phantom action'
    assert_equal [248, 94], [dropped[0][:type], dropped[0][:game_player]]
    assert_equal 1, dropped[0][:leave_reason]
    assert_equal :dropped, dropped[0][:leave_reason_name]
    assert dropped[0][:leave_dropped]
    assert_equal 0x7599768a, dropped[0][:leave_ref]

    clean = extract_actions(FactorioProtocol.parse_udp_payload(
      ['2716728cfe006a7a6d010000000004f8800055ff80fffb179fb2697a6d01000000000101000401'].pack('H*')
    ))
    assert_equal 1, clean.size, 'no phantom nothing/Unknown(255) from the metadata bytes'
    assert_equal [248, 128], [clean[0][:type], clean[0][:game_player]]
    assert_equal 0, clean[0][:leave_reason]
    assert_equal :quit, clean[0][:leave_reason_name]
    refute clean[0][:leave_dropped]
    assert_equal 0xb29f17fb, clean[0][:leave_ref]
  end

  # A kick carries reason 7 (defines.disconnect_reason.kicked), NOT a 0/1
  # dropped flag. Pinned from server-34197-20261105-102037 pkt 623659
  # (10:16:45.512924 UTC): Petricko93 /kick's BURMALDAMELLSTROY, and the
  # server broadcasts the leave in the next tick. Before the fix the block
  # `07 55 ff 62 ff 76 ad 5c 3e` was refused (flag != 0/1), left unconsumed,
  # and the closure decoded a phantom close_gui from it — so the kick had no
  # leave event at all. Asserting the slot count (3 = cleared + leave +
  # metadata) is what pins the block being consumed.
  def test_player_leave_metadata_reason_kicked_is_consumed
    res = FactorioProtocol.parse_udp_payload(
      ['070606ea7301afc5e2010000000006092cf8720755ff62ff76ad5c3eaec5e20100000000'].pack('H*')
    )
    tc = res[:heartbeat][:tick_closures].first
    assert_equal 31_638_959, tc[:tick]
    assert_equal 3, tc[:action_count]
    refute tc[:hit_unknown]
    assert_equal %i[selected_entity_cleared player_leave_game], tc[:actions].map { |a| a[:name] }

    leave = tc[:actions].last
    assert_equal 248, leave[:type]
    assert_equal 158, leave[:game_player]
    assert_equal 7, leave[:leave_reason]
    assert_equal :kicked, leave[:leave_reason_name]
    refute leave[:leave_dropped], 'reason 7 is a kick, not a drop'
    assert_equal 0x3e5cad76, leave[:leave_ref]
  end

  # The peer-disconnect synchronizer action carries the SAME enum; expose it
  # under the same name so a kick reads as :kicked on both wires.
  def test_peer_disconnect_reason_uses_disconnect_reason_names
    assert_equal :kicked, FactorioProtocol::DisconnectReason.name(7)
    assert_equal :banned, FactorioProtocol::DisconnectReason.name(9)
    assert_equal :quit, FactorioProtocol::DisconnectReason.name(0)
    assert_equal :reason_42, FactorioProtocol::DisconnectReason.name(42)
    assert_nil FactorioProtocol::DisconnectReason.name(nil)

    # Every entry in 2.1.24's defines.disconnect_reason (live RCON dump):
    # 10 is absent there, and switching_servers is 11, not 10.
    assert_equal({
                   0 => :quit, 1 => :dropped, 2 => :reconnect,
                   3 => :wrong_input, 4 => :desync_limit_reached,
                   5 => :cannot_keep_up, 6 => :afk, 7 => :kicked,
                   8 => :kicked_and_deleted, 9 => :banned,
                   11 => :switching_servers
                 }, FactorioProtocol::DisconnectReason::NAMES)
    assert_equal :reason_10, FactorioProtocol::DisconnectReason.name(10)

    assert_equal 'was kicked from the game', FactorioProtocol::DisconnectReason.text(:kicked)
    assert_equal 'was kicked from the game', FactorioProtocol::DisconnectReason.text(:kicked_and_deleted)
    assert_equal 'was banned from the game', FactorioProtocol::DisconnectReason.text(:banned)
    assert_equal 'was dropped from the game', FactorioProtocol::DisconnectReason.text(:dropped)
    assert_equal 'left the game', FactorioProtocol::DisconnectReason.text(:quit)
  end

  # Quickbar payloads, pinned from the real captures in captures/. The
  # lengths matter as much as the layout: a wrong quick_bar length desyncs
  # every action after it (the table's pick_slot 0 did exactly that).
  def test_quickbar_layouts
    qb = FactorioProtocol::Actions::QuickBar

    # set_slot: stable 2.1 is 5 bytes [item][slot][op][src u16] — item 1
    # (wooden-chest) into slot 8, no source (wire sample 2026-11-03).
    set = qb.decode(name: :quick_bar_set_slot, data: ['010800ffff'].pack('H*'))
    assert_equal({item: 1, slot: 8, op: 0, src: nil}, set)

    # op 1 = clear, src 0xFFFF = no source
    clear = qb.decode(name: :quick_bar_set_slot, data: ['200001ffff'].pack('H*'))
    assert_equal 1, clear[:op], 'op 1 clears the slot'
    assert_nil clear[:src], '0xFFFF means "no source"'
    assert_equal :undecodable,
                 qb.decode(name: :quick_bar_set_slot, data: ['1e00002000e23f6106'].pack('H*')),
                 'the 9-byte 2.0 form is not the stable 2.1 payload'

    # pick_slot is 4 bytes (was decoded as 0, which ate the next action)
    pick = qb.decode(name: :quick_bar_pick_slot, data: ['1e000100'].pack('H*'))
    assert_equal({item: 30, slot: 0, op: 1}, pick)
    assert_equal :undecodable, qb.decode(name: :quick_bar_pick_slot, data: ['1e0001'].pack('H*')),
                 'a payload of the wrong size is :undecodable, not a guess'
    assert_nil qb.decode(name: :use_item, data: ['1e0001'].pack('H*')),
                 'a non-quickbar action decodes to nil, so callers can tell the two apart'

    # page: byte 1 of set_selected_page, byte 0 of change_active_quick_bar
    assert_equal({page: 2}, qb.decode(name: :quick_bar_set_selected_page, data: ['0002'].pack('H*')))
    assert_equal({page: 2}, qb.decode(name: :change_active_quick_bar, data: ['02'].pack('H*')))
  end

  private

  # Build a complete server-to-client heartbeat UDP packet with the given actions.
  # Returns the raw UDP payload bytes.
  def build_server_tc_packet(actions)
    build_heartbeat_packet(actions, is_server: true)
  end

  # Build a complete client-to-server heartbeat UDP packet with the given actions.
  def build_client_tc_packet(actions)
    build_heartbeat_packet(actions, is_server: false)
  end

  def build_heartbeat_packet(actions, is_server:)
    # Net header: 0x07 = msg_type 7 (S2C) or 0x06 = msg_type 6 (C2S)
    net_type = is_server ? 0x07 : 0x06
    parts = [].pack('C*')

    # Assemble the tick closure with actions
    tc_parts = []
    actions.each do |act|
      type_bytes = act[:type] < 0xFF ? [act[:type]].pack('C') : [0xFF].pack('C') + [act[:type]].pack('v')
      delta_bytes = act[:delta] < 0xFF ? [act[:delta]].pack('C') : [0xFF].pack('C') + [act[:delta]].pack('v')
      data_bytes = act[:data].pack('C*')
      tc_parts << type_bytes << delta_bytes << data_bytes
    end

    # count_flagged: count = actions.size, segments = 0
    count_flagged = (actions.size << 1) | 0
    cflag_byte = count_flagged < 0xFF ? [count_flagged].pack('C') : [0xFF].pack('C') + [count_flagged].pack('V')

    # Tick closure: tick (8 bytes) + count_flagged + actions
    tick = [0, 0, 0, 0, 0, 0, 0, 0].pack('C*')  # tick = 0
    tc = tick + cflag_byte + tc_parts.join

    # Heartbeat flags: has_tick_closures=true, has_single_tick_closure=true
    hb_flags = 0x02 | 0x04  # has_tc + single_tc
    # For client: also set has_synchronizer_action? No.
    hb_flags_byte = [hb_flags].pack('C')

    # seq (4 bytes)
    seq = [1, 0, 0, 0].pack('V')

    hb_data = hb_flags_byte + seq + tc

    # For client heartbeat, append next_receive (8 bytes)
    unless is_server
      hb_data += [0, 0, 0, 0, 0, 0, 0, 0].pack('C*')
    end

    # Net header + heartbeat data
    net_hdr = [net_type].pack('C')
    net_hdr + hb_data
  end

  # Extract actions from a parsed UDP payload result
  def extract_actions(result)
    return [] unless result && result[:heartbeat]
    hb = result[:heartbeat]
    hb[:tick_closures]&.flat_map { |tc| tc[:actions] } || []
  end

  # A truncated varint read must not hand the caller a nil offset: the
  # heartbeat parser does `offset = v_off` and then walks from there, so a nil
  # raises NoMethodError mid-packet instead of failing the read. Found on a real
  # heartbeat (2.0.77, 380 B, flags 0x26) — the kind that arrives when a
  # client's action list runs past the packet.
  def test_a_truncated_varint_read_keeps_a_usable_offset
    data = "\x26\x06\xfc\x51\xee\x1d".b
    after, value = FactorioProtocol.decode_uint32v(data, data.bytesize - 1)
    assert_equal data.bytesize, after, 'the offset stays usable'
    assert_nil value
    # and the packet that triggered it parses without raising
    payload = ("\x26\x06\xfc\x51\xee\x1d\x41\x55\x60\x06\x00\x00\x00\x00\x00\x05\xf0\xba\x05\x10fluid-name.water\x01\x00\x05\xc3\x81").b
    refute_raises(NoMethodError) { FactorioProtocol.parse_udp_payload(payload) }
  end
end
