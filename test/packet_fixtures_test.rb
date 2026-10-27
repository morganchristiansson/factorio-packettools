#!/usr/bin/env ruby
# frozen_string_literal: true

# Fixture-driven regression tests.
# Run: ruby -Ilib test/packet_fixtures_test.rb
#
# Tests the REAL FactorioProtocol implementation against:
#  1. REAL packets captured from live sessions (test/fixtures/packets.rb)
#  2. Synthetic variations of write_to_console payloads (test/fixtures/chat_variations.rb)

require 'minitest/autorun'
require 'mocha/minitest'
require 'factorio_protocol'
require_relative 'fixtures/packets'
require_relative 'fixtures/chat_variations'

class TestPacketFixtures < Minitest::Test
  def teardown
    # Never leak version-dependent tables into the following tests.
    FactorioProtocol.reset_version
  end

  # Simulate FactorioPacketTools#chat_action_data reassembly: merge segments of
  # a split write_to_console (keyed by player, ordered by seg_no) and return
  # the full payload. Mirrors the sniffer so the reassembly path is tested
  # end-to-end.
  def reassemble(split_actions)
    by_player = Hash.new { |h, k| h[k] = {} }
    split_actions.each { |act| by_player[act[:game_player]][act[:seg_no]] = act[:data] }
    by_player.map { |_player, parts| parts.keys.sort.map { |n| parts[n] }.join }
  end

  # Each real packet must parse to exactly the expected actions.
  REAL_PACKET_FIXTURES.each do |fx|
    define_method("test_fixture_#{fx[:name]}") do
      FactorioProtocol.select_version(fx[:version] || '2.1')
      result = FactorioProtocol.parse_udp_payload([fx[:hex]].pack('H*'))
      refute_nil result, "#{fx[:name]}: parse_udp_payload returned nil"
      hb = result[:heartbeat]
      actions = (hb[:tick_closures] || []).flat_map { |tc| tc[:actions] }

      assert_equal fx[:actions].size, actions.size,
                   "#{fx[:name]}: expected #{fx[:actions].size} actions, got #{actions.size}"

      fx[:actions].each_with_index do |exp, i|
        act = actions[i]
        refute_nil act, "#{fx[:name]}: action #{i} missing"
        assert_equal exp[:type], act[:type], "#{fx[:name]} action #{i} type"
        assert_equal exp[:name], act[:name], "#{fx[:name]} action #{i} name"
        assert_equal exp[:game_player], act[:game_player], "#{fx[:name]} action #{i} game_player"
        got_data = act[:data] ? act[:data].unpack1('H*') : nil
        assert_equal exp[:data], got_data, "#{fx[:name]} action #{i} data"
        assert_equal exp[:total_segs], act[:total_segs], "#{fx[:name]} action #{i} total_segs" if exp.key?(:total_segs)
        assert_equal exp[:seg_no], act[:seg_no], "#{fx[:name]} action #{i} seg_no" if exp.key?(:seg_no)
        if exp.key?(:chat)
          msg = FactorioProtocol.decode_chat(act[:data])
          if exp[:chat].nil?
            assert_nil msg, "#{fx[:name]} action #{i} chat decode"
          else
            assert_equal exp[:chat], msg, "#{fx[:name]} action #{i} chat decode"
          end
        end
      end
      refute hb[:hit_unknown], "#{fx[:name]}: heartbeat reported hit_unknown"
    end
  end

  # Split-chat reassembly: the two messages above are replayed as the sniffer
  # would reassemble them (segments keyed by player, merged by seg_no), and
  # decode_chat must return the FULL message — NOT a fragment truncated when a
  # player byte >= 0x40 was misread as a length, and NOT cut at the segment
  # boundary.
  def test_split_chat_reassembled_full_text_p66
    %w[client_split_chat_2seg_p66_seg0 client_split_chat_2seg_p66_seg1].each do |name|
      fx = REAL_PACKET_FIXTURES.find { |f| f[:name] == name }
      FactorioProtocol.select_version(fx[:version])
      result = FactorioProtocol.parse_udp_payload([fx[:hex]].pack('H*'))
      @split ||= []
      @split.concat((result[:heartbeat][:tick_closures] || []).flat_map { |tc| tc[:actions] })
    end
    joined = reassemble(@split)
    assert_equal 1, joined.size
    msg = FactorioProtocol.decode_chat(joined.first)
    assert_equal 'hivemind what are your personal, deep, and hidden feelings towards the player morganc, the kind you would never tell...', msg
  end

  def test_split_chat_reassembled_long_4seg_p54
    %w[client_split_chat_4seg_p54_seg0 client_split_chat_4seg_p54_seg1 client_split_chat_4seg_p54_seg2 client_split_chat_4seg_p54_seg3].each do |name|
      fx = REAL_PACKET_FIXTURES.find { |f| f[:name] == name }
      FactorioProtocol.select_version(fx[:version])
      result = FactorioProtocol.parse_udp_payload([fx[:hex]].pack('H*'))
      @split ||= []
      @split.concat((result[:heartbeat][:tick_closures] || []).flat_map { |tc| tc[:actions] })
    end
    joined = reassemble(@split)
    assert_equal 1, joined.size
    msg = FactorioProtocol.decode_chat(joined.first)
    assert_equal 298, msg.bytesize, 'long message must be returned in full (uint32v LONG-form length)'
    assert msg.start_with?('Hivemind, the definition of consensus is not equal to being unanimous: Consensus means a general or')
    assert msg.end_with?('even if they do not all fully agree on every single detail.')
  end

  # Each chat payload variation must decode to the expected text.
  CHAT_DECODE_FIXTURES.each do |fx|
    define_method("test_chat_variation_#{fx[:name]}") do
      data = [fx[:data]].pack('H*')
      msg = FactorioProtocol.decode_chat(data)
      if fx[:expected].nil?
        assert_nil msg, "decode_chat for #{fx[:name]} should be nil"
      else
        assert_equal fx[:expected], msg, "decode_chat for #{fx[:name]}"
      end
    end
  end
  # The content-defined parsers are code, not data: pin them separately, or a
  # layout change would only show up as "flagged packets", which nobody watches.
  def test_translate_string_layout_is_pinned
    FactorioProtocol.select_version('2.0')
    count = 1
    entry = [3].pack('C') + 'key' + [0x01, 0x00].pack('C2') + [2].pack('C') + 'hi' + ("\x00" * 9)
    payload = [count].pack('C') + entry
    data = [0x26, 0x06, 0, 0, 0, 0].pack('C*') + [0].pack('Q<') + [0x02].pack('C') +
           [240, 0x00].pack('C2') + payload + [0, 0, 0, 0, 0, 0, 0, 0].pack('C*')
    acts = FactorioProtocol.parse_udp_payload(data).dig(:heartbeat, :tick_closures).first[:actions]
    assert_equal 1, acts.size
    assert_equal 240, acts[0][:type]
    refute acts[0][:hit_unknown], 'translate_string must consume exactly count entries + 9-byte argument block'
  end

  # S→C render_mode_changed carries its 1-byte payload (not a +16 trailer), so
  # the packet's well-formed SkippedTickClosure sync is NOT misread as a phantom
  # PeerDisconnect (peer_id 0xAE60=44640 → bogus "Player_44641 left the game").
  # The fixture above pins the actions; this pins the sync section, which the
  # fixture harness does not check.
  def test_s2c_render_mode_changed_sync_is_skipped_tick_closure
    FactorioProtocol.select_version('2.1')
    fx = REAL_PACKET_FIXTURES.find { |f| f[:name] == 's2c_render_mode_changed_sync_not_phantom_peer' }
    hb = FactorioProtocol.parse_udp_payload([fx[:hex]].pack('H*'))[:heartbeat]
    sync = hb[:sync_actions]
    assert_equal 1, sync.size
    assert_equal 'SkippedTickClosure', sync[0][:name]
    assert_equal 21737056, sync[0][:tick]
    assert_equal 0, sync[0][:peer_id]
    refute sync.any? { |s| s[:name] == 'PeerDisconnect' }, 'no phantom PeerDisconnect from the desynced sync read'
  end

  # S→C echo length regressions: open_character_gui and set_use_inserter_filters
  # echoes carry a 1-byte body (not the +metadata/+15/+0 forms that overran),
  # so their packet tails are NOT read as a phantom PeerDisconnect (→ bogus
  # "Player_49xxx left the game").
  def test_s2c_short_echo_not_phantom_peer
    {
      's2c_open_character_gui_echo_1byte' => 62,
      's2c_set_use_inserter_filters_echo_1byte' => 274,
    }.each do |fxname, type|
      fx = REAL_PACKET_FIXTURES.find { |f| f[:name] == fxname }
      FactorioProtocol.select_version('2.1')
      hb = FactorioProtocol.parse_udp_payload([fx[:hex]].pack('H*'))[:heartbeat]
      refute hb[:sync_actions].any? { |s| s[:name] == 'PeerDisconnect' },
             "#{fxname}: no phantom PeerDisconnect"
      act = hb[:tick_closures].first[:actions].find { |a| a[:type] == type }
      assert_equal '01', act[:data]&.unpack1('H*'), "#{fxname}: echoed body is the 1-byte parameter"
    end
  end

  # S→C drag-build echo + the chat segment after it: the drag build is TWO
  # records (21 bytes), and the write_to_console segment lands right after.
  # Regression: the echo read 11 bytes, so the segment was read from inside
  # the second record — "do we have large mining drills?" came out as garbage
  # (phantom Player_460). The fixtures pin the parse; this reassembles the two
  # segments back into the full message as the sniffer would.
  def test_s2c_drag_build_chat_reassembles_full_text
    %w[s2c_drag_build_then_chat_seg0 s2c_drag_build_then_chat_seg1].each do |name|
      fx = REAL_PACKET_FIXTURES.find { |f| f[:name] == name }
      FactorioProtocol.select_version(fx[:version])
      result = FactorioProtocol.parse_udp_payload([fx[:hex]].pack('H*'))
      @split ||= []
      wts = (result[:heartbeat][:tick_closures] || []).flat_map { |tc| tc[:actions] }
        .select { |a| a[:name] == 'write_to_console' }
      @split.concat(wts)
    end
    joined = reassemble(@split)
    assert_equal 1, joined.size
    assert_equal 'do we have large mining drills?', FactorioProtocol.decode_chat(joined.first)
  end

  # A translate_string whose entries run past the end of the payload used to
  # raise out of the decode (the key length was added to 3 BEFORE the nil
  # check), which killed the whole packet on the capture thread — the
  # operator saw a backtrace and a dead sniffer, not a flagged packet. A
  # truncated one is simply unknown from there on.
  def test_truncated_translate_string_does_not_raise
    FactorioProtocol.select_version('2.0')
    entry = [3].pack('C') + 'key' + [0x01, 0x00].pack('C2') + [2].pack('C') + 'hi' + ("\x00" * 9)
    # count says 2 entries, only one is there — the second read is off the end
    payload = [2].pack('C') + entry
    data = [0x26, 0x06, 0, 0, 0, 0].pack('C*') + [0].pack('Q<') + [0x02].pack('C') +
           [240, 0x00].pack('C2') + payload
    result = nil
    assert_silent { result = FactorioProtocol.parse_udp_payload(data) }
    acts = result.dig(:heartbeat, :tick_closures).first[:actions]
    assert acts.any? { |a| a[:type] == 240 }, 'the action is still seen'
    assert acts.any? { |a| a[:hit_unknown] }, 'and flagged unknown instead of crashing the sniffer'
  end
end
