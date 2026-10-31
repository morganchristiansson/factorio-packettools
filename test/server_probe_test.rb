# frozen_string_literal: true
# Tests for FactorioServerProbe's transport: the single-socket bulk refresher
# and the single-server probe, over UDP loopback (no real network).
# Run: bundle exec ruby -Ilib test/server_probe_test.rb
require 'minitest/autorun'
require_relative '../lib/server_probe'

class ServerProbeSpec < Minitest::Test
  # Build a minimal valid msg-17 reply payload (network header already
  # stripped). Small varints pack as a single byte (encode_uint8), which
  # parse_game_info reads back through decode_uint32v -- enough to reach the
  # player-name list and prove the count drains correctly.
  def minimal_reply(names)
    p = "\x00" * 12                  # opaque server id block
    p += [4].pack('C') + 'Test'        # name (len 4)
    p += [2, 0, 77].pack('C3')         # version 2.0.77
    p += [0].pack('V')                 # build
    p += [0].pack('C')                 # description length 0
    p += [0, 0].pack('V2')             # time_min + trailing u32
    p += [9].pack('C') + '1.2.3.4:5'   # host (len 9)
    p += "\x01\x00\x01"                # port prefix
    p += [0].pack('C')                 # mod count 0
    p += [0].pack('C')                 # tag count 0
    p += [names.length].pack('C')      # player count
    names.each { |n| p += [n.bytesize].pack('C') + n }
    p += "\x01"                        # trailing byte
    p.b
  end

  # Spin up a local UDP "server" on 127.0.0.1 that answers the msg-16 probe
  # with a forged msg-17, then let the single-socket refresher drain it.
  def start_fake_server(names)
    s = UDPSocket.new(Socket::AF_INET)
    s.bind('127.0.0.1', 0)
    port = s.addr[1]
    t = Thread.new do
      loop do
        begin
          data, sender = s.recvfrom(1024)
        rescue IOError
          break
        end
        break if data.nil? || data.empty?
        # sender = [family, port, hostname, ip]; reply to the numeric peer.
        s.send("\x11".b + minimal_reply(names), 0, sender[3], sender[1])
      end
    end
    [s, port, t]
  end

  def test_refresh_counts_drains_replies_on_one_socket
    s, port, t = start_fake_server(%w[bob alice])
    begin
      addr = "127.0.0.1:#{port}"
      live = FactorioServerProbe.refresh_counts([addr], timeout: 1)
      assert_equal 2, live[addr], 'the single-socket drain caught the forged reply'
    ensure
      s.close
      t.kill
      t.join
    end
  end

  def test_refresh_counts_dead_port_is_nil
    # Bind an ephemeral port, close it, then probe the vacated port -> no
    # reply, no exception, recorded as nil.
    s = UDPSocket.new
    s.bind('127.0.0.1', 0)
    dead_port = s.addr[1]
    s.close
    live = FactorioServerProbe.refresh_counts(["127.0.0.1:#{dead_port}"], timeout: 0.3)
    assert_equal({ "127.0.0.1:#{dead_port}" => nil }, live)
  end

  def test_refresh_counts_handles_mixed_live_and_dead
    s, port, t = start_fake_server(%w[bob])
    begin
      s2 = UDPSocket.new
      s2.bind('127.0.0.1', 0)
      dead_port = s2.addr[1]
      s2.close
      live = FactorioServerProbe.refresh_counts(["127.0.0.1:#{dead_port}", "127.0.0.1:#{port}"], timeout: 0.5)
      assert_nil live["127.0.0.1:#{dead_port}"]
      assert_equal 1, live["127.0.0.1:#{port}"]
    ensure
      s.close
      t.kill
      t.join
    end
  end

  def test_refresh_counts_empty_list
    assert_equal({}, FactorioServerProbe.refresh_counts([]))
  end
end
