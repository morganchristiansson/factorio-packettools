#!/usr/bin/env ruby
# frozen_string_literal: true

# Live map-download reassembly (client mode): the roster seed that a client
# cannot get any other way — the wire only shows players who join after it.
#
# The quiet period is what decides "the download is over", so the tests drive
# it with a tiny one rather than sleeping on the real 5s.
require 'minitest/autorun'
require 'mocha/minitest'
require 'tmpdir'
require 'map_download'
require 'live_capture'
require_relative '../factorio-packettools'

class TestMapDownload < Minitest::Test
  BLOCKS = 12

  # one block per player, each exactly MapDownload::BLOCK_SIZE bytes
  def block_bytes(n)
    ["#{n}:".ljust(MapDownload::BLOCK_SIZE, 'x').b]
  end

  def stream_bytes
    (0...BLOCKS).map { |i| block_bytes(i).first }.join
  end

  def feed(dl, bytes = stream_bytes)
    bytes.bytes.each_slice(MapDownload::BLOCK_SIZE).with_index do |slice, bn|
      dl.add_block(bn, slice.pack('C*'))
    end
  end

  # Wait for the worker to hand over, without sleeping on a fixed guess.
  def await(timeout = 5)
    deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + timeout
    sleep 0.01 while @done.nil? && Process.clock_gettime(Process::CLOCK_MONOTONIC) < deadline
    @done
  end

  def setup
    @done = nil
    @dir = Dir.mktmpdir
  end

  def teardown
    @dl&.stop
    FileUtils.remove_entry(@dir) if @dir && File.directory?(@dir)
  end

  # Ethernet + IPv4 + UDP frame carrying one msg 13 TransferBlock
  def transfer_frame(block_number, payload = 'A' * MapDownload::BLOCK_SIZE)
    udp_len = 8 + 5 + payload.bytesize
    len = 20 + udp_len
    eth = [0x0800].pack('n') + ("\x00" * 12)
    ip = [0x45, 0x00, len / 256, len % 256, 0, 0, 0, 0, 64, 17, 0, 0,
          10, 0, 0, 1, 10, 0, 0, 2].pack('C*')
    udp = [34197, 34197, udp_len, 0].pack('n4') # ports, length, checksum
    eth + ip + udp + "\x0d".b + [block_number].pack('V') + payload.b
  end

  def test_the_capture_fast_path_hands_the_reassembler_a_whole_block
    number, payload = LiveCapture.transfer_block(transfer_frame(7))
    assert_equal 7, number
    assert_equal MapDownload::BLOCK_SIZE, payload.bytesize
    assert_nil LiveCapture.transfer_block("\x00" * 60) # not a msg 13
    @dl = MapDownload.new(dir: @dir, quiet: 0.05) { |zip, n| @done = [zip, n] }
    @dl.add_block(number, payload)
    _zip, blocks = await
    assert_equal 1, blocks
  end

  # LiveCapture invokes the transfer-block hook through #call (callable
  # contract), not add_block directly — cover that path so a missing #call
  # regresses the test instead of crashing client mode.
  def test_call_delegates_to_add_block
    number, payload = LiveCapture.transfer_block(transfer_frame(7))
    @dl = MapDownload.new(dir: @dir, quiet: 0.05) { |zip, n| @done = [zip, n] }
    assert_respond_to @dl, :call
    @dl.call(number, payload)
    _zip, blocks = await
    assert_equal 1, blocks
  end

  def test_assembles_contiguous_blocks_into_one_archive
    @dl = MapDownload.new(dir: @dir, quiet: 0.05) { |zip, n| @done = [zip, n] }
    feed(@dl)
    zip, blocks = await
    assert_equal BLOCKS, blocks
    assert_equal stream_bytes, File.binread(zip)
  end

  def test_a_download_with_a_hole_is_not_offered
    @dl = MapDownload.new(dir: @dir, quiet: 0.05) { |zip, n| @done = [zip, n] }
    feed(@dl)
    # capture loss in the middle: the archive would have a hole in it and the
    # zip's central directory lives at the end, so it is not usable
    @dl.instance_variable_get(:@mutex).synchronize { @dl.instance_variable_get(:@blocks).delete(4) }
    sleep 0.3
    assert_nil @done
    assert_equal 0, @dl.downloads
  end

  def test_a_second_download_is_taken_separately
    seen = []
    @done = nil
    @dl = MapDownload.new(dir: @dir, quiet: 0.05) { |zip, _n| seen << File.binread(zip); @done = zip }
    feed(@dl)
    await # the first download is taken once the stream goes quiet
    @done = nil
    feed(@dl, block_bytes(99).first)
    await
    assert_equal 2, seen.size
    assert_equal stream_bytes, seen.first
  end

  def test_retransmitted_blocks_are_kept_once
    @dl = MapDownload.new(dir: @dir, quiet: 0.05) { |zip, n| @done = [zip, n] }
    feed(@dl)
    @dl.add_block(0, 'ZZZZ') # a retransmit must not overwrite the first copy
    zip, = await
    assert_equal stream_bytes, File.binread(zip)
  end

  # A three-player level.dat (the same shape the save carries), through the
  # sniffer's own seed path: subprocess, merge into players-cache.json, and
  # the RUNNING session's database picks the names up.
  def record(name, play, last_seen)
    stats = [play, 0, last_seen, 0].pack('V4')
    ("\xa5" * 300).b + stats.b + "\x00\x80\x3f".b + name.bytesize.chr.b + name.b + "\x00\x00".b
  end

  class FakeWriter
    attr_reader :path

    def initialize = @path = 'fake.pcap'
    def write_frame(*) = nil
    def close = nil
  end

  def test_seeding_fills_the_running_sessions_cache
    level = File.join(@dir, 'level.dat')
    File.binwrite(level, [record('coal', 0, 0).sub(/coal.{4}/, 'x' * 8),
                          record('alice', 1000, 90_000),
                          record('bob', 2000, 91_000),
                          record('carol', 3000, 92_000)].join)
    cache = File.join(@dir, 'players-cache.json')
    output = nil
    db = nil
    # the sniffer's own side files (unknown.packets-*.pcap) follow the cwd
    Dir.chdir(@dir) do
      sniffer = FactorioPacketTools.new({player_db: cache}, pcap_writer: FakeWriter.new)
      output, = capture_io { sniffer.send(:seed_roster_from_save, level, 4) }
      db = sniffer.instance_variable_get(:@player_db)
    end
    assert_equal({1 => 'alice', 2 => 'bob', 3 => 'carol'},
                 db.players.transform_values { |p| p[:name] })
    assert_equal %w[alice bob carol], JSON.parse(File.read(cache)).values.map { |v| v['name'] }
    assert_includes output, '[map-download] roster: 3 players'
  end

  # roster_save: startup disk-seed — a directory picks the newest save, an
  # explicit file path is used as-is, and the running session's DB reloads.
  # Writes real save-like zips (one zlib-compressed level.dat entry, the
  # shape Factorio's archive uses) so the extract tool's unzip path is used.
  def save_zip(path, *records)
    require 'zip'
    content = ('coal'.ljust(300).b + records.join).b
    buf = Zip::OutputStream.write_buffer do |zos|
      # real saves nest level.dat under a dir; the extract tool greps for `/level.dat`
      zos.put_next_entry('save/level.dat')
      zos.write(Zlib::Deflate.deflate(content))
    end
    File.binwrite(path, buf.string)
  end

  def test_roster_save_seeds_from_a_file_or_latest_in_a_directory
    saves = File.join(@dir, 'saves')
    Dir.mkdir(saves)
    old = File.join(saves, 'old.zip')
    new = File.join(saves, 'new.zip')
    save_zip(old, record('alice', 1000, 90_000), record('bob', 2000, 91_000))
    save_zip(new, record('carol', 3000, 92_000))
    File.utime(Time.now + 5, Time.now + 5, new) # make `new` clearly the newest
    cache = File.join(@dir, 'players-cache.json')

    # directory: picks the newest (new.zip -> carol only)
    Dir.chdir(@dir) do
      sniffer = FactorioPacketTools.new({player_db: cache}, pcap_writer: FakeWriter.new)
      sniffer.instance_variable_get(:@options)[:roster_save] = saves
      sniffer.send(:seed_roster_from_disk_save)
      db = sniffer.instance_variable_get(:@player_db)
      assert_equal %w[carol], db.players.transform_values { |p| p[:name] }.values
    end

    # explicit file: uses old.zip as-is (alice + bob) into a fresh cache
    cache2 = File.join(@dir, 'players-cache2.json')
    Dir.chdir(@dir) do
      sniffer = FactorioPacketTools.new({player_db: cache2}, pcap_writer: FakeWriter.new)
      sniffer.instance_variable_get(:@options)[:roster_save] = old
      sniffer.send(:seed_roster_from_disk_save)
      db = sniffer.instance_variable_get(:@player_db)
      assert_equal %w[alice bob], db.players.transform_values { |p| p[:name] }.values
    end

    # empty directory: warns, no crash, cache unchanged
    empty = File.join(@dir, 'empty')
    Dir.mkdir(empty)
    Dir.chdir(@dir) do
      sniffer = FactorioPacketTools.new({player_db: cache}, pcap_writer: FakeWriter.new)
      sniffer.instance_variable_get(:@options)[:roster_save] = empty
      _, err = capture_io { sniffer.send(:seed_roster_from_disk_save) }
      assert_includes err, 'no .zip saves'
    end
  end
end
