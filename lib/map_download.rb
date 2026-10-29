# frozen_string_literal: true

# Map-download reassembly from the LIVE stream (client mode).
#
# On join, the server streams its whole save as TransferBlock (msg 13)
# packets: `[u8 msg=13][u32 block number][503 bytes]`, and blocks 0..N
# concatenated are the save archive — the same file
# tools/extract_save_from_pcap.rb rebuilds offline. That save carries the
# FULL roster, which is the one thing a client cannot learn any other way: the
# wire only ever shows the players who join after us. So we seed
# players-cache.json from it.
#
# NOTHING heavy happens on the capture thread: the download bursts at ~20k
# pps and blocking there is what overflowed the kernel buffer before. #add_block
# is one hash store under a mutex; a worker thread waits for the stream to go
# quiet, concatenates the blocks and hands the archive to the roster tool.
#
# Server mode does not use this at all — the server has the save on disk and
# RCON is authoritative.
class MapDownload
  BLOCK_SIZE = 503
  # Seconds without a block before we call the download finished. The last
  # block of a download is followed by silence, and a partial download is
  # harmless (see #process).
  QUIET_SECONDS = 5.0
  # Sanity bound, not a size opinion: a real save can exceed 120 MB (240k
  # blocks — the old 200k cap silently truncated it). 4M blocks ≈ 2 GB.
  MAX_BLOCKS = 4_000_000

  attr_reader :blocks_seen, :downloads

  def initialize(dir:, quiet: QUIET_SECONDS, on_incomplete: nil, &on_complete)
    @dir = dir
    @quiet = quiet
    @on_complete = on_complete
    @on_incomplete = on_incomplete
    @blocks = {}
    @mutex = Mutex.new
    @cv = ConditionVariable.new
    @blocks_seen = 0
    @downloads = 0
    @cap_warned = false
    @thread = Thread.new { work }
  end

  # Called from the capture thread — keep it to a hash store.
  def add_block(number, payload)
    @mutex.synchronize do
      if @blocks.size >= MAX_BLOCKS
        unless @cap_warned
          warn "[map-download] block cap #{MAX_BLOCKS} reached (#{@blocks.size} blocks) — remaining blocks dropped"
          @cap_warned = true
        end
        return
      end
      return if @blocks.key?(number) # a retransmit; keep the first copy
      @blocks[number] = payload
      @blocks_seen += 1
      @last_at = monotonic
      @cv.signal
    end
  end

  # LiveCapture invokes the transfer-block hook through #call (it carries a
  # callable, per live_capture.rb's contract) — adapt the contract so the
  # sniffer's map-download reassembly runs on the capture thread. add_block
  # stays the real implementation used directly by tests.
  def call(number, payload)
    add_block(number, payload)
  end

  def stop
    @thread&.kill
  end

  private

  def monotonic
    Process.clock_gettime(Process::CLOCK_MONOTONIC)
  end

  def work
    loop do
      blocks = take_download
      next unless blocks
      begin
        process(blocks)
      rescue StandardError => e
        # One bad download must not kill the reassembler for the session.
        warn "[map-download] reassembly failed: #{e.class}: #{e.message}"
      end
    end
  end

  # Block until a download has gone quiet, then take it. nil = keep waiting.
  def take_download
    @mutex.synchronize do
      @cv.wait(@mutex) while @blocks.empty?
      until @blocks.empty?
        left = @quiet - (monotonic - @last_at)
        break if left <= 0
        @cv.wait(@mutex, left)
      end
      next if @blocks.empty?
      taken = @blocks
      @blocks = {}
      taken
    end
  end

  # Concatenate and hand over. A download with holes in it is not a usable
  # archive (the zip central directory lives at the end), so we skip it and
  # say so rather than seeding a roster from a broken file.
  def process(blocks)
    numbers = blocks.keys.sort
    missing = 0.upto(numbers.last).reject { |bn| blocks.key?(bn) }
    if missing.any?
      warn "[map-download] #{blocks.size} blocks, #{missing.size} missing from 0..#{numbers.last} " \
           "(e.g. #{missing.first(3).inspect}) — capture loss, roster not seeded"
      @on_incomplete&.call
      return
    end
    data = numbers.map { |bn| blocks[bn] }.join
    path = File.join(@dir, "map-download-#{Time.now.strftime('%Y%m%d-%H%M%S')}.zip")
    unless data.start_with?("PK\x03\x04".b) && data.include?("PK\x05\x06".b)
      # Keep the evidence: a truncated stream is what we need to diagnose,
      # and the previous code deleted it before anyone could look.
      File.binwrite(path, data)
      warn "[map-download] #{blocks.size} blocks (0..#{numbers.last}, #{data.bytesize} bytes) " \
           "— incomplete archive (first #{data.byteslice(0, 4).bytes.map { |b| format('%02x', b) }.join}) " \
           "— kept #{path}"
      @on_incomplete&.call
      return
    end
    File.binwrite(path, data)
    @downloads += 1
    @on_complete&.call(path, blocks.size)
  end

end
