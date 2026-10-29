# frozen_string_literal: true

require 'zlib'
require 'stringio'
require 'tempfile'
require 'fileutils'

# Link-layer -> UDP framing shared by the offline reader and live capture.
# Both get raw libpcap frames; only this module knows where the IP header is
# (DLT differences) and how to format the address pair. No frame object: the
# callers need the same tuple they always did.
module PcapFormat
  HEADER_SIZE = {
    0 => 4,     # DLT_NULL
    1 => 14,    # DLT_EN10MB
    113 => 16,  # DLT_LINUX_SLL
    276 => 20,  # DLT_LINUX_SLL2
  }.freeze

  # => [src_ip, dst_ip, sport, dport, udp_data, ip_packet] or nil.
  def self.udp(frame, datalink:)
    header = HEADER_SIZE[datalink]
    return nil unless header && frame.bytesize > header
    raw = frame.byteslice(header, frame.bytesize - header)
    return nil if raw.nil? || raw.bytesize < 28 || raw.getbyte(9) != 17
    ihl = (raw.getbyte(0) & 0x0f) * 4
    return nil if raw.bytesize < ihl + 8
    udp = raw.byteslice(ihl + 8, raw.bytesize - ihl - 8)
    return nil if udp.nil? || udp.empty?
    ["#{raw.getbyte(12)}.#{raw.getbyte(13)}.#{raw.getbyte(14)}.#{raw.getbyte(15)}",
     "#{raw.getbyte(16)}.#{raw.getbyte(17)}.#{raw.getbyte(18)}.#{raw.getbyte(19)}",
     raw.unpack1('n', offset: ihl), raw.unpack1('n', offset: ihl + 2),
     udp, raw]
  end

  # TransferBlock (msg 13): [u8 msg][u32 block][503 bytes] => [block, payload].
  def self.transfer_block(udp)
    return nil if udp.bytesize <= 5
    return nil unless (udp.getbyte(0) & 0x1F) == 13
    [udp.unpack1('V', offset: 1), udp.byteslice(5, udp.bytesize - 5).to_s]
  end
end

# PCAP Writer (for saving live capture)
# ─────────────────────────────────────────────────────────────────────
class PcapWriter
  attr_reader :path

  # gzip: true = write the stream gzip-compressed (use a .gz path).
  # keep: rolling retention in HOURS — rotate the capture every hour and
  #   delete files older than `keep` hours. nil = keep everything.
  # rotate_size: rotate a capture file once it exceeds this size (MB).
  # max_size: TOTAL size budget for the rotated files of this capture
  #   (MB) — oldest deleted first once the total is exceeded. nil = no
  #   byte budget (age only). Separate from rotate_size on purpose: one
  #   file is what a reader gets, the total is what the disk allows.
  # timestamped: write straight to a timestamped file
  #   (`base-<YYYYMMDD-HHMMSS>.pcap`) — the latest file IS the live one,
  #   no renames, no stable path. Restarts just open a new file. Used for
  #   both the normal capture and the small unknown-packet capture.
  def initialize(path, gzip: false, keep: nil, rotate_size: nil, max_size: nil, timestamped: false)
    @base_path = path
    @timestamped = timestamped
    @gzip = gzip
    @keep_hours = keep
    @rotate_bytes = rotate_size ? rotate_size * 1024 * 1024 : nil
    @max_size_bytes = max_size ? max_size * 1024 * 1024 : nil
    @start_time = Time.now
    @file_start = Time.now
    if timestamped
      @path = unique_timestamped_path(Time.now)
    else
      @path = path
      rotate_on_restart  # never silently destroy the previous run's capture
    end
    @file = open_file(@path)
    write_global_header
    # Ruby IO (or GzipWriter) and the kernel buffer writes. No per-record
    # flush/fsync; close on rotation/shutdown finalizes the buffered stream.
  end

  # Write a real captured Ethernet frame as-is (fast path for live capture;
  # avoids rebuilding fake IP/UDP headers per packet).
  def write_frame(frame, ts = Time.now)
    write_record(ts, frame)
  end

  def close
    return unless @file
    @file.close
    @file = nil
    # Logical bytes also identify an empty gzip stream correctly.
    File.delete(@path) if @timestamped && @bytes_written == 24 && File.exist?(@path)
  end

  private

  def open_file(path)
    io = File.open(path, 'wb')
    @gzip ? Zlib::GzipWriter.new(io) : io
  end

  def write_record(ts, data)
    return unless data
    ts_sec = ts.to_i
    ts_usec = ((ts.to_f - ts_sec) * 1_000_000).to_i
    hdr = [ts_sec, ts_usec, data.bytesize, data.bytesize].pack('VVVV')
    return unless @file
    rotate_if_due
    @file.write(hdr + data.b)
    @bytes_written += hdr.bytesize + data.bytesize
  end

  # If @path already holds a capture (previous run / restart), rename it
  # with a timestamp instead of overwriting — history is preserved.
  # Header-only files (24-byte pcap global header, zero packets — e.g. a
  # seconds-long run) carry nothing worth preserving: delete instead of
  # renaming, so restarts don't accumulate 4K timestamped clutter.
  def rotate_on_restart
    return unless File.exist?(@path)
    if File.size(@path) <= 24
      File.delete(@path)
      return
    end
    finished = timestamped_path(File.mtime(@path).strftime('%Y%m%d-%H%M%S'))
    finished = timestamped_path(Time.now.strftime('%Y%m%d-%H%M%S')) if File.exist?(finished)
    File.rename(@path, finished)
    prune_rotated
  end

  # Hourly and/or size-based rotation + retention: close the finished
  # file and open a fresh timestamped one (timestamped mode — nothing to
  # rename; the finished file's name was final from the start), then prune
  # beyond the retention bounds. Single owner: the capture thread.
  # Size rotation counts uncompressed bytes, including buffered data; for
  # gzip this is conservative.
  def rotate_if_due
    due = @keep_hours && (Time.now - @file_start) >= 3600
    if @rotate_bytes
      due = true if @bytes_written >= @rotate_bytes
    end
    return unless due
    @file.close
    @file = nil
    if @timestamped
      @path = unique_timestamped_path(Time.now)
    else
      finished = timestamped_path(@file_start.strftime('%Y%m%d-%H%M%S'))
      File.rename(@path, finished) if File.exist?(@path)
    end
    @file = open_file(@path)
    write_global_header
    @file_start = Time.now
    prune_rotated
  end

  # Pcap global header on every freshly opened file (init AND rotation —
  # the old code forgot the rotation case, leaving headerless files).
  def write_global_header
    @bytes_written = 24
    # Written directly (avoids pack issues)
    @file.write([0xd4, 0xc3, 0xb2, 0xa1].pack('C4'))  # magic LE
    @file.write([2, 4].pack('v2'))  # version
    @file.write([0, 0].pack('V2'))  # timezone, sigfigs
    @file.write([65535].pack('V'))   # snaplen
    @file.write([1].pack('V'))       # linktype = Ethernet
  end

  def timestamped_path(ts)
    suffix = if @base_path.end_with?('.pcap.gz')
               '.pcap.gz'
             else
               File.extname(@base_path)
             end
    stem = @base_path[0...-suffix.length]
    "#{stem}-#{ts}#{suffix}"
  end

  # First free `base-<ts>.pcap` at or after `time` (same-second restarts
  # must not collide).
  def unique_timestamped_path(time)
    t = time
    loop do
      cand = timestamped_path(t.strftime('%Y%m%d-%H%M%S'))
      return cand unless File.exist?(cand)
      t += 1
    end
  end

  # Retention: age first (`keep` hours), then — when max_size is set —
  # the OLDEST rotated files until the total rotated size fits. The
  # ACTIVE file is never pruned (it is still being written).
  def prune_rotated
    rotated = rotated_files
    if @keep_hours
      cutoff = Time.now - (@keep_hours * 3600)
      rotated.each do |f|
        if File.mtime(f) < cutoff
          puts "retention: deleted #{f} (older than #{@keep_hours}h)"
          File.delete(f)
        end
      end
      rotated = rotated_files
    end
    if @max_size_bytes
      total = rotated.sum { |f| File.size(f) }
      rotated.sort_by { |f| File.mtime(f) }.each do |f|
        break if total <= @max_size_bytes
        total -= File.size(f)
        puts "retention: deleted #{f} (over #{@max_size_bytes / 1024 / 1024}MB total)"
        File.delete(f)
      end
    end
  rescue Errno::ENOENT
    # file vanished between glob and delete
  end

  def rotated_files
    ext = File.extname(@base_path)
    stem = File.basename(@base_path, ext)
    Dir.glob(File.join(File.dirname(@base_path), "#{stem}-*#{ext}")) - [@path]
  end

end

# PCAP Reader
# ─────────────────────────────────────────────────────────────────────
class PcapReader
  def initialize(path)
    @path = path
  end

  def each_packet
    if gzip?
      Tempfile.create(['factorio-pcap', '.pcap']) do |file|
        file.binmode
        stream_gunzip(file)
        file.flush
        read_capture(file.path) { |*args| yield(*args) }
      end
    else
      read_capture(@path) { |*args| yield(*args) }
    end
  end

  private

  def gzip?
    raw = File.binread(@path, 2)
    raw.getbyte(0) == 0x1f && raw.getbyte(1) == 0x8b
  end

  # Streaming gunzip: 1MB chunks straight into the temp file, so a whole
  # capture never materializes as one Ruby string (File.binread of a
  # multi-hundred-MB .gz was the streaming replay's own OOM source).
  # Best-effort like before: a .gz still being written decompresses as
  # far as its bytes allow and warns about the truncation.
  def stream_gunzip(file)
    Zlib::GzipReader.open(@path) do |gz|
      while (chunk = gz.read(1 << 20))
        file.write(chunk)
      end
    end
  rescue Zlib::GzipFile::Error => e
    warn "Warning: gzip stream incomplete (#{e.message}); using what decompressed so far"
  end

  def read_capture(path)
    old_verbose = $VERBOSE
    $VERBOSE = nil
    require 'pcaprub'
    capture = PCAPRUB::Pcap.open_offline(path)
    datalink = capture.datalink
    pkt_num = 0
    capture.each_packet do |packet|
      pkt_num += 1
      frame = packet.data
      udp = PcapFormat.udp(frame, datalink: datalink)
      next unless udp
      src, dst, sport, dport, udp_data, = udp
      yield(pkt_num, packet.time + packet.microsec / 1_000_000.0,
            src, dst, sport, dport, udp_data, frame)
    end
  ensure
    capture&.close
    $VERBOSE = old_verbose
  end
end
