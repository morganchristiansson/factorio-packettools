# frozen_string_literal: true

# Generic "tail -f" for a text file that may not exist yet / rotate under
# us (factorio-current.log is truncated or renamed on restart). Follow
# starts at the CURRENT end of the file (existing content is not replayed)
# and yields each new line to the block as it appears. Rotation/truncation
# is detected the cheap way — file shrank below our position → reopen from
# the start; missing file → poll until it appears. Runs until the block or
# thread is killed; designed to live on its own Thread inside the sniffer.
module LogTail
  POLL_INTERVAL = 0.25 # seconds between reads when idle

  module_function

  # Block form: LogTail.follow(path) { |line| ... } — never returns
  # normally; call inside a Thread. Errors from the BLOCK propagate (the
  # caller's thread rescues); read-side errors (file vanished mid-poll)
  # are handled internally by re-entering the wait-for-file state.
  # Set from_start: true to read from the beginning (for -r replay against
  # an already-complete log file).
  def follow(path, from_start: false, &block)
    seek_end = !from_start
    File.open(path, 'r') do |f|
      f.seek(0, IO::SEEK_END) if seek_end
      loop do
        line = f.gets
        if line
          block.call(line.chomp)
        elsif f.stat.size < f.pos
          f.reopen(path) # rotated/truncated — start over from the top
        else
          sleep POLL_INTERVAL
        end
      rescue IOError, SystemCallError
        # File disappeared between stat and read (rotation race) — wait
        # for it to come back.
        sleep POLL_INTERVAL
        begin
          f.reopen(path)
          # On recovery after disappearance, seek to end if we started that way
          # (don't replay old content); on truncation detection, start from
          # the beginning to catch any post-rotation writes.
          f.seek(0, IO::SEEK_END) if seek_end && f.stat.size >= f.pos
        rescue SystemCallError
          # still gone; keep polling via the outer loop
        end
      end
    end
  end
end
