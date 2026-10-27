# frozen_string_literal: true

# Sniffer feature `action_validator` (config.yaml `plugins:`) — runtime
# action-ID validation, the live form of tools/validate_actions.rb.
#
# Receives the server's factorio-current.log lines (tailked ONCE by the
# host in FactorioPacketTools#start_log_watcher, fanned out as :on_log_line
# over the plugin bus) and joins them against the decoded C→S input
# actions by (tick, player,
# position): the log names actions, the capture numbers them — the join
# pins wire IDs to names and flags MISMATCH / NOT-IN-TABLE / a lost
# action at runtime, on the live server, while it happens. No RCON and
# no toggle here: action logging must already be on (it is what the log
# lines are); the file is read-only.
#
# The correlation pairs also VOTE: every (wire id → log name) pair lands
# in #votes, so the periodic summary can list wire IDs whose winning log
# name disagrees with the action table — candidate corrections for
# lib/input_actions_21.rb, exactly what the offline validator's
# --suggest prints. Unlike the offline tool, this sees the desync damage
# too: a (tick, player) whose log and wire sequences DIFFER in length is
# a lost/invented action — usually a wrong measured length before it.
#
# Server mode (host log via RCON) or client mode with an explicit
# log_path: pointing at the server's factorio-current.log.
class ActionValidator
  LOG_RE = /Action performed \[(\d+) (\d+) (\w+)\]/.freeze

  # Eviction is by GAME TICK, not wall time: the join is tick-based, so
  # age is measured in ticks. Entries older than the newest seen tick by
  # more than TICK_WINDOW fall out. A size cap (FIFO, oldest inserted
  # first) is the backstop for the one direction ticks can't bound: the
  # log tailing while no packets arrive — activity decides how much is in
  # flight, the cap decides what that can cost in memory.
  TICK_WINDOW = 600
  MAX_BUFFER_ENTRIES = 4096
  # Ticks scanned around an exact match when it misses (the closure tick
  # can lag the processing tick — tools/validate_actions.rb scans ±2 too).
  TICK_TOLERANCE = 2
  # Seconds between summary lines (and the rate limit on mismatch spam:
  # one detail line per distinct (wire, log) pair until the next summary).
  REPORT_INTERVAL = 300.0

  def initialize(host)
    @host = host
    @mutex = Mutex.new
    @log = Hash.new { |h, k| h[k] = [] }  # tick => [[player1idx, log_name], ...]
    @wire = Hash.new { |h, k| h[k] = [] }  # tick => [[player1idx, wire_type], ...]
    @votes = Hash.new { |h, k| h[k] = Hash.new(0) } # wire id => log name => n
    @stats = Hash.new(0)
    @reported = {}       # "wire|logname" => true, until the next summary
    @last_report = 0.0   # first summary prints as soon as there is something to say
    @unattributed_enabled = true
    @unattributed_samples = { wire: [], log: [] }
  end

  # Register the final cumulative report. Called by the sniffer at startup
  # (once, on the live instance — not per-test-instance).
  def register_exit_handler
    at_exit { report }
  end

  attr_reader :stats, :votes

  # Reached by the host's single log-tailer thread (emit(:on_log_line)),
  # not by its own LogTail — one reader on the inode feeds every consumer.
  # Plugin lifecycle: called when the plugin bus emits :on_start. Registers
  # the exit handler for the final cumulative report.
  def on_start
    register_exit_handler if @host
  end

  def on_log_line(line)
    record_log_line(line)
  end

  # One tailed log line → [player1idx, log_name] on its tick. The log's
  # player index is 1-based (same convention as the decoded game_player).
  def record_log_line(line)
    m = line.match(LOG_RE)
    return unless m
    @mutex.synchronize do
      @log[m[1].to_i] << [m[2].to_i, m[3]]
      evict(@log, m[1].to_i)
    end
  end

  # THE EVENT (the sniffer emits it per C→S tick closure): correlate this
  # tick's decoded actions against the log. Runs on the capture thread —
  # work here must stay cheap, the buffers hold ticks and the join is a
  # hash lookup.
  def on_input_actions(tick, actions)
    wire = actions&.reject { |a| a[:type].zero? } # 'nothing' padding is never logged
    return if !tick || wire.nil? || wire.empty?
    @mutex.synchronize do
      @wire[tick] = wire.map { |a| [a[:game_player], a[:type]] }
      evict(@wire, tick)
      correlate(tick)
      maybe_report
    end
  end

  # ── Correlation ──────────────────────────────────────────────────

  # Join one wire tick against the log: exact tick first, then the small
  # lag window (the log can lag 0-2 ticks behind the wire — tools/validate
  # actions.rb scans ±2 too). Consumes the matched log tick so the NEXT wire
  # tick cannot re-correlate stale entries (without this, tick+0 log entries
  # found at offset +1 get re-matched by tick+1, causing false seq_len
  # mismatches and cross-type MISMATCH reports).
  def correlate(tick)
    log_tick = (0..TICK_TOLERANCE).find { |o| @log.key?(tick + o) && !@log[tick + o].empty? }
    # A wire tick with no log lines yet is the normal idle case (logging
    # off, or pure movement the log's absence also covers) — not an error.
    return unless log_tick
    actual_log_tick = tick + log_tick
    lseqs = @log.delete(actual_log_tick)
    wseqs = @wire.delete(tick)
    # The log's player index is 0-based on stable 2.1.23 (wire game_player 3
    # logs as 2); the 2.0-era log was 1-based. Scan the offset like
    # tools/validate_actions.rb and prefer whichever joins.
    joined = nil
    [1, 0].each do |player_off|
      lplayers = lseqs.group_by { |(lp, _)| lp + player_off }
      next if (lplayers.keys & wseqs.group_by(&:first).keys).empty?
      joined = [lplayers, player_off]
      break
    end
    return unless joined
    lplayers, player_off = joined
    lplayers.each do |player, entries|
      lseq = entries.map(&:last)
      wseq = wseqs.select { |(p, _t)| p == player }.map(&:last)
      next if wseq.empty? # log-only player (remote, not on this client's C→S)
      if lseq.size != wseq.size
        # Sequence lengths differ: the log and the wire disagree on how
        # many actions this player performed this tick — a lost or
        # invented action on OUR side (usually a wrong length before it).
        @stats[:seq_len_mismatch] += 1
        if @stats[:seq_len_mismatch] <= 5
          offset_note = log_tick == 0 ? '' : " (log at tick #{actual_log_tick}, offset +#{log_tick})"
        puts "[action-validate] tick #{tick} player #{player}: #{wseq.size} wire actions but #{lseq.size} log actions (#{lseq.join(',')}) — a length before this likely desynced#{offset_note}"
        end
        next
      end
      wseq.zip(lseq).each { |wt, lname| record_pair(tick, player, wt, lname, log_tick, actual_log_tick) }
    end
    # This wire tick is done: the log entries it consumed (and any older
    # stragglers — a future closure can only need log ticks >= this one)
    # are dead. Clear them instead of waiting for the FIFO cap.
    # The wire tick is fully consumed (wseqs deleted above); evict older log
    # ticks that no future wire tick will reach (log_tick is within
    # TICK_TOLERANCE of the wire tick, so anything <= tick is unreachable).
    @log.keys.each { |t| @log.delete(t) if t < tick - TICK_TOLERANCE }
  end

  # Report only wire-side unattributed entries (wire actions that never found
  # a matching log line — potential tick misread or unlogged action).
  # Log-side unattributed entries are noise in client mode (remote players'
  # log lines have no matching C→S wire actions).
  def log_unattributed(buf, tick)
    return unless @unattributed_enabled
    return unless buf.equal?(@wire)
    entries = buf[tick]
    return unless entries && !entries.empty?
    @stats[:unattributed] += entries.size
    @unattributed_samples[:wire] << [tick, entries.size]
  end

  def record_pair(tick, player, wire_type, log_name, log_tick = 0, actual_log_tick = nil)
    @votes[wire_type][log_name] += 1
    wire_name = FactorioProtocol.action_name(wire_type)
    offset_note = log_tick == 0 ? '' : " (log at tick #{actual_log_tick}, offset +#{log_tick})"
    if wire_name.start_with?('Unknown')
      @stats[:not_in_table] += 1
    elsif normalize(wire_name) == normalize(log_name)
      @stats[:ok] += 1
    else
      @stats[:mismatch] += 1
      key = "#{wire_type}|#{log_name}"
      unless @reported[key]
        @reported[key] = true
        puts "[action-validate] MISMATCH tick #{tick} player #{player}: wire #{wire_type}=#{wire_name} but log says #{log_name}#{offset_note}"
      end
    end
  end

  # Periodic summary on the packet thread's cadence: counts, plus the
  # wire IDs whose winning log name disagrees with the action table —
  # the candidate corrections this feature exists to surface.
  # Called from on_input_actions (rate-limited) and at_exit (final report).
  def maybe_report
    now = Process.clock_gettime(Process::CLOCK_MONOTONIC)
    # Rate-limited: first summary prints immediately, then every interval.
    # The at_exit report bypasses the rate limit — called directly as `report`.
    return if @last_report.nonzero? && now - @last_report < REPORT_INTERVAL
    first = @last_report.zero?
    @last_report = now
    @reported.clear unless first # the first summary does not re-open the detail lines
    report_summary
  end

  def report
    return unless @stats.values.any? || @votes.any?
    report_summary
  end
                def report
    return unless @stats.values.any? || @votes.any?
    report_summary
  end

  def report_summary
    return unless @stats.values.any? || @votes.any?
    s = @stats
    puts format('[action-validate] %<ok>d OK, %<mis>d mismatched, %<nit>d not-in-table, ' \
                '%<seq>d sequence-length mismatches, %<un>d unattributed ticks ' \
                '(actions correlated so far)',
                ok: s[:ok], mis: s[:mismatch], nit: s[:not_in_table], seq: s[:seq_len_mismatch], un: s[:unattributed])
    # Show a few unattributed wire-tick samples to point at the gap.
    samples = @unattributed_samples[:wire]
    if samples.any?
      samples.sort_by! { |tick, _| tick }
      tick, count = samples.first
      puts "  sample: wire tick #{tick}: #{count} wire actions with no log line"
    end
    disagreements = @votes.reject { |id, names| names.any? { |name, _| normalize(name) == normalize(table_name(id)) } }
    disagreements.sort.each do |id, names|
      winner, n = names.max_by { |_, c| c }
      puts format('  candidate: wire %<id>d table=%<tn>s but log says %<wn>s (x%<n>d)',
                  id: id, tn: table_name(id) || '(absent)', wn: winner, n: n)
    end
  end

  # Wire id → table name, or nil. Read through the SELECTED tables, so
  # the summary speaks the version the session decodes with.
  def table_name(id) = FactorioProtocol.actions.dig(id, 0)

  # ── Buffers ──────────────────────────────────────────────────────

  # Tick-window eviction (primary): drop every tick older than the newest
  # seen by more than TICK_WINDOW. Then the FIFO cap (backstop, oldest
  # inserted first — hashes keep insertion order and both streams arrive
  # roughly in order). Called on every insert.
  def evict(buf, tick)
    @newest_tick = tick if tick > (@newest_tick ||= tick)
    floor = @newest_tick - TICK_WINDOW
    buf.keys.each do |t|
      if t < floor
        log_unattributed(buf, t) # before delete — reports unmatched entries
        buf.delete(t)
      end
    end
    cap(buf)
  end

  def cap(buf)
    while buf.values.sum(&:size) > MAX_BUFFER_ENTRIES
      t = buf.keys.first
      log_unattributed(buf, t)
      buf.delete(t)
    end
  end

  # CamelCase (log) vs snake_case (table) — compare normalized. Same
  # shape as tools/validate_actions.rb#normalize.
  def normalize(name)
    # Normalize: PascalCase → snake_case, so "StopWalking" matches "stop_walking"
    # (the /toggle-action-logging names use a different casing convention).
    name.to_s.gsub(/([a-z0-9])([A-Z])/, '\1_\2').downcase
  end
end
