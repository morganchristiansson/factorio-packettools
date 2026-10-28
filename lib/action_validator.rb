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
  LOG_LINE_RE = /Action performed \[(?<tick>\d+) (?<player>\d+) (?<name>\w+)\]/.freeze

  # Eviction is by GAME TICK, not wall time: the join is tick-based, so
  # age is measured in ticks. Entries older than the newest seen tick by
  # more than TICK_WINDOW fall out. A size cap (FIFO, oldest inserted
  # first) is the backstop for the one direction ticks can't bound: the
  # log tailing while no packets arrive — activity decides how much is in
  # flight, the cap decides what that can cost in memory.
  TICK_WINDOW = 600
  MAX_BUFFER_ENTRIES = 4096
  # Larger cap for -r replay: the log tailer outruns the capture replay
  # (~5x), so we need a bigger buffer to retain entries until @consume_tick
  # is set and the tick-window eviction takes over. ~50MB for 400K entries.
  REPLAY_PRELOAD_CAP = 400_000
  # Ticks scanned around an exact match when it misses (the closure tick
  # can lag the processing tick — tools/validate_actions.rb scans ±2 too).
  TICK_TOLERANCE = 2
  # How far BELOW the newest wire tick a log line is kept before it is
  # declared dead. Client mode receives our own C→S packet a few ticks
  # before the server's S→C broadcasts for the intervening ticks, so ticks
  # arrive slightly out of order; evicting at tick - TICK_TOLERANCE threw
  # away log lines for the lower ticks that were still about to be fed and
  # made them pair with the next tick (+2) instead (client-20261028-104957
  # tick 24860861..864: 266/stop_walking/cleared mismatches). One second
  # (64 ticks) covers network reordering and still bounds the buffer.
  REORDER_WINDOW = 64
  # Seconds between summary lines (and the rate limit on mismatch spam:
  # one detail line per distinct (wire, log) pair until the next summary).
  REPORT_INTERVAL = 300.0
  # Action logging is per-process and off after a restart. With it off the
  # wire side alone fills the correlation buffers and can never join. After
  # this much activity with no `Action performed` line at all, report it
  # once, release the buffers and stop buffering until a log line proves the
  # operator turned it back on.
  LOGGING_OFF_ACTIONS = 100
  LOGGING_OFF_SECONDS = 30.0

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
    @join_memo = {}      # "tick:player" => joined once — packets can FEED the same closure again
    @unknown_seen = Hash.new(0) # wire id => occurrences, table has no name
    # nil = not proven either way yet, true = a log line has arrived,
    # false = enough wire activity with no log lines (buffering paused).
    @logging_on = nil
    @logging_off_reported = false
    @first_wire_at = nil
    @last_log_at = nil
    @wire_actions_since_log = 0
    @stale_log_reported = false
  end

  # Register the final cumulative report. Called by the sniffer at startup
  # (once, on the live instance — not per-test-instance).
  def register_exit_handler
    at_exit { report }
  end

  attr_reader :stats, :votes

  # Override the FIFO backstop size (entries). The streaming validator
  # sets a generous one because ITS pace — the capture replay, guarded by
  # the log reader's pacing — is what bounds memory, not the cap.
  attr_writer :buf_cap

  # The capture side's current replay position: the tick correlate is
  # processing (set at the head of every correlate call, matched or not),
  # or nil before the capture has produced its first action-bearing tick
  # closure. Paced log readers wait while they run ahead of this.
  def consume_tick
    @mutex.synchronize { @consume_tick }
  end

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
    tick = m[1].to_i
    @mutex.synchronize do
      note_log_line_for_state
      # A live tail can read from the top when the log is replaced/rotated;
      # that history is already older than the capture's correlation window
      # and can never join. Skip it instead of counting it as a misdecode
      # (offline validation skips pre-capture history the same way).
      if @consume_tick && tick < @consume_tick - TICK_WINDOW
        @stats[:log_stale] += 1
        unless @stale_log_reported
          @stale_log_reported = true
          puts "[action-validate] skipping stale log history (tick #{tick} < capture tick " \
               "#{@consume_tick - TICK_WINDOW}) — the tail is behind; correlation resumes when it catches up"
        end
        return
      end
      counts = (@buf_counts ||= {})
      id = @log.object_id
      counts[id] = (counts[id] || 0) + 1
      log_buf = @log
      log_buf[tick] << [m[2].to_i, m[3]]
      @newest_tick = tick if tick > (@newest_tick ||= tick)
      # Only evict by tick window when the capture replay has started
      # (@consume_tick is set in correlate). Before that, the log tailer
      # outruns the capture by ~40x — evicting by @newest_tick would
      # delete entries the capture hasn't reached yet. The cap below
      # bounds the buffer until @consume_tick takes over.
      ref = @consume_tick || @newest_tick
      floor = ref - TICK_WINDOW
      while (old_t = log_buf.keys.first) && old_t < floor
        drop_log_unmatched(old_t, log_buf[old_t].size)
        counts[id] -= log_buf[old_t].size
        log_buf.delete(old_t)
      end
      # Cap backstop: same-tick floods only (a misdecode can pile thousands
      # of uncorrelated log lines onto one tick — see drop_log_unmatched).
      # Tick-window eviction above (driven by @consume_tick in correlate)
      # bounds normal operation. Larger limit for -r replay: the log tailer
      # reads ahead of the capture, so the buffer temporarily holds more.
      # buf_cap= overrides for a self-paced caller (the streaming validator
      # bounds memory through pacing, not the cap).
      cap_limit = @buf_cap ||
                  ((@host.respond_to?(:options) && @host.options[:pcap]) ? REPLAY_PRELOAD_CAP : MAX_BUFFER_ENTRIES)
      while counts[id] > cap_limit
        old_t = log_buf.keys.first
        drop_log_unmatched(old_t, log_buf[old_t].size)
        counts[id] -= log_buf[old_t].size
        log_buf.delete(old_t)
      end
    end
  end

  # THE EVENT (the sniffer emits it per C→S tick closure): correlate this
  # tick's decoded actions against the log. Runs on the capture thread —
  # work here must stay cheap, the buffers hold ticks and the join is a
  # hash lookup.
  #
  # append: a replayed capture can split one tick's closures across
  # packets (and echo them from S→C). The caller deduplicates identical
  # repeats; a genuinely different later fragment APPENDS to what this
  # tick already holds, like the offline join's accumulation.
  # The sniffer's append event: the same tick arrived from the other
  # direction with a different fragment (client mode feeds C→S + S→C).
  def on_input_actions_append(tick, actions)
    on_input_actions(tick, actions, append: true)
  end

  def on_input_actions(tick, actions, append: false)
    wire = actions&.reject { |a| a[:type].zero? } # 'nothing' padding is never logged
    return if !tick || wire.nil? || wire.empty?
    @mutex.synchronize do
      note_wire_actions_for_state(wire.size)
      return if @logging_on == false # no log lines to join — don't buffer
      wire.each { |a| @unknown_seen[a[:type]] += 1 if a[:name].to_s.start_with?('Unknown') }
      entries = wire.map { |a| [a[:game_player], a[:type]] }
      entries = @wire[tick].to_a + entries if append && @wire[tick]
      @buf_counts ||= {}
      @buf_counts[@wire.object_id] = (@buf_counts[@wire.object_id] || 0) + entries.size
      @wire[tick] = entries
      evict(@wire, tick, tick)        # wire floor is capture's current tick, not log tailer's
      correlate(tick)
      maybe_report
    end
  end

  # ── Action-logging state ─────────────────────────────────────────

  # Called under @mutex for every `Action performed` line. The first line
  # proves logging is on; a line after an OFF report means the operator just
  # enabled it, so resume buffering/correlation.
  def note_log_line_for_state
    now = Process.clock_gettime(Process::CLOCK_MONOTONIC)
    @last_log_at = now
    @first_wire_at = nil
    @wire_actions_since_log = 0
    @logging_on = true
    return unless @logging_off_reported
    @logging_off_reported = false
    puts '[action-validate] action logging detected — resuming correlation'
  end

  # Called under @mutex for each wire tick. No log line despite sustained
  # action traffic means /toggle-action-logging is off (it does not persist
  # across restarts). Report once and release the buffers; #note_log_line_for_state
  # turns it back on if the operator enables it during the run.
  def note_wire_actions_for_state(count)
    return if @logging_on == false
    now = Process.clock_gettime(Process::CLOCK_MONOTONIC)
    @first_wire_at ||= now
    @wire_actions_since_log += count
    return if @wire_actions_since_log < LOGGING_OFF_ACTIONS
    return if now - (@last_log_at || @first_wire_at) < LOGGING_OFF_SECONDS

    @logging_on = false
    @logging_off_reported = true
    @wire.clear
    @log.clear
    @buf_counts = {}
    @join_memo.clear
    puts format('[action-validate] no Action performed log lines after %<n>d actions — ' \
                '/toggle-action-logging appears OFF. Enable it on the server (RCON) to ' \
                'validate actions; correlation buffering paused.',
                n: @wire_actions_since_log)
  end

  # ── Correlation ──────────────────────────────────────────────────

  # Join one wire tick against the log: exact tick first, then the small
  # lag window (the log can lag or lead small amounts — the offline tool
  # scans ±2; mirror that, scored per tick). Consumes ONLY the pairs that
  # joined: a tick's closures arrive across MULTIPLE packets (one per
  # client, each carrying its own player's inputs), so the log bucket and
  # the wire tick must stay alive until every player that will ever join
  # it has joined — deleting the whole bucket on the first feed starved
  # every later feed of its player's lines.
  #
  # Ambiguity rule: when the best candidate (tick offset, player offset)
  # is NOT strictly better than the runner-up, the join is DEFERRED — the
  # entries stay in both buffers. This is the action-logged-later case:
  # the wire tick has no log line of its own (bucket empty), so a future
  # line at +1 and the true line at +2 tie on lengths alone; joining at
  # +1 would steal the wrong line and cascade (measured on the full
  # S→C capture: whole runs of zoom/walk swaps). Deferred ticks are
  # retried by later correlates (below): by then the conflicting garbage
  # was consumed by its own feed, the true pairing is the only candidate
  # left, and the join is unambiguous.
  def correlate(tick)
    @consume_tick = tick
    attempt_join(tick)
    # Retry leftovers: older wire ticks deferred by the ambiguity rule
    # (or whose log line simply had not been admitted yet). They join here
    # only when the choice is now unambiguous.
    @wire.keys.select { |t| t < tick }.each { |t| attempt_join(t) }
    # Older log ticks no future wire tick will reach (a candidate offset is
    # within TICK_TOLERANCE of its wire tick) are dead — CORRELATED entries
    # were already consumed by attempt_join, so anything still here is an
    # uncorrelated misdecode remainder (see drop_log_unmatched), which is
    # counted, not silently dropped. O(1) amortized from the front.
    floor = tick - REORDER_WINDOW
    while (t = @log.keys.first) && t < floor
      drop_log_unmatched(t, @log[t].size)
      @log.delete(t)
    end
  end

  # One join attempt for one wire tick. Returns when consumed (or nothing
  # matched); leaves everything in place when deferred.
  def attempt_join(tick)
    return unless @wire.key?(tick) # plain-hash read: no default-proc pollution
    wseqs = @wire[tick]
    return if wseqs.empty?
    wplayers = wseqs.group_by(&:first)
    # Score each (tick lag, player offset) combination. Per common player:
    #   sizes equal        -> all positions pair (the bulk case; the name
    #                         agreement is measured but never gates pairing,
    #                         so a wrong table name still gets REPORTED)
    #   sizes differ       -> the wire missed (or invented) an action — a
    #                         known decode defect — so only the name-AGREEING
    #                         prefix pairs from the left, the excess stays on
    #                         its own side
    # Candidates rank by name agreement FIRST, then paired count, then the
    # smaller offsets: name agreement is the structural truth signal (the
    # action-logged-later case has its true pair right there at offset 0
    # with an agreeing extra line, while the accidental +1 sibling pair
    # disagrees). The votes themselves (record_pair) stay name-agnostic —
    # whatever actually pairs gets voted and reported, never filtered.
    scored = []
    (0..TICK_TOLERANCE).each do |o|
      next unless @log.key?(tick + o) # plain-hash reads: no default-proc pollution
      bucket = @log[tick + o]
      next if bucket.empty?
      (0..1).each do |player_off|
        lplayers = bucket.group_by { |(lp, _)| lp + player_off }
        common = lplayers.keys & wplayers.keys
        next if common.empty?
        plan = {} # player => [pairs] (the [wire_type, log_name] zips to join)
        agrees = 0
        pairs_total = 0
        common.each do |player|
          entries = lplayers[player]
          lseq = entries.map(&:last)
          wseq = wplayers[player].map(&:last)
          if lseq.size == wseq.size
            zipped = wseq.zip(lseq)
            plan[player] = [zipped, entries]
            pairs_total += zipped.size
            agrees += zipped.count { |(wt, ln)| name_matches?(wt, ln) }
          else
            zipped = wseq.zip(lseq).take_while { |(wt, ln)| name_matches?(wt, ln) }
            next if zipped.empty? # no agreeing prefix, no pairs from here
            plan[player] = [zipped, entries]
            pairs_total += zipped.size
            agrees += zipped.size
          end
        end
        next if plan.empty?
        scored << [o, player_off, plan, agrees, pairs_total]
      end
    end
    return unless scored.any?
    scored.sort_by! { |(_o, _po, _plan, agrees, pairs_total)| [-agrees, -pairs_total, _o, _po] }
    o, player_off, plan, agrees, pairs_total = scored.first
    if scored.size > 1
      o2, _, _, agrees2, pairs2 = scored[1]
      # An EXACT-tick candidate is never ambiguous against a lagged one: the
      # log line at the wire tick is the authoritative pairing. Deferring on
      # a 0-vs+1 agreement tie let the exact tick stay buffered while the +1
      # sibling joined first, cascading into whole runs of 266/cleared/zoom
      # mismatches (client-20261028-104957 tick 24855904). Keep deferring
      # when the best is itself a lag candidate (the action-logged-later
      # case this rule exists for).
      return if o.positive? && o2.positive? && agrees == agrees2 && pairs_total == pairs2
    end
    actual_log_tick = tick + o

    # Pair what joins, consume positionally from both buffers, keep the rest.
    matched_counts = {} # player => pairs joined
    plan.each do |player, (zipped, entries)|
      key = "#{tick}:#{player}"
      next if @join_memo[key] # fed again by another packet with the same closure
      @join_memo[key] = true
      @join_memo.shift if @join_memo.size > 4096
      if entries.size != zipped.size
        # Log had extra lines beyond the agreeing prefix (the wire missed
        # an action — or the wire invented one): a lost/invented action on
        # OUR side, usually a wrong length before it.
        @stats[:seq_len_mismatch] += 1
        if @stats[:seq_len_mismatch] <= 5
          offset_note = o.zero? ? '' : " (log at tick #{actual_log_tick}, offset +#{o})"
          puts "[action-validate] tick #{tick} player #{player}: #{zipped.size} wire actions but #{entries.size} log actions (#{entries.map(&:last).join(',')}) — a length before this likely desynced#{offset_note}"
        end
      end
      zipped.each { |(wt, lname)| record_pair(tick, player, wt, lname, o, actual_log_tick) }
      matched_counts[player] = zipped.size
    end
    return if matched_counts.empty?

    # Positional consumption: drop each joined player's FIRST n entries from
    # both buffers (group_by preserved order, so positional identity holds).
    # Unjoined log-only / wire-only entries stay for the feeds to come.
    taken = Hash.new(0)
    kept_l = []
    (@log[actual_log_tick] || []).each do |lentry|
      ident_w = lentry[0] + player_off
      if matched_counts.key?(ident_w) && taken[ident_w] < matched_counts[ident_w]
        taken[ident_w] += 1
      else
        kept_l << lentry
      end
    end
    if kept_l.empty?
      @log.delete(actual_log_tick)
    else
      @log[actual_log_tick] = kept_l
    end

    taken_w = Hash.new(0)
    kept_w = []
    removed_w = 0
    wseqs.each do |wentry|
      p = wentry[0]
      if matched_counts.key?(p) && taken_w[p] < matched_counts[p]
        taken_w[p] += 1
        removed_w += 1
      else
        kept_w << wentry
      end
    end
    @buf_counts ||= {}
    @buf_counts[@wire.object_id] = (@buf_counts[@wire.object_id] || 0) - removed_w
    if kept_w.empty?
      @wire.delete(tick)
    else
      @wire[tick] = kept_w
    end
  end

  # Wire type name vs log name under the case-normalizing comparison.
  def name_matches?(wire_type, log_name)
    n = FactorioProtocol.action_name(wire_type)
    return false unless n
    normalize(n) == normalize(log_name)
  end

  # Correlated entries are eaten by attempt_join the moment they join, so a
  # bucket that survives to be EVICTED here was never matched — a misdecode
  # (a wrong length earlier desynced this tick's decode, so its log lines
  # never found a wire action). Count them into the cumulative report as
  # log-side unmatched instead of silently forgetting them, so the buffers
  # self-empty and report tracks every orphan. This is the live tail's ONLY
  # reason to matter: it empties itself, growing only on misdecodes.
  def drop_log_unmatched(tick, count)
    @stats[:log_unmatched] += count
    (@unattributed_samples[:log] << [tick, count]) if @unattributed_samples[:log].size < 100
  end

  # Report only wire-side unattributed entries (wire actions that never found
  # a matching log line — potential tick misread or unlogged action).
  # Log-side unmatched entries ride the @stats[:log_unmatched] counter via
  # drop_log_unmatched (they are not listened into @log).
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

  # End-of-stream accounting (the streaming validator calls it once after
  # the last on_input_actions): whatever is still buffered never correlated
  # — their log lines / wire actions never found a partner before the
  # stream ended (or a misdecode orphaned them). Count them into the report
  # and release them; the standalone tool corrects afterwards.
  def finish_accounting
    @mutex.synchronize do
      @wire.each_key { |t| log_unattributed(@wire, t) }
      @log.keys.each { |t| drop_log_unmatched(t, @log[t].size) }
      @wire.clear
      @log.clear
    end
  end

  def report_summary
    return unless @stats.values.any? || @votes.any?
    s = @stats
    puts format('[action-validate] %<ok>d OK, %<mis>d mismatched, %<nit>d not-in-table, ' \
                '%<seq>d sequence-length mismatches, %<un>d unattributed, %<lun>d log-unmatched ' \
                '(actions correlated so far)',
                ok: s[:ok], mis: s[:mismatch], nit: s[:not_in_table], seq: s[:seq_len_mismatch],
                un: s[:unattributed], lun: s[:log_unmatched])
    if s[:log_stale].positive?
      puts "  #{s[:log_stale]} stale log line(s) skipped (older than the capture window)"
    end
    # Show a few unattributed wire-tick samples to point at the gap.
    samples = @unattributed_samples[:wire]
    if samples.any?
      samples.sort_by! { |tick, _| tick }
      tick, count = samples.first
      puts "  sample: wire tick #{tick}: #{count} wire actions with no log line"
    end
    lsamples = @unattributed_samples[:log]
    if lsamples.any?
      lsamples.sort_by! { |tick, _| tick }
      tick, count = lsamples.first
      puts "  sample: log tick #{tick}: #{count} log actions that never correlated (misdecode)"
    end
    if @unknown_seen.any?
      puts '  unknown wire IDs seen: ' +
           @unknown_seen.sort.map { |id, n| "#{id}=#{n}" }.join(', ')
      unknown_votes = @unknown_seen.keys.select { |id| @votes.key?(id) && @votes[id].any? }
      unknown_votes.sort.each do |id|
        winner, n = @votes[id].max_by { |_, c| c }
        puts format('  candidate: wire %<id>d table=(absent) but log says %<wn>s (x%<n>d)',
                    id: id, wn: winner, n: n)
      end
      unmatched = @unknown_seen.keys - unknown_votes
      if unmatched.any?
        puts '  unknown wire IDs not yet matched to a log line: ' +
             unmatched.sort.map { |id| "#{id}=#{@unknown_seen[id]}" }.join(', ')
      end
    end
    disagreements = @votes.reject do |id, names|
      @unknown_seen.key?(id) || names.any? { |name, _| normalize(name) == normalize(table_name(id)) }
    end
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

  # Tick-window eviction: drop every tick older than the newest seen by
  # more than TICK_WINDOW. Live feeding is incremental (paced by the
  # game, never a bulk feed), so the tick window alone bounds the buffer
  # — no size cap. Oldest-first, O(1) amortized: hashes keep insertion
  # order, so keys.first is the oldest and we stop at the first key above
  # the floor. Wire ticks dropped here also count as unattributed.
  def evict(buf, tick, ref = nil, cap_limit = MAX_BUFFER_ENTRIES)
    @newest_tick = tick if tick > (@newest_tick ||= tick)
    ref ||= @consume_tick || @newest_tick
    floor = ref - TICK_WINDOW
    # O(1) fast-path: Ruby hashes keep insertion order, so keys.first is
    # the oldest. If it's >= floor and the per-buffer entry count is within
    # bounds, skip the O(n) scan entirely — keeps record_log_line O(n) total.
    counts = (@buf_counts ||= {})
    key = buf.object_id
    oldest = buf.keys.first
    if oldest && oldest >= floor && (counts[key] || 0) <= cap_limit
      return
    end
    # Ruby hashes are insertion-ordered, so keys.first is the oldest.
    # Only delete from the front — stop as soon as a key is above the floor.
    # This is O(k) for k entries below floor, not O(n) for all entries.
    while (t = buf.keys.first) && t < floor
      counts[key] = (counts[key] || 0) - buf[t].size
      log_unattributed(buf, t)
      buf.delete(t)
    end
    cap(buf, counts, key, cap_limit)
  end

  def cap(buf, counts, key, limit = MAX_BUFFER_ENTRIES)
    while (counts[key] || 0) > limit
      t = buf.keys.first
      counts[key] -= buf[t].size
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
