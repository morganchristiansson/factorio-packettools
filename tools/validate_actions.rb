#!/usr/bin/env ruby
# frozen_string_literal: true

# Validate input-action wire IDs by correlating `/toggle-action-logging`
# output with a packet capture, offline (self-contained).
#
# The game logs one line per action (names only, no IDs):
#   Action performed [7544253 36 StartWalking]
# i.e. [<game_tick> <player> <ActionName>]. Heartbeat tick closures carry
# the SAME game tick with the wire action IDs, in processing order — so
# joining on (tick, player, position) pairs each name with its ID.
#
# The capture's tick closures and the log's action lines are both
# tick-ordered streams, so the replay merges them sequentially: the log is
# streamed from the top with pre-capture history skipped (the capture is a
# subset of the log; ticks are monotonic), then each wire tick pulls the
# log lines whose tick has now arrived (≤ tick + tolerance — the validator
# scans the lag window) before feeding the validator. O(1) memory — not
# even a lookahead beyond one line, no threads (both inputs are files, the
# merge is paced by the capture replay).
#
# Usage:
#   ruby tools/validate_actions.rb --pcap server-40220-20261026-085202.pcap.gz
#   ruby tools/validate_actions.rb --pcap captures/*.pcap --suggest
#
# Options:
#   --pcap FILE        stream-replay an existing capture against the log
#   --log FILE         default ~/factorio/factorio-current.log
#   --suggest          print a corrected Ruby 2.1 table for pasting
require 'optparse'
require_relative '../lib/pcap'
require_relative '../lib/factorio_protocol'
require_relative '../lib/action_validator'

options = { log: File.expand_path('~/factorio/factorio-current.log'), suggest: false }
OptionParser.new do |opts|
  opts.banner = 'Usage: validate_actions.rb --pcap FILE [--suggest]'
  opts.on('--pcap FILE', 'Stream-replay an existing packet capture against the log') { |v| options[:pcap] = v }
  opts.on('--log FILE', "Factorio log (default: ~/factorio/factorio-current.log)") { |v| options[:log] = v }
  opts.on('--suggest', 'Print a corrected Ruby 2.1 table for pasting') { |v| options[:suggest] = true }
end.parse!
abort 'Give --pcap FILE' unless options[:pcap]

def capture_min_tick(path)
  first = nil
  PcapReader.new(path).each_packet do |_pkt, _ts, _src, _dst, _sp, _dp, udp_data, _raw|
    next unless FactorioProtocol.heartbeat_payload?(udp_data)
    parsed = FactorioProtocol.parse_udp_payload(udp_data)
    hb = parsed&.[](:heartbeat)
    next unless hb
    (hb[:tick_closures] || []).each do |tc|
      if tc && tc[:tick]
        first = tc[:tick]
        break
      end
    end
    break if first
  end
  first
end

def decode_closures(udp_data)
  return unless FactorioProtocol.heartbeat_payload?(udp_data)
  parsed = FactorioProtocol.parse_udp_payload(udp_data)
  return unless parsed
  hb = parsed[:heartbeat]
  hb && hb[:tick_closures]
end

# Log names are CamelCase, the action table snake_case — compare
# normalized (same shape as ActionValidator#normalize).
def normalize(name)
  name.to_s.gsub(/([a-z0-9])([A-Z])/, '\1_\2').downcase
end

# One tick closure → the validator. A tick's closures arrive across
# multiple packets (one per client), and S→C echoes repeat one already
# seen — so dedupe an exact repeat and append a genuinely new fragment.
def feed_tick(validator, fed, tick, actions)
  sig = (actions || []).map { |a| [a[:game_player], a[:type]] }
  return if sig.empty?
  prev = fed[tick]
  if prev.nil?
    fed[tick] = sig
    validator.on_input_actions(tick, actions)
  elsif prev == sig
    # S→C echo of a closure already fed — one copy goes to the join.
  else
    fed[tick] = prev + sig
    validator.on_input_actions(tick, actions, append: true)
  end
  fed.shift if fed.size > 4096 # ticks arrive in order — keep the recent window
end

# End-of-run report from the validator's completed votes: confirmed wire
# IDs (OK / MISMATCH / NOT-IN-TABLE), IDs correlated but absent from the
# table, and the optional --suggest table.
def report_wire_ids(votes, table, options)
  known = table.each_with_object({}) { |(id, (name, _)), h| h[id] = name }
  best_name = {}
  votes.each do |wire, names|
    name, n = names.max_by { |_, c| c }
    best_name[wire] = [name, n]
  end

  puts "\n== Confirmed wire IDs (#{best_name.size}) =="
  best_name.sort.each do |wire, (name, n)|
    tname = known[wire]
    flag = if tname && normalize(tname) == normalize(name)
             'OK'
           elsif tname
             "MISMATCH — table says #{tname}"
           else
             'NOT IN TABLE'
           end
    puts format('  %3d (0x%02x) %-32s x%-4d %s', wire, wire, name, n, flag)
  end

  cap_ids = votes.keys
  missing = (cap_ids - known.keys).sort
  puts "\n== Wire IDs correlated, not in table (#{missing.size}) =="
  puts '  ' + missing.map { |w| format('%d(0x%02x)', w, w) }.join(' ') unless missing.empty?

  never = (known.keys - cap_ids).sort
  puts "\n== Table entries never correlated from this capture (#{never.size}) =="
  puts '  (this run never joined them to a log line — unexercised here, not necessarily wrong)'

  return unless options[:suggest]
  suggest = {}
  known.each { |id, name| suggest[id] = name unless best_name[id] }
  best_name.each { |id, (name, _)| suggest[id] = name }
  puts "\n== Suggested table (confirmed overrides) =="
  suggest.sort.each { |id, name| puts "  #{id} => [#{name.inspect}, #{table[id]&.last.inspect}]," }
end

# ── Replay: single-threaded paced merge of capture + log ───────────
table = FactorioProtocol::ACTIONS_21 # 2.1 stable is the only released version
min_tick = capture_min_tick(options[:pcap])
abort 'capture has no tick closures to correlate against' unless min_tick

validator = ActionValidator.new(nil)
fed = {} # closure tick => signatures already fed (S→C echoes are duplicates)
n_pkts = n_ticks = n_wire_actions = n_log_lines = 0

# Stream the log from the top, skipping pre-capture history inline
# (action lines with tick < the capture's first tick). One sequential
# pass, O(1) memory, one line of lookahead — enough for the validator's
# 0..+2 lag scan.
puts "log: streaming #{options[:log]} from tick #{min_tick} (pre-capture lines skipped)"
log_file = File.open(options[:log])
read_next_log_entry = lambda do
  return nil if log_file.closed?
  while (line = log_file.gets)
    m = line.match(ActionValidator::LOG_RE)
    next unless m
    next if m[1].to_i < min_tick # history before the capture's first tick
    return [m[1].to_i, m[2].to_i, m[3]]
  end
  nil
end
log_next = read_next_log_entry.call

PcapReader.new(options[:pcap]).each_packet do |_pkt, _ts, _src, _dst, _sp, _dp, udp_data, _raw|
  n_pkts += 1
  next unless (closures = decode_closures(udp_data))
  closures.each do |tc|
    tick = tc[:tick]
    next unless tick
    # Pull everything the wire has now caught up to: lines at tick ≤ T
    # join T exactly; the +tolerance covers the lag the validator scans.
    while log_next && log_next[0] <= tick + ActionValidator::TICK_TOLERANCE
      validator.record_log_line("Action performed [#{log_next.join(' ')}]")
      n_log_lines += 1
      log_next = read_next_log_entry.call
    end
    n_ticks += 1
    n_wire_actions += (tc[:actions] || []).size
    feed_tick(validator, fed, tick, tc[:actions])
  end
end
log_file.close unless log_file.closed?
validator.finish_accounting

puts "pcap: #{n_pkts} packets, #{n_ticks} ticks, #{n_wire_actions} actions"
puts "log:  #{n_log_lines} action lines admitted alongside the capture"
validator.report # sequence-length / unattributed / candidate summary
report_wire_ids(validator.votes, table, options)