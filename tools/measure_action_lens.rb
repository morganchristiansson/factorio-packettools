#!/usr/bin/env ruby
# frozen_string_literal: true

# Measure and audit the 2.1 client→server input-action payload lengths.
#
# Every C→S heartbeat ends with an 8-byte [tick(4)][pad(4)] block, so a tick
# closure's action bytes end at a known offset: with every action's length known
# but one, that one is arithmetic (ActionLenSolver). This tool drives that over a
# capture set — one pass, whatever the question.
#
#   ruby tools/measure_action_lens.rb PCAP...          what is still undecoded,
#                                                       worst offenders first
#   ruby tools/measure_action_lens.rb --decide PCAP... everything the wire
#                                                       settles that the table lacks
#   ruby tools/measure_action_lens.rb --type 88 ...    one or more types, with
#                                                       their candidate tallies
#                                                       (repeatable, ONE pass)
#   ruby tools/measure_action_lens.rb --check PCAP...  does the shipped table
#                                                       still agree with the wire
#                                                       (hides each type on a
#                                                       sample of closures that
#                                                       contain it)
#
# It does NOT write the table. Lengths are added deliberately, one type at a
# time, and --check guards them: an earlier version of this tool wrote the table
# from a walk that read every action header without skipping payloads, so in a
# two-action closure the second type came from inside the first action's data and
# the arithmetic was meaningless while looking fine. A tool that cannot defend
# its numbers should not be able to write them.
#
# --check skips table entries whose payload the PARSER computes rather than
# reading from the table (the ActionLengths overrides: echo bodies, structural
# reads) and 0 entries (the deliberate variable/trailer-only base). Hiding one
# of those measures bytes the parser never calls that action's payload.
#
# Accepts any pcap, gz included; only client→server heartbeats are read.
require 'json'
require 'optparse'
require_relative 'action_len_solver'
require_relative '../lib/factorio_protocol'

MIN_OBS = 5    # distinct closures that must agree
MARGIN = 3     # and this factor over the runner-up
opts = OptionParser.new do |o|
  o.on('--check', 'verify every fixed table length against the wire') { @check = true }
  o.on('--decide', 'list every type the wire decides but the table lacks') { @decide = true }
  o.on('--type N', Integer, 'measure one action type (repeatable)') { |v| (@types ||= []) << v }
  o.on('--json', 'machine-readable output') { @json = true }
end
opts.parse!
args = ARGV.reject { |a| a.start_with?('--') }
abort 'usage: measure_action_lens.rb [--check|--decide|--type N ...] [--json] PCAP...' if args.empty?

# The measured lengths live IN the action table now (input_actions_21.rb):
# `lens` here is the table's fixed lengths, and --check re-verifies them
# against the wire — the table IS the measured artifact.
lens = FactorioProtocol.actions.select { |_t, (_n, l)| !l.nil? }.transform_values { |(_n, l)| l }
name = ->(t) { FactorioProtocol.actions[t]&.first || '** UNIDENTIFIED **' }
CODE = ActionLenSolver::CODE_PARSED

# ── --check: does each shipped length survive its own hidden measurement? ──
# A table type is never a "hole" in an ordinary walk (the walk knows its
# length), so the old check, which only looked at decided hole types, could
# never disagree — it was vacuous. Sample closures containing each type and
# re-measure with the type hidden instead.
if @check
  bad, checked, undecided, seen = ActionLenSolver.check_table(
    args, lens, min_obs: MIN_OBS, margin: MARGIN, code_parsed: CODE
  )
  if bad.empty?
    puts "all #{checked} checked table lengths agree (#{undecided}/#{seen} types had no decisive sample)"
    exit 0
  end
  bad.sort_by { |_, d| -d[:votes] }.each do |t, d|
    puts "  #{t} #{name[t]}: table #{d[:claimed]}, wire says #{d[:got]} (#{d[:votes]} closures, runner-up #{d[:second]})"
  end
  exit 1
end

# ── One pass: what does the wire say about every type it can see? ───────
# The corpus tally asks the wire about every type the walk cannot cross; a
# --type query instead HIDES that type, so it becomes the hole — otherwise the
# walk steps over it and there is nothing to measure. Every requested type
# rides ONE pass (the parse is what was slow; repeating it per type was the
# 42s-per-type trap).
tally = if @types&.any?
          # A type that is NOT in the table is already "the first hole" wherever
          # it appears — filter one corpus pass. Only a type that IS in the
          # table has to be hidden (walk once per type), which is what auditing
          # a known length costs.
          unknown = @types.reject { |t| lens.key?(t) }
          known   = @types.select { |t| lens.key?(t) }
          t = ActionLenSolver.measure_types(args, lens, unknown, code_parsed: CODE) if unknown.any?
          if known.any?
            t ||= Hash.new { |h, k| h[k] = Hash.new(0) }
            ActionLenSolver.measure_hidden_types(args, lens, known, code_parsed: CODE).each do |k, v|
              t[k] = v
            end
          end
          t
        else
          t, rate = ActionLenSolver.measure_corpus(args, lens, nil, code_parsed: CODE)
          t
        end
decided = {}
tally.each do |t, by_len|
  next if t > 400 # a desync artefact, not an action
  ranked = by_len.sort_by { |_, n| -n }
  best, top = ranked.first
  second = ranked[1]&.last.to_i
  decided[t] = { length: best, votes: top, second: second } if top && top >= MIN_OBS && second * MARGIN < top
end

# ── --type N ...: the same pass, filtered ──────────────────────────────
if @types&.any?
  failed = false
  @types.each do |t|
    d = decided[t]
    failed ||= d.nil?
    if @json
      puts JSON.generate(type: t, name: name[t], table: lens[t],
                         verdict: d ? 'measured' : 'ambiguous', length: d&.fetch(:length, nil),
                         votes: d&.fetch(:votes, nil), runner_up: d&.fetch(:second, nil),
                         tally: tally[t].to_h.transform_values(&:to_i))
    else
      puts "type #{t} (#{name[t]}) — table says #{lens[t].inspect}, #{args.size} file(s)"
      if tally[t].empty?
        puts '  no decisive closure: this action never appears where the rest of the'
        puts '  closure is measurable. Needs more traffic, or a layout decode.'
      else
        tally[t].sort_by { |_, n| -n }.first(6).each { |l, n| puts "  length #{l}: #{n} closures#{d && l == d[:length] ? '  <-' : ''}" }
        puts "  verdict: #{d ? "measured (#{d[:length]} bytes, #{d[:votes]} closures, runner-up #{d[:second]})" : 'ambiguous'}"
      end
      puts
    end
  end
  exit(failed ? 1 : 0)
end

# ── --decide (and the default): what is left, worst first ─────────────
fresh = decided.reject { |t, _| lens.key?(t) }
if @json
  puts JSON.generate(measured: lens.size,
                     undecided: fresh.transform_values { |d| d[:length] },
                     candidates: fresh.transform_values { |d| { length: d[:length], votes: d[:votes] } })
  exit 0
end
puts "table: #{lens.size} fixed lengths; capture set: #{args.size} file(s)"
puts
if fresh.empty?
  puts '== nothing new: the wire decides nothing the table lacks =='
else
  puts '== the wire decides, the table lacks =='
  fresh.sort_by { |t, d| [-d[:votes], t] }.each do |t, d|
    printf("  %-5d %-42s => %-4d  (%d closures, runner-up %d)\n", t, name[t], d[:length], d[:votes], d[:second])
  end
end

puts "\n== unmeasured types ranked by failure rate (the tail work-list) =="
(rate || {}).select { |_, (f, _)| f.positive? }.sort_by { |_, (f, c)| [-f, -c] }.first(20).each do |t, (f, c)|
  printf("  %-5d %-42s %4d failing / %5d closures\n", t, name[t], f, f + c)
end
puts "\n#{rate.size} unmeasured types seen. To decide one:"
puts '  ruby tools/measure_action_lens.rb --type N captures/*.pcap'
