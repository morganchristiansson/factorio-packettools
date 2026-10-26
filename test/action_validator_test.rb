# frozen_string_literal: true

# Tests for the action_validator sniffer plugin (runtime correlation of
# /toggle-action-logging log lines with decoded C→S wire actions).
# Run: bundle exec ruby -Ilib test/action_validator_test.rb

require 'minitest/autorun'
require_relative '../lib/action_validator'
require 'factorio_protocol'

class TestActionValidator < Minitest::Test
  def setup
    FactorioProtocol.reset_version
    @v = ActionValidator.new(Object.new)
  end

  def teardown
    FactorioProtocol.reset_version
  end

  # ── helpers ──────────────────────────────────────────────────────

  # The log's player index is 0-based on stable 2.1.23 (wire game_player is
  # 1-based) — the tests write log indices as wire player - 1 to match.
  def log!(tick, player, name)
    @v.record_log_line("Info InputActionHandler.cpp:672: Action performed [#{tick} #{player - 1} #{name}]")
  end

  # A decoded C→S tick closure: hashes with the fields the sniffer's emit
  # carries (the validator only reads :type, :game_player).
  def wire!(tick, list)
    @v.on_input_actions(tick, list.map { |t, player| { type: t, game_player: player } })
  end

  # ── cases ────────────────────────────────────────────────────────

  def test_matching_actions_correlate_ok
    log! 1000, 12, 'Build'        # CamelCase log form
    wire! 1000, [[69, 12]]        # stable 2.1 build
    assert_equal 1, @v.stats[:ok]
    assert_equal 0, @v.stats[:mismatch]
  end

  def test_mismatch_prints_and_counts
    log! 1000, 12, 'Upgrade'
    out = capture_io do
      wire! 1000, [[132, 12]]     # stable 2.1 deconstruct
    end.first
    assert_includes out, 'MISMATCH'
    assert_includes out, 'wire 132=deconstruct but log says Upgrade'
    assert_equal 1, @v.stats[:mismatch]
  end

  def test_mismatch_detail_printed_once_until_next_summary
    log! 1000, 12, 'Upgrade'
    capture_io { wire! 1000, [[132, 12]] }
    capture_io { wire! 1000, [] }
    log! 1001, 12, 'Upgrade'
    out3, = capture_io { wire! 1001, [[132, 12]] }
    # Same (wire, log) pair repeats after the pair was reported once — the
    # repeat is counted, the detail line is not printed again.
    assert_equal 2, @v.stats[:mismatch]
    assert_empty out3
  end

  def test_not_in_table_counted_and_voted
    log! 1000, 12, 'StartWalking'
    wire! 1000, [[999, 12]]
    assert_equal 1, @v.stats[:not_in_table]
    assert_equal 1, @v.votes[999]['StartWalking']
  end

  def test_sequence_length_mismatch_flagged
    log! 1000, 12, 'StartWalking'
    log! 1000, 12, 'StopWalking'
    out = capture_io do
      wire! 1000, [[70, 12]]      # only one wire action for two log lines
    end.first
    assert_includes out, '1 wire actions but 2 log actions'
    assert_equal 1, @v.stats[:seq_len_mismatch]
  end

  def test_tick_tolerance_joins_lagged_log_line
    log! 1002, 12, 'Build'        # log tick leads by 2
    capture_io { wire! 1000, [[69, 12]] }
    assert_equal 1, @v.stats[:ok]
  end

  def test_nothing_padding_stripped_from_wire_side
    log! 1000, 12, 'Build'
    capture_io { wire! 1000, [[0, 12], [69, 12]] }
    assert_equal 1, @v.stats[:ok], "padding action must not pair with the log's Build"
  end

  def test_unrelated_players_do_not_pair
    log! 1000, 12, 'Build'
    out, = capture_io { wire! 1000, [[70, 13]] } # player 13 on the wire, 12 in the log
    assert_empty out
    assert_equal 0, @v.stats[:ok]
    assert_equal 0, @v.stats[:mismatch]
  end

  def test_votes_accumulate_for_candidate_corrections
    log! 1000, 12, 'Build'
    log! 1001, 12, 'Build'
    capture_io do
      wire! 1000, [[69, 12]]
      wire! 1001, [[69, 12]]
    end
    assert_equal({ 'Build' => 2 }, @v.votes[69])
  end

  def test_summary_no_false_candidates_for_case_only_difference
    # The log uses PascalCase, the table uses snake_case — normalize both,
    # so "StopWalking" must NOT appear as a candidate "disagreement".
    log! 1000, 12, 'StopWalking'
    out, = capture_io { wire! 1000, [[1, 12]] }
    assert_includes out, '1 OK'
    refute_includes out, 'candidate: wire 1'
  end

  def test_log_tick_consumed_after_correlation
    # Log entry at tick+2 is consumed by wire tick: tick+1 must NOT re-find it.
    log! 1002, 12, 'Build'
    capture_io { wire! 1000, [[69, 12]] }  # correlates with log tick 1002
    assert_equal 1, @v.stats[:ok]
    assert_empty @v.instance_variable_get(:@log), 'log tick should be consumed'
    # Re-correlating tick+1 should NOT find stale log entries at tick+2.
    log! 2002, 12, 'Build'
    capture_io { wire! 2000, [[69, 12]] }
    assert_equal 2, @v.stats[:ok]
  end

  def test_summary_lists_table_disagreements
    log! 1000, 12, 'Zorb'         # log name no table entry agrees with
    out, = capture_io { wire! 1000, [[132, 12]] } # the first correlation prints the summary
    assert_includes out, 'candidate: wire 132 table=deconstruct but log says Zorb'
  end

  def test_summary_rate_limited
    capture_io { @v.send(:maybe_report) } # first summary prints
    out, = capture_io { @v.send(:maybe_report) }
    assert_empty out, 'second summary within the interval must not print'
  end

  def test_buffers_evict_old_ticks_and_cap_size
    1000.times { |i| log!(i, 12, 'Build') }
    # All within the tick window — nothing evicted yet.
    assert @v.instance_variable_get(:@log).size <= ActionValidator::TICK_WINDOW + 1
    # Crossing the tick window evicts from the front.
    log! 100_000, 12, 'Build'
    assert_empty @v.instance_variable_get(:@log).keys.select { |t| t < 100_000 - ActionValidator::TICK_WINDOW }
    # FIFO cap backstop: an unbounded flood of one tick is capped by entries.
    10_000.times { log!(100_001, 12, 'Build') }
    assert @v.instance_variable_get(:@log).values.sum(&:size) <= ActionValidator::MAX_BUFFER_ENTRIES + 1
  end
end
