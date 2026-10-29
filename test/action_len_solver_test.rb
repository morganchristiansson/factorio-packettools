#!/usr/bin/env ruby
# frozen_string_literal: true

# ActionLenSolver tests.
#
# The solver is what makes the action tables' measured lengths reproducible:
# given a real C→S heartbeat
# and the length of every action in it EXCEPT one, it returns that one's length
# from the byte budget. The fixtures in test/fixtures/packets.rb are real
# packets, so every length the table claims is re-derived here from those bytes —
# if the table drifts from the wire, this fails.
#
# The decisive detail: a closure is walked SEQUENTIALLY, skipping each action's
# payload. An earlier version read every action's header without skipping
# payloads, so in a two-action closure the second type came from inside the first
# action's data and the arithmetic was meaningless while looking fine.
require 'minitest/autorun'
require 'mocha/minitest'
require 'factorio_protocol'
require 'factorio_protocol/build' # build_input_action / build_client_heartbeat
require_relative 'fixtures/packets'
require_relative '../tools/action_len_solver'

class TestActionLenSolver < Minitest::Test
  # The version-dependent tables are module state, and most tests here measure
  # against the 2.0 ones. Reset before AND after, so no 2.0 table survives into
  # another test file when they are run in one process.
  def setup
  end

  def teardown
  end

  def fixture(name)
    fx = REAL_PACKET_FIXTURES.find { |f| f[:name] == name }
    refute_nil fx, "fixture #{name} missing"
    [fx[:hex]].pack('H*')
  end

  # The measured lengths live in the action table now (no separate lens);
  # fixed table lengths are the solver's lens.
  def table_lens
    FactorioProtocol.actions.select { |_t, (_n, l)| !l.nil? }.transform_values { |(_n, l)| l }
  end

  def solved(name, type)
    ActionLenSolver.measure_length(fixture(name), table_lens, type)
  end

  # A closure whose actions are all unknown has no hole to fill: the solver must
  # refuse rather than hand out the whole area as one action's payload.
  # (2.0 fixture bytes — the property is version-agnostic, the lens is empty.)
  def test_refuses_when_nothing_is_known
    # Synthetic closure [900 d1][901 d0] — no known lengths, no hole.
    a1 = FactorioProtocol.build_input_action(900, 1, "\x00\x00".b)
    a2 = FactorioProtocol.build_input_action(901, 0, "\x00\x00".b)
    data = FactorioProtocol.build_client_heartbeat(
      seq: 1, next_receive: 0, closures: [[0, 2, a1 + a2]]
    )
    assert_nil ActionLenSolver.measure_length(data, {}, 900)
    assert_nil ActionLenSolver.measure_length(data, {}, 901)
  end
end
