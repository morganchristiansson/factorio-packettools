#!/usr/bin/env ruby
# frozen_string_literal: true

# Tests for scheduled follow-ups (followups.rb): registry, scheduler thread, restart persistence.
# Run: ruby -Ilib test/hivemind_followups_test.rb

require_relative 'hivemind_helper'

class TestHivemindFollowUps < Minitest::Test
  include HivemindSpecHelpers

  # The FEATURE, and the entries it owns (they moved off the agent).
  def followups = @agent.plugins[:followups]
  def pending = followups.pending

  def setup
    @agent = make_agent
  end


  # ── Scheduled follow-ups (timeout tool) ────────────────────────

  def test_schedule_followup_stores_entry_and_returns_name
    result = @agent.schedule_followup(delay_seconds: 60, task: 'check spawn defense', name: 'spawn-check')
    assert_match(/Follow-up 'spawn-check' scheduled for \+60s/, result)
    entries = pending
    assert_equal 1, entries.size
    assert_equal 'check spawn defense', entries.first[:task]
    assert_operator entries.first[:due_at], :>, Time.now.to_f, 'absolute unix deadline (for restart re-arm)'
    assert_operator entries.first[:due], :>, Process.clock_gettime(Process::CLOCK_MONOTONIC), 'monotonic due (for firing)'
  end


  def test_schedule_followup_validates_delay_task_and_name
    assert_match(/minimum delay/, @agent.schedule_followup(delay_seconds: 1, task: 'too soon', name: 'x'))
    assert_match(/positive number/, @agent.schedule_followup(delay_seconds: 0, task: 'zero', name: 'x'))
    assert_match(/empty/, @agent.schedule_followup(delay_seconds: 60, task: '   ', name: 'x'))
    assert_match(/name is empty/, @agent.schedule_followup(delay_seconds: 60, task: 'check', name: '   '))
    assert_empty pending
  end


  def test_schedule_followup_upserts_same_name
    @agent.schedule_followup(delay_seconds: 60, task: 'old task', name: 'prowl')
    result = @agent.schedule_followup(delay_seconds: 25, task: 'new task', name: 'prowl')
    assert_match(/rescheduled/, result)
    entries = pending
    assert_equal 1, entries.size, 'same name replaces the pending entry'
    assert_equal 'new task', entries.first[:task]
  end


  def test_schedule_followup_caps_pending
    max = followups.max_pending_followups
    max.times { |i| @agent.schedule_followup(delay_seconds: 60, task: "t#{i}", name: "timer-#{i}") }
    result = @agent.schedule_followup(delay_seconds: 60, task: 'overflow', name: 'overflow')
    assert_match(/max #{max}/, result)
    assert_equal max, pending.size
    # Re-scheduling an EXISTING name never counts toward the cap.
    ok = @agent.schedule_followup(delay_seconds: 30, task: 'refresh', name: 'timer-0')
    assert_match(/rescheduled/, ok)
    assert_equal max, pending.size
  end


  def test_cancel_followup_removes_entry
    @agent.schedule_followup(delay_seconds: 60, task: 'check', name: 'prowl')
    assert_match(/cancelled/, @agent.cancel_followup(name: 'prowl'))
    assert_empty pending
    assert_match(/no follow-up named/, @agent.cancel_followup(name: 'prowl'))
  end


  def test_fire_followup_runs_turn_with_task_and_fresh_context
    @agent.schedule_followup(delay_seconds: 60, task: 'remind spawn defense', name: 'spawn')
    @agent.send(:append_history, 'bob', 'biters at the wall!')  # queued since last prompt
    entry = pending.first
    prompts = []
    @agent.stubs(:complete).with { |p| prompts << p; true }.returns('hold the line')
    followups.send(:fire_followup, entry)
    assert_includes prompts.first, 'SCHEDULED FOLLOW-UP'
    assert_includes prompts.first, 'remind spawn defense'
    assert_includes prompts.first, 'biters at the wall!', 'follow-up sees console lines queued since the last prompt'
    assert_includes @agent.instance_variable_get(:@rcon).sent.last, 'hold the line', 'model reply is broadcast'
  end


  def test_fire_followup_stays_silent_when_model_returns_nothing
    @agent.schedule_followup(delay_seconds: 60, task: 'check', name: 'check')
    entry = pending.first
    # the model decides nothing needs doing
    @agent.stubs(:complete).returns('')
    followups.send(:fire_followup, entry)
    assert_empty @agent.instance_variable_get(:@rcon).sent, 'no chat spam when the model stays silent'
  end


  def test_followups_survive_restart
    Dir.mktmpdir do |dir|
      sess = File.join(dir, 'session.json')
      a1 = new_hive_agent(rcon: FakeRcon.new, session: sess, memory_dir: false)
      a1.schedule_followup(delay_seconds: 60, task: 'remind spawn defense', name: 'spawn')
      a1.send(:persist!)
      data = JSON.parse(File.read(sess))
      assert_equal 1, data['followups'].size, 'follow-up persisted with its deadline'

      a2 = new_hive_agent(rcon: FakeRcon.new, session: sess, memory_dir: false)
      fups = a2.plugins[:followups].pending # 60s out: no turn, no model call
      assert_equal 1, fups.size
      assert_equal 'remind spawn defense', fups.first[:task]
      assert_equal 'spawn', fups.first[:name], 'name preserved across restart'
      assert_operator fups.first[:due], :>, Process.clock_gettime(Process::CLOCK_MONOTONIC), 'remaining delay kept'
    end
  end


  def test_overdue_followup_fires_after_restart
    Dir.mktmpdir do |dir|
      sess = File.join(dir, 'session.json')
      a1 = new_hive_agent(rcon: FakeRcon.new, session: sess, memory_dir: false)
      a1.schedule_followup(delay_seconds: 60, task: 'ping', name: 'ping-timer')
      # Rewrite the persisted deadline to the near future (simulates downtime)
      data = JSON.parse(File.read(sess))
      # New format: object keyed by timer name.
      data['followups'] = { 'ping-timer' => { 'due_at' => Time.now.to_f + 0.4, 'task' => 'ping' } }
      File.write(sess, JSON.generate(data))

      a2 = new_hive_agent(rcon: FakeRcon.new, session: sess, memory_dir: false)
      a2.define_singleton_method(:complete) { |_p| '' } # the scheduler's thread fires it later
      deadline = Time.now + 3
      fups = a2.plugins[:followups]
      sleep 0.05 until fups.pending.empty? || Time.now > deadline
      assert_empty fups.pending, 're-armed follow-up fired by the scheduler'
    end
  end


  def test_legacy_followup_formats_are_discarded
    Dir.mktmpdir do |dir|
      sess = File.join(dir, 'session.json')
      File.write(sess, JSON.generate(
        'followups' => [
          [7, Time.now.to_f + 60, 'integer-id legacy'],
          ['tuple-name', Time.now.to_f + 60, 'string-tuple legacy']
        ]
      ))
      agent = new_hive_agent(rcon: FakeRcon.new, session: sess, memory_dir: false)
      assert_empty agent.plugins[:followups].pending, 'non-hash formats are discarded, not migrated'
    end
  end


  # The scheduler starts at agent construction; ensure_followup_scheduler is
  # start-once and does not revive a dead thread (thread death is not recovered).
  def test_scheduler_started_at_construction
    agent = new_hive_agent(rcon: FakeRcon.new, memory_dir: false)
    fups = agent.plugins[:followups]
    sched = fups.instance_variable_get(:@scheduler)
    assert sched&.alive?, 'scheduler started at agent construction'

    id_before = sched.object_id
    fups.ensure_followup_scheduler # already running — start-once no-op
    assert_equal id_before, fups.instance_variable_get(:@scheduler).object_id,
                 'a live scheduler is not replaced'

    # A thread that dies is left dead — no revival.
    sched.kill; sched.join(0.1)
    fups.ensure_followup_scheduler
    refute fups.instance_variable_get(:@scheduler)&.alive?, 'a killed scheduler is not revived'

    class << agent
      def complete(_p) = '' # never hit the network
    end
    result = agent.schedule_followup(delay_seconds: 30, task: 'scheduler check', name: 'scheduler-check')
    assert_match(/scheduled/, result)
    assert_equal 'scheduler check', agent.plugins[:followups].pending.first[:task]
    agent.send(:persist!)
    assert agent.send(:compaction_material).include?('Pending scheduled follow-ups:')
  end

end
