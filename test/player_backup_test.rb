# frozen_string_literal: true

require 'minitest/autorun'
require 'json'
require 'tmpdir'
require_relative '../lib/player_backup'

class PlayerBackupTest < Minitest::Test
  Host = Struct.new(:rcon, :player_db)

  def setup
    @dir = Dir.mktmpdir
    @path = File.join(@dir, 'players-backup.json')
    @backup = PlayerBackup.new(Host.new(nil, nil), path: @path)
  end

  def teardown
    FileUtils.remove_entry(@dir)
  end

  def record(name)
    JSON.parse(File.read(@path))[name]
  end

  # Measured live on 2.1.23: /color RGB sets alpha 0.5 and derives chat_color
  # by adding 0.15 to each channel, clamped at 1.0.
  def test_color_rgb_derives_chat_color_by_adding_the_game_tint
    @backup.on_chat(:factorio, 'Alice', '/color 12 34 56')
    r = record('Alice')
    assert_in_delta 0.0471, r['color'][0], 0.0001
    assert_in_delta 0.1333, r['color'][1], 0.0001
    assert_in_delta 0.2196, r['color'][2], 0.0001
    assert_in_delta 0.5, r['color'][3], 0.0001
    assert_in_delta 0.1971, r['chat_color'][0], 0.0001
    assert_in_delta 0.2833, r['chat_color'][1], 0.0001
    assert_in_delta 0.3696, r['chat_color'][2], 0.0001
    assert_in_delta 1.0, r['chat_color'][3], 0.0001
  end

  def test_rgb_fourth_value_is_ignored_and_white_is_capped
    @backup.on_chat(:factorio, 'Alice', '/color 255 0 0 255')
    assert_in_delta 0.5, record('Alice')['color'][3], 0.0001
    @backup.on_chat(:factorio, 'Alice', '/color 255 255 255')
    r = record('Alice')
    assert_equal [1.0, 1.0, 1.0], r['chat_color'][0, 3]
  end

  def test_named_color_uses_the_hand_tuned_table
    @backup.on_chat(:factorio, 'Alice', '/color red')
    r = record('Alice')
    assert_in_delta 0.815, r['color'][0], 0.0001
    assert_in_delta 0.166, r['chat_color'][1], 0.0001
  end

  # Existing records predate chat_color. Restoring one must not leave the
  # game's default chat tint in place: derive the game's own value from color.
  def test_restore_derives_missing_chat_color_from_color
    calls = []
    rcon = Object.new
    rcon.define_singleton_method(:restore_player) do |_name, _cells, color: nil, chat_color: nil|
      calls << [color, chat_color]
      0
    end
    backup = PlayerBackup.new(Host.new(rcon, nil), path: @path)
    capture_io do
      assert backup.send(:restore, 'Alice', 1, { 'color' => [1.0, 0.0, 0.0, 0.5] })
    end
    assert_equal [[[1.0, 0.0, 0.0, 0.5], [1.0, 0.15, 0.15, 1.0]]], calls
  end

  # set_player_color's 4th wire byte is ignored; the action sets both colours.
  def test_color_picker_action_sets_both_colours_with_alpha_half
    @backup.on_player_color('Alice', [1.0, 0.0, 1.0, 0.0])
    r = record('Alice')
    assert_equal [1.0, 0.0, 1.0, 0.5], r['color']
    assert_equal [1.0, 0.15, 1.0, 1.0], r['chat_color']
  end
end
