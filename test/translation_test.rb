#!/usr/bin/env ruby
# frozen_string_literal: true

# Tests for the Translation backends and the /simulate console command.
#
# Regression: /simulate used to call the typo'd @translation_agent
# translate_service method. This suite drives the real handler and asserts the
# translated output instead of relying on a hand-written pass/fail runner.
# Argos is only installed on the target server, so the CLI test uses a fake
# `argos-translate` executable.
# Run: ruby -Ilib test/translation_test.rb

require 'minitest/autorun'
require 'mocha/minitest'
require 'tmpdir'
require 'fileutils'
require_relative '../factorio-packettools'
require_relative '../lib/translation'
require_relative '../lib/translation_argos'
require_relative '../lib/translation_mock'

# The plugin's config is required (no code defaults), so the tests point at
# the checked-in example, the way the hivemind tests do.
TRANSLATION_TEST_CONFIG = File.expand_path('../config-translation.yaml.example', __dir__)

# Lets tests inject the translation feature where the sniffer reaches it: it
# is built by PluginSet now, so the /simulate console command and the
# emit(:on_chat) bus go through @plugins[:translation], not a @translation_agent
# ivar. The fake needs only what the sniffer calls on it.
class PluginsDouble
  def initialize(translation: nil) = @translation = translation
  def [](name) = name == :translation ? @translation : nil
  def enabled?(*) = false
  def emit(*) = nil
end

class TestTranslation < Minitest::Test
  def setup
    @agents = []
  end

  def teardown
    @agents.each(&:close_events)
    FileUtils.remove_entry(@scenario_dir) if @scenario_dir
  end

  def make_agent(backend: :mock, rcon: nil, player_db: PlayerDatabase.new(nil), roster: nil,
                 config_file: TRANSLATION_TEST_CONFIG, **kwargs)
    agent = Translation.new(
      rcon: rcon,
      player_db: player_db,
      backend: backend,
      roster: roster,
      config_file: config_file,
      **kwargs
    )
    @agents << agent
    agent
  end

  # A copy of the example config with the optional scenario locale block on:
  # the default example leaves it off, so most tests exercise the no-scenario
  # path and only the integration tests opt in.
  def scenario_config
    @scenario_dir ||= Dir.mktmpdir('translation-test')
    path = File.join(@scenario_dir, 'config-translation.yaml')
    File.write(path, File.read(TRANSLATION_TEST_CONFIG) +
                     "\nscenario_locale:\n  storage_key: locale\n  event: locale-selected\n")
    path
  end

  # The unknown-packets writer is injected as a null double: the default is
  # a REAL PcapWriter, which leaves an empty captures/unknown.packets-<ts>.pcap
  # in the repo on every run.
  class NullWriter
    def path = 'unknown.packets (test)'
    def write_frame(*) = nil
    def close = nil
  end

  def make_sniffer
    FactorioPacketTools.new({ server: false, pcap: nil, interface: nil },
                            unknown_pcap_writer: NullWriter.new)
  end

  def command_recorder
    commands = []
    rcon = Object.new
    rcon.define_singleton_method(:command) do |command|
      commands << command
      ''
    end
    rcon.define_singleton_method(:lua_quote) { |value| RconClient.allocate.lua_quote(value) }
    [rcon, commands]
  end

  def test_simulate_command_and_locale_console
    sniffer = make_sniffer
    player_db = sniffer.instance_variable_get(:@player_db)
    sniffer.instance_variable_set(:@plugins, PluginsDouble.new(translation: make_agent(player_db: player_db)))

    simulate_output, simulate_error = capture_io do
      sniffer.handle_command(%q{/simulate StarBurtS ru "Zdravstvuyte"})
    end
    assert_includes simulate_output,
                    "[simulate] player=StarBurtS lang=ru msg='Zdravstvuyte' => translated='[en] Zdravstvuyte'"
    refute_includes simulate_error, 'NoMethodError'

    locales_output, = capture_io do
      sniffer.handle_command('/locales somePlayer en')
      sniffer.handle_command('/locales somePlayer')
      sniffer.handle_command('/locales')
      sniffer.handle_command('/locales somePlayer en,pt') # old syntax: first wins
    end
    assert_equal 'en', player_db.locale_override('somePlayer')
    assert_includes locales_output, 'somePlayer: en'
    capture_io do
      sniffer.handle_command('/locales somePlayer -')
    end
    assert_nil player_db.locale_override('somePlayer')
  end

  def test_google_api_key_from_yaml_with_env_override
    Dir.mktmpdir do |dir|
      base = YAML.safe_load_file(TRANSLATION_TEST_CONFIG).merge('backend' => 'google')
      with_key = File.join(dir, 'with-key.yaml')
      without_key = File.join(dir, 'without-key.yaml')
      File.write(with_key, YAML.dump(base.merge('google_api_key' => 'yaml-key')))
      File.write(without_key, YAML.dump(base))

      with_env('GOOGLE_TRANSLATE_API_KEY' => nil) do
        assert make_agent(backend: nil, config_file: with_key).google_api_key?,
               'key picked up from the config file'
      end
      with_env('GOOGLE_TRANSLATE_API_KEY' => 'env-key') do
        assert make_agent(backend: nil, config_file: with_key).google_api_key?
      end
      with_env('GOOGLE_TRANSLATE_API_KEY' => nil) do
        # No key anywhere is a startup error, not a silently broken agent.
        error = assert_raises(ArgumentError) { make_agent(backend: nil, config_file: without_key) }
        assert_match(/needs a Google key/, error.message)
      end
    end
  end

  # Config is required: no file, or a file missing a key, is an error the
  # sniffer reports as "[translate] Translation agent disabled: ...".
  def test_config_is_required
    error = assert_raises(Errno::ENOENT) { make_agent(config_file: '/nonexistent/config-translation.yaml') }
    assert_match(/config-translation\.yaml\.example/, error.message)

    Dir.mktmpdir do |dir|
      path = File.join(dir, 'partial.yaml')
      File.write(path, YAML.dump('backend' => 'mock'))
      # Not validated up front: the key raises where it is read, naming itself.
      error = assert_raises(KeyError) { make_agent(config_file: path) }
      assert_includes error.message, 'whitelist'
    end
  end

  # No hardcoded defaults left: the whitelist and the anti-spam interval come
  # from the file.
  def test_no_code_defaults_for_whitelist_or_interval
    config = YAML.safe_load_file(TRANSLATION_TEST_CONFIG)
    agent = make_agent(backend: :mock)

    assert_equal config['whitelist'].map(&:downcase).to_set, agent.whitelist
    assert_equal config['min_interval'], agent.instance_variable_get(:@min_interval)
  end

  def with_env(vars)
    old = vars.to_h { |k, _| [k, ENV[k]] }
    vars.each { |k, v| v.nil? ? ENV.delete(k) : ENV[k] = v }
    yield
  ensure
    old.each { |k, v| v.nil? ? ENV.delete(k) : ENV[k] = v }
  end

  def test_backend_wiring
    fake = fake_argos_install
    argos = make_agent(backend: :argos, argos_path: fake)
    assert_instance_of ArgosTranslateService, argos.translation_service
    assert_equal fake, argos.translation_service.instance_variable_get(:@path)

    mock = make_agent
    assert_instance_of MockTranslationService, mock.translation_service

    google = make_agent(backend: :google, google_api_key: 'fake-key')
    assert_instance_of GoogleCloudTranslateService, google.translation_service

    hybrid = make_agent(backend: :hybrid, google_api_key: 'fake-key', argos_path: fake)
    assert_instance_of HybridTranslationService, hybrid.translation_service
    assert_instance_of ArgosTranslateService, hybrid.translation_service.instance_variable_get(:@argos)
    assert_instance_of GoogleCloudTranslateService, hybrid.translation_service.instance_variable_get(:@google)
  end

  # A minimal fake argos install: the CLI plus an argospm that lists packs
  # (the service refuses to start without both).
  def fake_argos_install
    @fake_argos_dir ||= Dir.mktmpdir('fake-argos')
    script = File.join(@fake_argos_dir, 'argos-translate')
    argospm = File.join(@fake_argos_dir, 'argospm')
    File.write(script, "#!/bin/sh\nprintf 'PEREVOD\\n'\n")
    File.chmod(0o755, script)
    File.write(argospm, "#!/bin/sh\necho 'translate-ru_en'\necho 'translate-en_ru'\n")
    File.chmod(0o755, argospm)
    script
  end

  def test_argos_cli_arguments_safety_stderr_and_supported_languages
    Dir.mktmpdir do |dir|
      script = File.join(dir, 'fake-argos')
      argospm = File.join(dir, 'argospm')
      log = File.join(dir, 'args.log')
      File.write(script, "#!/bin/sh\nprintf '%s\\n' \"$@\" > \"#{log}\"\nprintf 'PEREVOD\\n'\n")
      File.chmod(0o755, script)
      File.write(argospm, "#!/bin/sh\necho 'translate-ru_en'\necho 'translate-en_ru'\n")
      File.chmod(0o755, argospm)

      service = ArgosTranslateService.new(path: script)
      text = "Zdravstvuyte $(touch injected) `touch backticked`"
      assert_equal 'PEREVOD', service.translate(text, source_lang: 'ru', target_lang: 'en')
      assert_equal ['--from-lang', 'ru', '--to-lang', 'en', text], File.readlines(log).map(&:strip)
      refute File.exist?(File.join(dir, 'injected'))
      refute File.exist?(File.join(dir, 'backticked'))

      assert_equal 'PEREVOD', service.translate("a\0b", source_lang: 'ru', target_lang: 'en')
      assert_equal 'ab', File.readlines(log).map(&:strip).last

      noisy = File.join(dir, 'noisy-argos')
      File.write(noisy, "#!/bin/sh\necho '2026-09-17 17:06:58 WARNING: Language en package default expects mwt' >&2\nprintf 'PEREVOD\\n'\n")
      File.chmod(0o755, noisy)
      assert_equal 'PEREVOD', ArgosTranslateService.new(path: noisy).translate('x', source_lang: 'ru', target_lang: 'en')

      assert service.supported?('ru')
      assert service.supported?('RU')
      assert service.supported?('ru-RU')
      refute service.supported?('hu')
      refute service.supported?('hu-HU')
    end
  end

  # A backend that cannot run is a STARTUP error, not a healthy agent that
  # silently never translates: no binary, and no language packs.
  def test_missing_argos_install_is_an_error
    error = assert_raises(RuntimeError) { ArgosTranslateService.new(path: '/nonexistent/argos-translate') }
    assert_match(/argos-translate not found/, error.message)

    Dir.mktmpdir do |dir|
      script = File.join(dir, 'argos-translate')
      File.write(script, "#!/bin/sh\nprintf 'PEREVOD\\n'\n")
      File.chmod(0o755, script)
      error = assert_raises(RuntimeError) { ArgosTranslateService.new(path: script) } # no argospm beside it
      assert_match(/no argos language packs/, error.message)
    end
  end

  def test_on_chat_relays_translations_by_locale
    roster = -> { [{ index: 1, name: 'ivan' }, { index: 2, name: 'bob' }, { index: 3, name: 'pedro' }] }
    rcon, commands = command_recorder
    player_db = PlayerDatabase.new(nil)
    player_db[1] = {name: 'ivan', locale: 'ru'}
    player_db[2] = {name: 'bob', locale: 'en'}
    player_db[3] = {name: 'pedro', locale: 'pt'}
    agent = make_agent(rcon: rcon, player_db: player_db, roster: roster)

    output, = capture_io do
      result = agent.handle_chat(1, 'привет')
      assert_equal [true, 'привет'], result
      agent.handle_chat(3, 'hola que tal')
      assert_equal '[en] привет', agent.simulate_translation('ivan', 'ru', 'привет')
      agent.simulate_translation('pedro', 'pt-BR', 'olá')
    end

    # Console echoes the TRANSLATIONS sent, not the original text
    # (the sniffer already printed the chat itself).
    assert_includes output, '[translate] [ru>en] ivan: [en] привет  |  [ru>pt] ivan: [pt] привет'
    refute_includes output, "[translate] ivan (ru): привет\n"

    assert_equal 4, commands.size
    first = commands.first
    assert_includes first, '/sc '
    assert_includes first, 'for _, p in pairs(game.connected_players)'
    assert_includes first, '[2]="[ru>en] ivan:'
    assert_includes first, '[3]="[ru>pt] ivan:'
    refute_includes first, '[1]='
    assert_includes first, 'local x = t[p.index]'
    assert_includes first, 'p.print(x, ps)'
    assert_includes first, 'local n = "ivan"'
    assert_includes first, 'local s = game.players[n]'
    assert_includes first, 's.chat_color or s.color'
    assert_includes first, '{color = (s.chat_color or s.color)}'

    second = commands[1]
    assert_includes second, '[1]="[pt>ru] pedro:'
    assert_includes second, '[2]="[pt>en] pedro:'
    refute_includes second, '[3]='

    fourth = commands[3]
    assert_includes fourth, '[1]="[pt>ru] pedro:'
    assert_includes fourth, '[2]="[pt>en] pedro:'
    refute_includes fourth, 'pt-BR'

    fourth = commands[3]
    assert_includes fourth, '[1]="[pt>ru] pedro:'
    assert_includes fourth, '[2]="[pt>en] pedro:'
    refute_includes fourth, 'pt-BR'
  end

  # ONE locale per player, and the override REPLACES the game default: it
  # decides both the language a speaker writes and the language a reader
  # receives. A reader whose override is English is not sent the pt relay
  # even though their Factorio interface locale is pt-BR.
  def test_locale_override_replaces_game_locale_for_speaker_and_reader
    roster = -> {
      [{ index: 1, name: 'ivan' }, { index: 2, name: 'bob' },
       { index: 3, name: 'pedro' }, { index: 4, name: 'alice' },
       { index: 5, name: 'olga' }]
    }
    rcon, commands = command_recorder
    player_db = PlayerDatabase.new(nil)
    player_db[1] = {name: 'ivan', locale: 'ru'}
    player_db[2] = {name: 'bob', locale: 'en'}
    player_db[3] = {name: 'pedro', locale: 'pt'}
    player_db[4] = {name: 'alice', locale: 'pt-BR'}
    player_db[5] = {name: 'olga', locale: 'ru'}
    player_db.set_locale_override('ivan', 'en')
    player_db.set_locale_override('alice', 'en')
    agent = make_agent(rcon: rcon, player_db: player_db, roster: roster)

    capture_io { agent.handle_chat(1, 'hello all') }
    lua = commands.first
    assert_includes lua, '[3]="[en>pt] ivan:'
    assert_includes lua, '[5]="[en>ru] ivan:'
    refute_includes lua, '[2]=', 'bob already reads English'
    refute_includes lua, '[4]=', 'alice selected English over her pt-BR default'
    refute_includes lua, 'ru>en', 'the speaker override is the message language'
  end

  def test_relay_skips_unchanged_whitelisted_and_unsupported_targets
    missing_pack = Class.new(MockTranslationService) do
      def translate(text, source_lang:, target_lang:)
        target_lang == 'pt' ? text : super
      end
    end.new

    roster = -> { [{ index: 1, name: 'ivan' }, { index: 2, name: 'bob' }, { index: 3, name: 'pedro' }] }
    rcon, commands = command_recorder
    player_db = PlayerDatabase.new(nil)
    player_db[1] = {name: 'ivan', locale: 'ru'}
    player_db[2] = {name: 'bob', locale: 'en'}
    player_db[3] = {name: 'pedro', locale: 'pt'}
    agent = make_agent(rcon: rcon, player_db: player_db, roster: roster)
    agent.instance_variable_set(:@translation_service, missing_pack)

    capture_io { agent.handle_chat(1, "привет\0\0") }
    assert_includes commands.first, '[2]="[ru>en] ivan:'
    refute_includes commands.first, '[3]='
    refute_includes commands.first, "\0"

    unsupported_rcon, unsupported_commands = command_recorder
    unsupported_db = PlayerDatabase.new(nil)
    unsupported_db[1] = {name: 'ivan', locale: 'ru'}
    unsupported_db[2] = {name: 'bob', locale: 'en'}
    unsupported_db[3] = {name: 'pierre', locale: 'fr'}
    unsupported_agent = make_agent(
      rcon: unsupported_rcon,
      player_db: unsupported_db,
      roster: -> { [{ index: 1, name: 'ivan' }, { index: 2, name: 'bob' }, { index: 3, name: 'pierre' }] }
    )

    capture_io { unsupported_agent.handle_chat(1, 'привет') }
    assert_includes unsupported_commands.first, '[2]="[ru>en] ivan:'
    refute_includes unsupported_commands.first, '[3]='
  end

  def test_on_chat_skips_non_factorio_sources
    roster = -> { [{ index: 1, name: 'ivan' }] }
    rcon, commands = command_recorder
    player_db = PlayerDatabase.new(nil)
    player_db[1] = {name: 'ivan', locale: 'ru'}
    agent = make_agent(rcon: rcon, player_db: player_db, roster: roster)
    # Only in-game (:factorio) chat is translated: nil for any other source,
    # and no relay command is sent.
    assert_nil agent.on_chat(:discord, 'Alice', 'hi', 1)
    assert_nil agent.on_chat(:hivemind, 'Hivemind', 'done', 1)
    agent.close_events
    assert_empty commands
  end

  def test_locale_override_persistence
    Dir.mktmpdir do |dir|
      cache = File.join(dir, 'players-cache.json')
      db = PlayerDatabase.new(cache)
      db[7] = {name: 'somePlayer', locale: 'pt-BR'}
      db.set_locale_override('somePlayer', 'en')

      assert_equal 'en', db.locale_override('somePlayer')
      reloaded = PlayerDatabase.new(cache)
      assert_equal 'en', reloaded.locale_override('somePlayer')
      assert File.exist?(File.join(dir, 'players-locale.json'))
      assert_equal({ 'somePlayer' => 'en' }, JSON.parse(File.read(File.join(dir, 'players-locale.json'))))
      assert_equal 'somePlayer', reloaded.lookup(7)
      assert_equal 'pt-BR', reloaded.get_locale(7)

      reloaded.set_locale_override('somePlayer', nil)
      cleared = PlayerDatabase.new(cache)
      assert_nil cleared.locale_override('somePlayer')
    end
  end

  # The game's storage.locale is the authoritative single-locale copy.
  # Startup replaces the cached map (a name the game no longer has went back
  # to its default), and a legacy array file keeps its first language.
  def test_replace_locale_overrides_and_legacy_array_migration
    Dir.mktmpdir do |dir|
      cache = File.join(dir, 'players-cache.json')
      File.write(File.join(dir, 'players-locale.json'),
                 JSON.generate('Old' => ['en', 'pt'], 'Gone' => 'ru'))
      db = PlayerDatabase.new(cache)
      assert_equal 'en', db.locale_override('Old')
      assert_equal 'ru', db.locale_override('Gone')

      db.replace_locale_overrides('Alice' => 'pl', 'Bob' => 'pt-BR')
      assert_equal({ 'Alice' => 'pl', 'Bob' => 'pt' }, db.all_locale_overrides)
      assert_nil db.locale_override('Old'), 'a name absent from storage went back to default'

      db.replace_locale_overrides(nil)
      assert_empty db.all_locale_overrides
    end
  end

  # The locale GUI's event is the live update path: one line changes (or
  # clears, locale=nil) exactly one player's override.
  def test_on_log_line_applies_locale_selected
    rcon, = command_recorder
    player_db = PlayerDatabase.new(nil)
    agent = make_agent(rcon: rcon, player_db: player_db, config_file: scenario_config)

    agent.on_log_line('event=locale-selected, actor=Alice, locale=pl')
    assert_equal 'pl', player_db.locale_override('Alice')

    # Factorio decorates script log lines with a timestamp and source.
    agent.on_log_line('123.456 Script @__level__/locale.lua:42: event=locale-selected, actor=Alice, locale=de')
    assert_equal 'de', player_db.locale_override('Alice')

    agent.on_log_line('event=locale-selected, actor=Alice, locale=nil')
    assert_nil player_db.locale_override('Alice')

    agent.on_log_line('event=locale-selected, actor=Bob, locale=')
    assert_nil player_db.locale_override('Bob')

    agent.on_log_line('event=player-died, actor=Alice, locale=pl')
    assert_nil player_db.locale_override('Alice')
  end

  # An operator / Hivemind selection writes BOTH the cache and the game's
  # storage.locale, so it survives the startup sync.
  def test_set_locale_mirrors_into_game_storage
    rcon, = command_recorder
    writes = []
    rcon.define_singleton_method(:set_player_locale) { |name, locale, key| writes << [name, locale, key] }
    player_db = PlayerDatabase.new(nil)
    agent = make_agent(rcon: rcon, player_db: player_db, config_file: scenario_config)

    assert_equal 'pl', agent.set_locale('Alice', 'pl-PL')
    assert_equal 'pl', player_db.locale_override('Alice')
    assert_equal [['Alice', 'pl', 'locale']], writes

    assert_nil agent.set_locale('Alice', nil)
    assert_equal [['Alice', 'pl', 'locale'], ['Alice', nil, 'locale']], writes
  end

  # players-locale.json is the durable, name-keyed copy. On startup the
  # current save's table wins for names it has, and names it lacks are
  # written back — so a fresh save (empty table) does not lose selections.
  def test_on_start_merges_and_restores_locales
    rcon, = command_recorder
    writes = []
    rcon.define_singleton_method(:player_locales) { |key| (@seen_key = key) && { 'Alice' => 'pl', 'Bob' => 'pt-BR' } }
    rcon.define_singleton_method(:set_player_locale) { |name, locale, key| writes << [name, locale, key] }
    player_db = PlayerDatabase.new(nil)
    player_db.set_locale_override('Stale', 'ru')
    agent = make_agent(rcon: rcon, player_db: player_db, config_file: scenario_config)

    agent.on_start
    assert_equal 'locale', rcon.instance_variable_get(:@seen_key)
    assert_equal({ 'Stale' => 'ru', 'Alice' => 'pl', 'Bob' => 'pt' }, player_db.all_locale_overrides)
    assert_equal [['Stale', 'ru', 'locale']], writes

    # A failed query (nil) keeps the cache instead of wiping it.
    rcon.define_singleton_method(:player_locales) { |_key| nil }
    agent.on_start
    assert_equal({ 'Stale' => 'ru', 'Alice' => 'pl', 'Bob' => 'pt' }, player_db.all_locale_overrides)
  end

  # Without the scenario block nothing under `storage` is touched and log
  # lines are ignored: players-locale.json + /locales are the whole source.
  def test_scenario_locale_integration_is_optional
    rcon, commands = command_recorder
    player_db = PlayerDatabase.new(nil)
    agent = make_agent(rcon: rcon, player_db: player_db)

    assert_nil agent.locale_storage_key
    assert_nil agent.locale_event
    agent.on_start
    agent.on_log_line('event=locale-selected, actor=Alice, locale=pl')
    assert_nil player_db.locale_override('Alice')
    assert_equal 'pl', agent.set_locale('Alice', 'pl')
    assert_equal 'pl', player_db.locale_override('Alice')
    assert_empty commands
  end

  # Both names are configurable: the scenario may call its table/event
  # anything.
  def test_scenario_locale_names_are_configurable
    rcon, _commands = command_recorder
    writes = []
    rcon.define_singleton_method(:set_player_locale) { |name, locale, key| writes << [name, locale, key] }
    player_db = PlayerDatabase.new(nil)
    @scenario_dir ||= Dir.mktmpdir('translation-test')
    path = File.join(@scenario_dir, 'config-translation.yaml')
    File.write(path, File.read(TRANSLATION_TEST_CONFIG) +
                     "\nscenario_locale:\n  storage_key: ui/lang\n  event: lang-picked\n")
    agent = make_agent(rcon: rcon, player_db: player_db, config_file: path)

    agent.on_log_line('event=locale-selected, actor=Alice, locale=pl')
    assert_nil player_db.locale_override('Alice')
    agent.on_log_line('event=lang-picked, actor=Alice, locale=pl')
    assert_equal 'pl', player_db.locale_override('Alice')
    agent.set_locale('Alice', 'de')
    assert_equal [['Alice', 'de', 'ui/lang']], writes
  end
end
