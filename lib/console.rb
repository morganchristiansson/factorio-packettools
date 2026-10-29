# frozen_string_literal: true

# Interactive stdin console. Owns the output filters (/show /actions /noise
# /debug) so the packet host only asks "is this visible?" and owns the
# command surface so adding /model or /simulate does not touch the sniffer.
#
# This is deliberately one file: ViewFilter is the state, Console is the line
# parser. Plugin-specific commands stay here for now; the host exposes only
# online_players/print_summary.
class ViewFilter
  attr_accessor :debug

  def initialize(debug: false)
    @show_players = []
    @show_actions = []
    @hide_actions = []
    @debug = debug
  end

  def visible?(pname, act)
    name = pname.to_s.downcase
    return false if @show_players.any? && !@show_players.include?(name)
    return false if @hide_actions.include?(act[:name])
    return false if @show_actions.any? && !@show_actions.include?(act[:name])
    true
  end

  def player_visible?(name)
    n = name.to_s.downcase
    return false if @show_players.any? && !@show_players.include?(n)
    true
  end

  def describe
    puts "show_players=#{@show_players.inspect}"
    puts "show_actions=#{@show_actions.inspect} hide_actions=#{@hide_actions.inspect}"
    puts "debug=#{@debug}"
  end

  # /show|/actions|/noise: replace mode (bare names), +add / -remove
  # modifiers, or * to clear. Filters are downcased.
  def modify(kind, args)
    list = case kind
           when :players then @show_players
           when :actions then @show_actions
           when :noise then @hide_actions
           end
    if args.nil? || args.empty?
      puts "#{kind}: #{list.inspect}"
      return
    elsif args == ['*']
      list = []
    elsif args.first.start_with?('+', '-')
      args.each do |a|
        name = a[1..].downcase
        a.start_with?('+') ? list = (list + [name]).uniq : list -= [name]
      end
    else
      list = args.map(&:downcase)
    end
    case kind
    when :players then @show_players = list
    when :actions then @show_actions = list
    when :noise then @hide_actions = list
    end
    puts "#{kind}: #{list.inspect}"
  end
end

class Console
  def initialize(host, player_db:, plugins:, debug: false)
    @host = host
    @player_db = player_db
    @plugins = plugins
    @filter = ViewFilter.new(debug: debug)
  end

  attr_reader :filter

  # plugins may be a live Proc (the host replaces @plugins on re-init/tests).
  def plugins = @plugins.respond_to?(:call) ? @plugins.call : @plugins

  def visible?(pname, act) = @filter.visible?(pname, act)
  def player_visible?(name) = @filter.player_visible?(name)
  def debug? = @filter.debug

  def handle(line)
    parts = line.strip.split(/\s+/)
    return if parts.empty?
    case parts[0]
    when '/help', '/?'
      puts <<~HELP
        filter console (type a command, Enter):
          /players                     list online players
          /show NAME...                only show these players (* = clear)
          /show +NAME  /show -NAME     add / remove one player
          /actions NAME...             only show these action types
          /noise NAME...               hide these action types
          /debug                       toggle decoded per-action lines
          /filter                      show current filter state
          /stats                       print session stats
          /model [MODEL]               show or switch LLM model at runtime (Hivemind only)
          /try MODEL [MESSAGE]         one-off dry-run with a configured model — not persisted, not sent to game
          /compact                     distill session into memory, then start fresh
          /simulate NAME LANG MSG      test the translation backend with MSG in LANG
          /locales                     list per-player language overrides
          /locales NAME LANG[,...]     set a player's languages (- clears) e.g. /locales KrlosUltimate en,pt
      HELP
    when '/players'
      names = @host.online_players
      puts "online (#{names.size}): #{names.join(', ')}"
    when '/filter'
      @filter.describe
    when '/show' then @filter.modify(:players, parts[1..])
    when '/actions' then @filter.modify(:actions, parts[1..])
    when '/noise' then @filter.modify(:noise, parts[1..])
    when '/debug'
      @filter.debug = !@filter.debug
      puts "decoded per-action lines: #{@filter.debug ? 'SHOWN' : 'hidden'}"
    when '/stats'
      @host.print_summary
    when '/model'
      hivemind = plugins[:hivemind]
      if hivemind.nil?
        puts "hivemind disabled (no HIVE_API_KEY or init failed) — model N/A"
      elsif parts[1].nil?
        puts "model: #{hivemind.model} (configured in config-hivemind.yaml)"
        puts "available: #{hivemind.models.join(', ')}"
        puts "usage: /model <model-id>"
      else
        model = parts[1..].join(' ').strip.gsub(/\A["']|["']\z/, '')
        puts hivemind.switch_model!(model)
      end
    when '/try'
      hivemind = plugins[:hivemind]
      if hivemind.nil?
        puts "hivemind disabled — cannot try"
      elsif parts[1].nil?
        puts "usage: /try <model> [message]  — e.g. /try gpt-4o hivemind how is the factory?"
        puts "       replays last trigger with MODEL one-off (not persisted, not sent to game)"
      else
        model = parts[1].strip.gsub(/\A["']|["']\z/, '')
        msg = parts[2..]&.join(' ')
        msg = nil if msg && msg.strip.empty?
        puts hivemind.try_model!(model, msg)
      end
    when '/simulate'
      # Test the translation backend directly: translate MSG from LANG to English.
      # Usage: /simulate <player_name> <language_code> <message>
      # (player_name is decorative — the backend has no per-player state.)
      translation = plugins[:translation]
      if translation.nil?
        puts 'translation agent not enabled — cannot simulate'
        return
      end
      if parts[1].nil? || parts[2].nil?
        puts 'usage: /simulate <player_name> <language_code> <message>'
        puts 'example: /simulate dlruen ru "Zdravstvuyte"'
        return
      end
      player_name = parts[1]
      lang_code = parts[2]
      # Rejoin the rest as the message (may contain spaces); strip wrapping
      # quotes so the documented `... "some text"` form works.
      msg = parts[3..]&.join(' ')&.gsub(/\A["']|["']\z/, '')
      if msg.nil? || msg.strip.empty?
        puts 'usage: /simulate <player_name> <language_code> <message>'
        return
      end
      begin
        translated = translation.simulate_translation(player_name, lang_code, msg)
        puts "[simulate] player=#{player_name} lang=#{lang_code} msg='#{msg}' => translated='#{translated}'"
      rescue StandardError => e
        warn "[simulate] error: #{e.class}: #{e.message}"
      end
    when '/locales'
      if @player_db.nil?
        puts 'no player db — cannot manage locale overrides'
      elsif parts[1].nil?
        # bare /locales: list every override
        all = @player_db.all_locale_overrides
        puts all.empty? ? 'no locale overrides' : all.map { |n, l| "#{n}: #{l.join(',')}" }.join("\n")
      elsif parts[2].nil?
        # /locales NAME: show the override
        langs = @player_db.locale_overrides(parts[1])
        puts langs.to_a.empty? ? "#{parts[1]}: no override (game locale used)" : "#{parts[1]}: #{langs.join(',')}"
      else
        # /locales NAME en,pt   or   /locales NAME - (clear)
        if parts[2] == '-'
          @player_db.set_locale_overrides(parts[1], [])
          puts "/locales #{parts[1]}: cleared"
        else
          langs = parts[2..].join(',').split(',').filter_map { |l|
            b = l.split('-').first&.downcase&.strip
            b unless b.empty?
          }.uniq
          @player_db.set_locale_overrides(parts[1], langs)
          puts "/locales #{parts[1]}: #{langs.join(',')}"
        end
      end
    when '/compact'
      # Compaction is one of Hivemind's own plugins (config-hivemind.yaml
      # `plugins:`); the only other way in is no running agent. Past that
      # compact_memory! itself returns false for a disabled memory store, so
      # the session is kept and nothing is cleared.
      hivemind = plugins[:hivemind]
      unless hivemind&.plugin?(:compaction)
        puts 'memory compaction unavailable (no agent, or the compaction plugin is off in config-hivemind.yaml) — session NOT cleared'
        return
      end
      # Runs in a background thread so the console stays responsive (the
      # compaction LLM call takes seconds; it queues behind any live ask).
      # The session is wiped only after a SUCCESSFUL pass — if compaction
      # is disabled or errors, compact_memory! returns false and the
      # session is kept. Both calls serialize on the agent mutex.
      Thread.new do
        if hivemind.compact_memory!('manual')
          # Trim, don't wipe: drop the messages the pass saw (minus a
          # recent tail kept for flow); mid-pass console lines survive.
          hivemind.trim_session_after_compaction!
        else
          puts 'memory compaction FAILED — session kept (see [hivemind] error above)'
        end
      end
      puts 'memory compaction started — session resets when done (see [hivemind] logs)'
    else
      puts "unknown command #{parts[0]} — try /help"
    end
  rescue StandardError => e
    warn "filter console error: #{e.class}: #{e.message}"
  end
end
