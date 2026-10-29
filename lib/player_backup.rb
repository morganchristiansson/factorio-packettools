# frozen_string_literal: true

require 'json'

# Player backup — the file is lib/player_backup.rb, the class takes its
# CamelCase name, and it is listed in config.yaml `plugins:`. Nothing in the
# sniffer names it: Plugins.features builds every listed class and pushes
# `on_join_enriched` at the ones that implement it.
#
# What it keeps, per player, keyed by NAME, in `players-backup.json` next to
# the process cwd (the players-cache.json convention, and no configuration of
# its own):
#
#   quickbar  the 10×10 grid
#   color     LuaPlayer.color as [r, g, b, a]
#   online_time  ticks played on EARLIER saves — the base added to the live
#                total (see #sync_times)
#
# WHY a side file, keyed by name: players-cache.json's per-player state is
# per-savefile — game indexes are handed out in join order and reset when the
# save does, so index 42 on a new map is a different person. A name is the
# only thing that survives the save, so this file's lifetime is longer than any
# single save's. That matters most for the quickbar, which the save does NOT
# carry (verified: no encoding of the slot ids appears anywhere in it), so a
# bar has to be restored from here or it is lost.
#
# WHEN: once at startup, from ONE query over the WHOLE roster (see #on_start)
# — every player the save knows, offline included, so a save change cannot
# take a bar we never heard of. Then on every confirmed join, from the ONE
# RCON query the sniffer already makes for the joiner (see
# RconClient#player_attributes_for, which reads the whole bar and the colour).
# Their in-game bar is the truth:
#   * they have one  → snapshot it, which is also how a player who edited
#     their bar mid-session gets the new one saved;
#   * they have none but we do → write it back over RCON, then bring the
#     in-memory cache in line with the game.
#
# The COLOUR: the current save carries its own copy (four f32s in front of
# the player's name — docs/save/level-dat.md), so mid-session it only needs
# snapshotting (they can re-pick it any time — the set_player_color action,
# ~25 samples/second while the picker is open, hence the no-op-if-unchanged
# check). But a NEW save has no copy: the player is handed a palette colour
# by index. `LuaPlayer.color` is writable, so #restore puts ours back with
# the bar, in the same one RCON command.
#
# No RCON, no backup: the event is simply not acted on (client mode, or RCON
# down), and the file is only read when there is something to restore. Other
# events (Plugins::Feature) are inherited no-ops.
class PlayerBackup
  FILENAME = 'players-backup.json'
  # Every key one record may carry. Anything else in the file is dropped on
  # read, so a typo'd field cannot masquerade as data.
  FIELDS = %w[quickbar color chat_color online_time online_time_seen].freeze

  # Predefined /color command names → [player_color, chat_color], each as
  # [r, g, b, a] floats 0..1. From the game's utility-constants.player_colors
  # table (external/data-raw-dump.json / core/prototypes/utility-constants.lua).
  # The /color <name> command is the ONLY way to set player_color and
  # chat_color to DIFFERENT values — the RGB form derives chat_color by adding
  # 0.15 to each channel (clamped at 1.0), measured live on 2.1.23:
  #   /color 12 34 56 → color=[0.0471,0.1333,0.2196,0.5],
  #                     chat_color=[0.1971,0.2833,0.3696,1.0]
  # The predefined entries carry hand-tuned chat_color values that do not
  # follow that formula. player color alpha is ALWAYS 0.5 and chat alpha 1.0.
  COLOR_NAMES = {
    'default'  => [[0.869, 0.5, 0.13, 0.5],   [1.0, 0.63, 0.259, 1.0]],
    'red'      => [[0.815, 0.024, 0.0, 0.5],   [1.0, 0.166, 0.141, 1.0]],
    'green'    => [[0.093, 0.768, 0.172, 0.5], [0.173, 0.824, 0.25, 1.0]],
    'blue'     => [[0.155, 0.54, 0.898, 0.5],  [0.343, 0.683, 1.0, 1.0]],
    'orange'   => [[0.869, 0.5, 0.13, 0.5],    [1.0, 0.63, 0.259, 1.0]],
    'yellow'   => [[0.835, 0.666, 0.077, 0.5], [1.0, 0.828, 0.231, 1.0]],
    'pink'     => [[0.929, 0.386, 0.514, 0.5], [1.0, 0.52, 0.633, 1.0]],
    'purple'   => [[0.485, 0.111, 0.659, 0.5], [0.821, 0.44, 0.998, 1.0]],
    'white'    => [[0.8, 0.8, 0.8, 0.5],       [0.9, 0.9, 0.9, 1.0]],
    'black'    => [[0.1, 0.1, 0.1, 0.5],       [0.5, 0.5, 0.5, 1.0]],
    'gray'     => [[0.4, 0.4, 0.4, 0.5],       [0.7, 0.7, 0.7, 1.0]],
    'brown'   => [[0.3, 0.117, 0.0, 0.5],      [0.757, 0.522, 0.371, 1.0]],
    'cyan'     => [[0.275, 0.755, 0.712, 0.5], [0.335, 0.918, 0.866, 1.0]],
    'acid'     => [[0.559, 0.761, 0.157, 0.5], [0.708, 0.996, 0.134, 1.0]],
  }.freeze

  # `host` is the sniffer (Plugins hands every feature its owner): the two
  # things this one needs are on it, and either may be nil — no RCON, no
  # backup.
  #
  # `path:` is the same dependency injection every other file-backed class
  # here takes (PlayerDatabase.new(path), MemoryStore.new(dir)): the file to
  # keep is a CONSTRUCTOR argument, not a baked-in constant, so a caller (a
  # test, or two features with two files) names its own instead of the whole
  # process chdir'ing into a scratch directory to get out of the way.
  def initialize(host, path: FILENAME)
    @rcon = host.rcon
    @player_db = host.player_db
    @player_attrs = host.respond_to?(:attrs) ? host.attrs : nil
    @path = path
    @mutex = Mutex.new # one join at a time + the file write (see #persist)
  end

  # A player changed their colour mid-session (the set_player_color action,
  # 4 UNORM bytes — see FactorioPacketTools#log_action). The game and the
  # save keep their own copy, so this is a snapshot like every other colour
  # here: it just keeps the file current between joins instead of at the next
  # one. The picker sends ~25 samples/second while it is open, so the
  # no-op-if-unchanged check in #note_color is load-bearing, not a nicety.
  #
  # `rgba` is already [r,g,b,a] floats 0..1 (FactorioPacketTools#on_player_color
  # converts the wire bytes). Measured on 2.1.23: the action's 4th byte is
  # IGNORED (0, 127 and 255 all leave the player colour alpha at 0.5) and the
  # action sets BOTH colours: color = RGB + alpha 0.5, chat_color = color +
  # 0.15 (clamped) + alpha 1.0. So the wire alpha must not be stored as sent.
  def on_player_color(name, rgba)
    return unless rgba.is_a?(Array) && rgba.length == 4
    color = [rgba[0], rgba[1], rgba[2], 0.5]
    note_color(name, color, chat_color_for(color))
  end

  # A /color console command, arriving as chat (write_to_console). Verified
  # independent of the set_player_color action: /color is a chat message the
  # player types; set_player_color is the color-picker GUI action. They never
  # co-occur (captures: 4 /color commands from player 8, 0 set_player_color
  # actions in that capture; 182 set_player_color from player 122 in a
  # different capture). /color sets BOTH color and chat_color (they differ —
  # only predefined names allow independent values; RGB derives chat_color
  # by adding 0.15 to each channel).
  # :factorio source only — /color typed in Discord or by Hivemind must not
  # move the backup. Player_N names are dropped: they are unbound indexes,
  # not real players.
  def on_chat(source, author, text, _player_id = nil)
    return unless source == :factorio
    return if author.nil? || author.start_with?('Player_')
    result = parse_color_command(text)
    return unless result
    player_color, chat_color = result
    note_color(author, player_color, chat_color)
  end

  # Startup (see FactorioPacketTools#on_start): ONE query for the whole
  # roster and a snapshot of everyone in it, joined or not. Without this the
  # file only ever learns about players who join AFTER we start — on a
  # long-running server that is nobody who played before us, and their bars
  # are exactly the ones a save change takes away. The roster goes through
  # helpers.write_file, so its size (a 300-player server × 100 slots) costs
  # nothing but disk.
  #
  # Same rules as the join path: an empty bar teaches us nothing (we keep
  # what we have — that is the whole point of this file), and a :failed read
  # (an offline player whose getter raises) is not an empty bar. The join
  # query still runs and still overwrites: it is the only source for a bar
  # edited mid-session, and it reads the same Lua this does, so a player in
  # both must come back identical.
  def on_start
    return unless @rcon
    roster = @rcon.roster_backup
    return if roster.nil? || roster.empty?
    bars = colors = chat_colors = 0
    times = []
    @mutex.synchronize do
      roster.each do |p|
        name = p[:name].to_s
        next if name.empty?
        times << [name, p[:online_time]] # o= in the roster Lua — the live total
        rec = (records[name] ||= {})
        color = p[:color]
        if color.is_a?(Array) && color.length == 4 && rec['color'] != color.map(&:to_f)
          rec['color'] = color.map(&:to_f)
          colors += 1
        end
        chat_color = p[:chat_color]
        if chat_color.is_a?(Array) && chat_color.length == 4 && rec['chat_color'] != chat_color.map(&:to_f)
          rec['chat_color'] = chat_color.map(&:to_f)
          chat_colors += 1
        end
        bar = p[:quickbar]
        next if bar == :failed # the getter raised: not an empty bar, nothing to save
        next unless filled?(bar) && rec['quickbar'] != copy(bar)
        rec['quickbar'] = copy(bar)
        bars += 1
      end
      persist if bars + colors + chat_colors > 0 # one write for the whole roster, not one per player
    end
    # outside the lock (sync_times takes it) — one write for the roster
    sync_times(times)
    puts "[player-backup] roster snapshot: #{roster.size} players, #{bars} bar(s), #{colors} colour(s), #{chat_colors} chat-colour(s) saved"
  end

  # The event (see FactorioPacketTools#on_join_enriched). Runs on the join
  # thread, so the restore is a blocking RCON call on a thread that is there
  # for it.
  def on_join_enriched(name, index, attrs)
    return unless @rcon
    saved = saved_record(name) # read BEFORE we overwrite anything
    # Play time first, before any :failed return below: it is independent of
    # the bar. A name in the returned list is a save change (see #sync_times).
    new_save = sync_times([[name, attrs[:online_time]]]).include?(name.to_s)
    # A save change hands the player the game's DEFAULTS: a starting
    # quickbar and a palette colour. Both are perfectly valid values, so
    # neither the "empty bar" rule below nor a snapshot can tell them apart
    # from state the player chose — snapshotting here would overwrite the
    # backup with the defaults, and restoring them later would be restoring
    # the defaults forever. The play-time clock is the one thing that knows,
    # so it gates the restore, and the snapshot is skipped: what we put back
    # is what the game ends up holding, so the file and the game still agree.
    return if new_save && restore(name, index, saved)
    note_color(name, attrs[:color], attrs[:chat_color])
    # nil is the join query's "empty bar" (the payload always carries the
    # key); only :failed, the Lua read raising, means we do not know
    return if attrs[:quickbar] == :failed
    bar = attrs[:quickbar]
    if filled?(bar)
      save_quickbar(name, bar)
    elsif saved && filled?(saved['quickbar'])
      restore(name, index, saved)
    end
  end

  # Player LEFT the game (clean quit in either direction, or the heartbeat
  # watchdog) — the live total is already folded into PlayerAttrs, last
  # chance to record what this save is worth.
  #
  # The sniffer hands us PlayerAttrs' FULL total: this-save ticks PLUS the
  # earlier-saves base that PlayerBackup itself keeps and PlayerAttrs adds
  # back on read. But `seen` tracks the GAME's own p.online_time — this-save
  # only — so a drop under `seen` means the save restarted, not the base
  # inflating the mirror. Stripping the base is what makes the leave value a
  # this-save lower bound again (the assumption sync_times relies on):
  # without it, a leave+rejoin of the SAME save looks like a drop (the base
  # lifts `seen` past what the game reports) and the player's bar and colour
  # get restored on every reconnect instead of only on the first join of a
  # new save.
  def on_player_event(kind, name, _reason = nil, ticks = nil)
    return unless kind == :left
    # A leave (clean :quit or :timeout) — the sniffer hands PlayerAttrs'
    # FULL live total (this-save + the earlier-saves base that PlayerAttrs
    # adds back on read, folded by disconnect first). reason is ignored: a
    # timeout is still a leave the save clock has stopped on. Stripping our
    # own base recovers this-save ticks (the assumption sync_times relies on).
    this_save = ticks.to_i - base_ticks(name)
    sync_times([[name, this_save]], exact: false)
  end

  # Fold the game's live play times (name → ticks; a whole roster is fine)
  # into the stored high-water mark. A live total that DROPPED means the
  # save's own clock restarted — a new save, a new map — and everything the
  # old save had that this one hasn't yet becomes a base, added to the live
  # total on read (PlayerAttrs#online_time_ticks). The game cannot be told
  # about a base: LuaPlayer.online_time is read-only, which is the whole
  # reason this file exists. Same name-keyed accumulator the Biter Battles
  # scenario keeps in its `session` global (utils/datastore/session_data.lua)
  # with their web panel in the middle; we are the panel.
  #
  # WHY a drop, and whose: the game's own `p.online_time` cannot fall inside one
  # save — it only accumulates while the player is connected — so a drop in
  # an EXACT number (roster snapshot, join query; both read it over RCON)
  # means the save's clock restarted, and everything the old save had that
  # this one hasn't yet becomes a base. Our own mirror (PlayerAttrs, what a
  # leave reports) is NOT exact: a player we never seeded from RCON has a
  # base of 0 there, so it undercounts, and treating ITS drop as a reset
  # would invent play time. Hence `exact: false` — a mirror number may push
  # the mark up (it can only know more, never less) but never lower it, so
  # every reset is read off the game. Wrong direction by design: a missed
  # reset loses time, a false one invents it.
  #
  # Within one save the mark only rises, so nothing is written on every sync:
  # a roster snapshot of 300 players is one file write, and a re-sync with
  # unchanged numbers is none.
  # the file carries). Returns the names whose clock RESTARTED at this sync
  # (empty on a normal one) — a join that sees its own name in the list knows
  # the game just handed it the defaults of a new save.
  def sync_times(pairs, exact: true)
    bases = {}
    resets = []
    @mutex.synchronize do
      changed = false
      pairs.each do |name, live|
        name = name.to_s
        next if name.empty?
        live = live.to_i
        rec = (records[name] ||= {})
        seen = rec['online_time_seen']
        dropped = seen && live < seen.to_i && exact
        base = rec['online_time'].to_i + (dropped ? seen.to_i - live : 0)
        bases[name] = base
        resets << name if dropped
        next if seen == live || (seen && !exact && live <= seen.to_i)
        rec['online_time'] = base
        rec['online_time_seen'] = live
        changed = true
      end
      persist if changed # one write for the whole batch, not one per player
    end
    @player_attrs&.set_foreign_bases(bases) unless bases.empty?
    resets
  end

  # The base (ticks from earlier saves) alone — what the online_time total is
  # this much bigger than the save's own.
  def base_ticks(name)
    @mutex.synchronize { (records[name.to_s] || {})['online_time'].to_i }
  end

  # Everything we keep for a name, or nil: {"quickbar" => …, "color" => […]}.
  def [](name)
    saved_record(name)
  end

  # The saved bar alone (what the quickbar side of this file is for).
  def saved_bar(name)
    saved_record(name)&.fetch('quickbar', nil)
  end

  private

  # ── the name-keyed file ───────────────────────────────────────────

  # One copy per field: the caller keeps editing what it handed us.
  def saved_record(name)
    return nil if name.to_s.empty?
    rec = @mutex.synchronize { records[name.to_s] }
    return nil unless rec.is_a?(Hash) # someone we have never seen (a copy of
                                      # {} would be truthy)
    rec.merge('quickbar' => rec['quickbar'] && copy(rec['quickbar']),
              'color' => rec['color'] && rec['color'].dup,
              'chat_color' => rec['chat_color'] && rec['chat_color'].dup)
  end

  # The colour reported by either the set_player_color action (color picker —
  # both colours, derived from RGB) or a /color console command. The game and
  # the save keep their own color copy, so this is a snapshot, never a
  # restore — it just keeps the file current between joins. chat_color is
  # optional (nil when the source didn't provide it, e.g. an older caller).
  def note_color(name, color, chat_color = nil)
    return unless color.is_a?(Array) && color.length == 4
    @mutex.synchronize do
      rec = (records[name.to_s] ||= {})
      changed = false
      if rec['color'] != color.map(&:to_f) # unchanged: no write
        rec['color'] = color.map(&:to_f)
        changed = true
      end
      if chat_color.is_a?(Array) && chat_color.length == 4 && rec['chat_color'] != chat_color.map(&:to_f)
        rec['chat_color'] = chat_color.map(&:to_f)
        changed = true
      end
      persist if changed
    end
  end

  # Parse a /color console command from chat text into
  # [player_color, chat_color], each [r,g,b,a] floats 0..1, or nil.
  #   /color red           → named lookup from COLOR_NAMES (both values differ)
  #   /color 255 0 0       → RGB: alpha is ALWAYS 0.5; chat_color = RGB + 0.15
  #   /color 255 0 0 255   → the 4th value is IGNORED by 2.1.23 (0, 1, 127
  #                          and 255 all leave alpha at 0.5 and chat unchanged):
  #                          measured with the observer client + RCON.
  # Verified: /color 255 0 0 → color=[1,0,0,0.5], chat_color=[1,0.15,0.15,1];
  # /color 12 34 56 → color=[0.0471,0.1333,0.2196,0.5],
  #                   chat_color=[0.1971,0.2833,0.3696,1.0].
  # chat_color is color + 0.15 per channel, clamped to 1.0 (NOT a 0.15 floor:
  # a 0 channel becomes 0.15, a 0.5 channel becomes 0.65). Named colors bypass
  # the formula — their chat_color is hand-tuned in the table.
  def parse_color_command(text)
    return nil unless text
    m = text.match(/\A\/color\s+(\S+)/i)
    return nil unless m
    arg = m[1]
    return COLOR_NAMES[arg] if COLOR_NAMES.key?(arg)
    return nil unless text.match?(/\A\/color\s+\d/) # not RGB — not a /color we recognize
    nums = text.match(/\A\/color\s+(\d+)\s+(\d+)\s+(\d+)/)
    return nil unless nums
    color = [nums[1..3].map { |v| v.to_f / 255.0 }, 0.5].flatten
    [color, chat_color_for(color)]
  end

  # Chat tint the game derives from a /color RGB or set_player_color action:
  # each channel + 0.15, capped at 1.0, alpha 1.0 (measured on 2.1.23).
  def chat_color_for(color)
    [color[0, 3].map { |c| [c + 0.15, 1.0].min }, 1.0].flatten
  end

  def save_quickbar(name, bar)
    @mutex.synchronize do
      rec = (records[name.to_s] ||= {})
      rec['quickbar'] = copy(bar)
      persist
    end
  end

  # A copy of the stored grid: the caller keeps editing the one it handed us.
  def copy(grid)
    Array(grid).map { |slots| slots.is_a?(Array) ? slots.dup : slots }
  end

  def filled?(bar)
    Array(bar).flatten.compact.any?
  end

  # ── restore ──────────────────────────────────────────────────────

  # Put back everything we saved, in ONE RCON command (RconClient#
  # restore_player): the quickbar cells and the colours, each only if we have
  # it. True when something was written. Called for a player joining a NEW
  # save (the game's defaults are not what they chose) and for one joining
  # with an empty bar.
  #
  # Both LuaPlayer.color AND LuaPlayer.chat_color are restored: the game
  # hands out its own palette colour for both on a new save, and chat_color
  # does NOT inherit from color — a restored color with no chat_color leaves
  # the game's default chat colour, which may not be what the player chose.
  # Records written before chat_color existed (or by an old build) fall back
  # to the game's own derivation from color: channel + 0.15, capped at 1.0.
  def restore(name, index, saved)
    return false unless saved.is_a?(Hash)
    bar = filled?(saved['quickbar']) ? saved['quickbar'] : nil
    color = saved['color'].is_a?(Array) && saved['color'].length == 4 ? saved['color'] : nil
    chat_color = saved['chat_color'].is_a?(Array) && saved['chat_color'].length == 4 ? saved['chat_color'] : nil
    chat_color ||= chat_color_for(color) if color
    return false unless bar || color || chat_color
    cells = cells_of(bar || [])
    done = @rcon.restore_player(name, cells, color: color, chat_color: chat_color)
    if bar
      if done == cells.size
        puts "[player-backup] #{name}: restored #{done} slot(s) from #{PlayerBackup::FILENAME}"
      else
        version = @rcon.server_version || 'unknown version'
        warn "[player-backup] #{name}: restored #{done}/#{cells.size} slot(s) — #{version} rejected the rest?"
      end
    end
    puts "[player-backup] #{name}: restored colour #{Array(color).join(',')}" if color
    puts "[player-backup] #{name}: restored chat colour #{Array(chat_color).join(',')}" if chat_color
    # the game now holds it; so must the cache
    @player_db&.replace_quickbar(index, bar) if bar
    @player_db[index] = { color: color } if color && @player_db
    true
  end

  # 10×10 grid → {flat slot index (1..100) => item id}, the form the setter
  # command takes.
  def cells_of(bar)
    cells = {}
    bar.each_with_index do |slots, page|
      Array(slots).each_with_index do |item, slot|
        cells[(page * PlayerDatabase::QUICKBAR_SLOTS) + slot + 1] = item if item
      end
    end
    cells
  end

  # ── state ────────────────────────────────────────────────────────

  def records
    @records ||= load_records
  end

  # Reads the current file. Unreadable or corrupt: start empty, the next join
  # with a bar refills it. There is NO copy of this file: it is the one
  # artifact here that cannot be rebuilt from anywhere else, so copy it by
  # hand (`cp players-backup.json{,.bak}`) when starting a new save.
  def load_records
    return {} unless File.exist?(@path)
    JSON.parse(File.read(@path)).each_with_object({}) do |(name, rec), out|
      next unless rec.is_a?(Hash)
      out[name.to_s] = rec.select { |k, _v| FIELDS.include?(k) }
    end
  rescue JSON::ParserError, SystemCallError
    {}
  end

  # Assumes the mutex is held (called from #save). Same temp+rename as
  # players-cache.json: a crash mid-write must not leave a file that would
  # then be read back as "this player's bar is empty".
  def persist
    path = @path
    tmp = "#{path}.tmp"
    File.write(tmp, JSON.pretty_generate(records))
    File.rename(tmp, path)
  rescue StandardError => e
    warn "#{@path} save failed: #{e.class}: #{e.message}"
  end
end
