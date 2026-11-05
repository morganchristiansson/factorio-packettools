# frozen_string_literal: true

require 'time'
require 'tmpdir'
require_relative 'factorio_protocol/disconnect_reason'
require_relative 'factorio_protocol'
require_relative 'item_db'
require_relative 'player_db'
require_relative 'pcap'
require_relative 'live_capture'
require_relative 'rcon_client'
require_relative 'log_tail'
require_relative 'plugins'
require_relative 'server_detect'
require_relative 'player_attrs'
require_relative 'console'
require_relative 'action_presenter'

# ─────────────────────────────────────────────────────────────────────
# Main Application
# ─────────────────────────────────────────────────────────────────────
class FactorioPacketTools
  # How far past the known roster a player index may sit before it counts as
  # a desync rather than a player we have no name for. Used only when strict
  # player-id checking is OFF (offline replay by default): on the 2026-10-03
  # set, 10,036 packets were flagged for index 357 and 736 for 360 — both
  # real players (both chatting under their Player_N placeholders), just past
  # the last index this cache names. A real desync throws the index thousands
  # of places away (33024, 53354). Live capture uses membership instead
  # (config `strict_player_ids:`): the roster is seeded from RCON or the save,
  # so an id with no cache entry is real evidence of a misdecode.
  UNKNOWN_PLAYER_WINDOW = 100

  # Always-on capture rotation defaults (hardcoded — config.yaml can
  # override). Without ANY bound the active capture grows forever (observed:
  # a 511 MB server-34197.pcap plus 2.9 GB of never-pruned restarts) and
  # rotation only happened on restart. Three independent bounds, three
  # knobs: rotate hourly or at `rotate_size`, keep for `keep` hours, and
  # keep the rotated files under `max_size` MB in total.
  DEFAULT_KEEP_HOURS = 72
  DEFAULT_ROTATE_SIZE_MB = 256
  DEFAULT_MAX_SIZE_MB = 512

  def initialize(options, pcap_writer: nil, unknown_pcap_writer: nil)
    # What lands in the pcap is ONE axis (was two half-overlapping flags):
    #   normal — filtered (drop keepalive-only heartbeats, server-mode
    #            outgoing broadcasts, msg 13 map-download blocks)
    #   full   — record everything
    #   save   — record ONLY the msg 13 TransferBlocks, for
    #            tools/extract_save_from_pcap.rb
    @capture_mode = (options[:capture] || 'normal').to_s
    raise ArgumentError, "capture: #{@capture_mode.inspect} (normal, full, save)" unless
      %w[normal full save].include?(@capture_mode)
    @options = options
    @player_db = PlayerDatabase.new(options[:player_db])
    # A decoded player index with no players-cache entry is a misdecode when
    # the roster is authoritative (live server RCON / a save seed). Offline
    # replay defaults to the old far-outside-the-roster rule because an old
    # capture and today's cache need not describe the same world; set
    # `strict_player_ids: true` there when the roster IS known to match.
    @strict_player_ids = options.key?(:strict_player_ids) ? !!options[:strict_player_ids] : !options[:pcap]
    # Until a roster source has actually spoken, an empty cache is not a
    # reason to call every player invalid (client mode learns the roster from
    # the map download after joining).
    @roster_ready = @player_db.players.any?
    # The roster of the CURRENT save (RCON's game.players: every player of
    # this savefile, offline included) as an ARRAY of names in index order:
    # the game hands out the indexes sequentially, so game index N is
    # roster[N-1] (a hole = no player at that index). A join is accepted
    # when its index is one of these (a returning player) or above the
    # highest one (a new player). Without it a stale cache from another save
    # decides, and every join is rejected as a misdecode.
    @roster = []
    @stats = { packets: 0, factorio_packets: 0, actions: 0, outgoing_skipped: 0, capture_skipped: 0,
               bad_string: 0, unknown: 0, desync: 0, decode_error: 0, invalid_player: 0,
               duplicate_s2c: 0, invalid_join: 0 }
    @unknown_names = {} # undecoded action type -> how often we saw it
    @invalid_player_ids = {} # invalid player index -> how often we flagged it
    @invalid_join_keys = {} # misdecoded join (kind:id) -> already warned
    @disk_seed_started = false # client-mode disk-save fallback decision made
    @join_seen = false # this client connected while we were watching
    @client_state = nil # last ClientChangedState seen from our client
    @max_peer_id = nil # highest S→C peer id, for NewPeerInfo validation
    @fed_action_sigs = {} # tick => action signature already sent to the validator
    # log_path: explicit factorio-current.log from config.yaml (nil = auto-detect
    # in #start_log_watcher). The host keeps ONE tailer thread that emits
    # :on_log_line to the plugin bus instead of each feature tailing the file.
    @log_path = options[:log_path]
    @log_thread = nil
    # Capture is ALWAYS on for live capture (auto-named + rotated); pcap-read
    # analysis (-r) doesn't re-capture. Auto-naming writes timestamped files
    # directly (captures/server-<port>-<ts>.pcap) — the latest file IS the
    # live one, no renames, no stable path. Restarts just open a new file.
    # Client mode defers until the first packet reveals the server identity.
    # Tests inject a fake writer via the pcap_writer: kwarg (dependency
    # injection, not config).
    @pcap_writer = pcap_writer
    @pending_capture = nil
    if !options[:pcap] && !@pcap_writer
      dir = default_capture_dir
      if options[:server]
        port = @options[:port]
        id = "server#{port ? "-#{port}" : ''}"
        @pcap_writer = new_pcap_writer(capture_path(dir, id))
        puts "capturing to #{@pcap_writer.path}#{retention_hint}"
      else
        @pending_capture = dir  # client: resolve the server identity on the first packet
      end
    end
    # Protocol-development capture is always on. Keep this separate from the
    # normal rolling capture so decoder failures can be replayed later.
    unknown_path = File.join(default_capture_dir, 'unknown.packets.pcap')
    # Tests inject a fake here too (same kwarg pattern as pcap_writer):
    # a real writer means one empty unknown.packets-<ts>.pcap per test run,
    # dropped in the repo's captures/ and never closed.
    @unknown_writer = unknown_pcap_writer ||
                      PcapWriter.new(unknown_path, keep: effective_keep,
                                     rotate_size: effective_rotate_size, max_size: effective_max_size,
                                     timestamped: true)
    puts "saving unknown packets to #{@unknown_writer.path}"
    @item_db = nil
    if options[:item_db] && File.exist?(options[:item_db])
      @item_db = ItemDB.new(options[:item_db])
    end
    @entity_db = nil
    if options[:entity_db] && File.exist?(options[:entity_db])
      @entity_db = ItemDB.new(options[:entity_db])
    end
    @presenter = ActionPresenter.new(item_db: @item_db, entity_db: @entity_db,
                                     dump_raw_types: !!@options[:dump_raw_types])
    # Self (this client) tracking: we learn our own username from the
    # ConnectionRequestReplyConfirm and our own game player index from our
    # outgoing (C→S) heartbeat actions. This lets us correct the peer-id
    # based guesses from ConnectionAcceptOrDeny / NewPeerInfo, which use
    # NETWORK peer ids — those only equal game indexes for new joiners.
    @self_ip = nil
    @self_name = nil
    # peer_id (network) -> name, for join/leave events (peer ids are NOT
    # game indexes; game indexes come from heartbeat actions instead).
    @peer_names = {}
    # The live roster lives entirely in @attrs (PlayerAttrs): "online" ==
    # record with :connected. One structure, one lock.
    # src_ip → [name, confirmed]: every player seen connecting (msg 4
    # username), flipped to confirmed once their first C→S heartbeat action
    # binds a game index. Liveness touches use it; join/leave EVENTS come
    # only from the server-verified S→C roster actions.
    @ip_names = {}
    # S→C broadcast dedupe: canonical UDP payload -> last seen capture ts.
    @s2c_seen = {}
    # Names already announced by the S→C player_join_game broadcast (one
    # :joined per join, even if per-client heartbeat variants repeat it).
    @s2c_joined = {}
    # Cross-packet chat segment reassembly buffer: [player, total_segs] =>
    # {seg_no => payload}. Split chat messages arrive as separate
    # input-action segments across packets; merged when complete.
    @chat_segments = {}
    # Mirrored LuaPlayer attributes (connected/online_time/afk_time):
    # seeded once from RCON, maintained by packet decoding.
    # Admin status lives in PlayerDatabase (players-cache.json). See PlayerAttrs.
    # Also owns the live roster (connected records).
    @attrs = PlayerAttrs.new
    # Latest game tick observed in heartbeat tick closures — the clock for
    # lazy online_time computation (60 ticks/s, tick is in every closure).
    @game_tick = 0
    # Features (config.yaml `plugins:`): one Plugins object for this owner,
    # which builds them from the list and dispatches what we emit below.
    # This file names none of them. hivemind and translation are objects
    # this host drives, not features it emits to. MODE-INDEPENDENT and
    # outside any mode block: the packet path emits on_player_color in
    # every mode (pcap replay included), so @plugins must always exist.
    # Every listed name is a feature: PluginSet builds it lazily on the
    # first event/access. Hivemind's sniffer-specific bits — its live tick
    # provider and the sniffer's own plugin list (for the tool gate) — are
    # handed down as the feature's constructor kwargs via the args: slot.
    listed = Array(options[:plugins]).map { |n| n.to_s.to_sym }
    @plugins = Plugins::PluginSet.new(listed, self, args: {hivemind: {current_tick: -> { @game_tick }, sniffer_plugins: options[:plugins]}})
    # Interactive filters + command surface. The packet host only asks the
    # filter; plugin commands stay in the console for now.
    @console = Console.new(self, player_db: @player_db, plugins: -> { @plugins },
                           debug: !!@options[:debug])
    # IP identity is packed bytes (PcapFormat); this host's configured IPs
    # are the filter key in both modes. Server mode may auto-detect later.
    @host_ip_keys = Array(options[:host_ips]).to_h { |ip| [PcapFormat.ip_bytes(ip), true] }
    # Server mode: this host IS the game server. Classify packet direction
    # by comparing src/dst against our own IPs and analyze ONLY incoming
    # (client→server) traffic — the outgoing direction is a broadcast of
    # every action to all N clients (N duplicates per action).
    if options[:server]
      # This host's IPs: the configured `ip:` (the entry point normalizes
      # it into :host_ips) or the auto-detected list; else all local IPv4s.
      @host_ips = (options[:host_ips] || []).dup
      @host_ips = ServerDetect.local_ipv4 if @host_ips.empty?
      @host_ip_keys = @host_ips.to_h { |ip| [PcapFormat.ip_bytes(ip), true] }
      # src_ip -> username, learned from ConnectionRequestReplyConfirm (msg 4,
      # incoming). Bound to the real game index by the client's first C→S
      # heartbeat action below. (@ip_names, defined above for all modes.)
      # RCON roster: authoritative {name -> index} for players connected at
      # startup. Loaded once before capture; players who join later are
      # learned from the packet stream (msg 4 + first C→S heartbeat).
      @rcon = nil
      if options[:rcon] && !options[:no_rcon]
        begin
          @rcon = RconClient.new(**options[:rcon])
        rescue => e
          warn "RCON roster disabled: #{e.class}: #{e.message}"
          @rcon = nil
        end
      end
      # Item/entity name lookup: explicit --item-db / --entity-db files win;
      # otherwise dump both from RCON via helpers.write_file and read them
      # back from script-output (`prototypes.<kind>` iteration order = wire
      # ids; `game.*_prototypes` does not exist at runtime). See
      # docs/rcon-knowledge.md.
      if @rcon && @rcon.script_output_dir
        begin
          @rcon.dump_prototype_files
          unless @item_db
            f = File.join(@rcon.script_output_dir, 'factorio-packettools-items.txt')
            if File.exist?(f) && File.size(f) > 0
              @item_db = ItemDB.new(f)
              puts "Item DB populated from RCON: #{@item_db.size} items"
            end
          end
          unless @entity_db
            f = File.join(@rcon.script_output_dir, 'factorio-packettools-entities.txt')
            if File.exist?(f) && File.size(f) > 0
              @entity_db = ItemDB.new(f)
              puts "Entity DB populated from RCON: #{@entity_db.size} entities"
            end
          end
        rescue => e
          warn "Prototype DB from RCON failed: #{e.class}: #{e.message}"
        end
      end
      # Optional features: plugin FEATURES in @plugins (built lazily by
      # PluginSet); the sniffer holds no feature ivars to carry over or
      # re-point.
      # Hivemind AI agent: reads packet-decoded chat and answers players who
      # say "hivemind". Needs the `hivemind` plugin (config.yaml `plugins:`)
      # AND server mode with RCON plus a key for its startup model — the
      # constructor enforces those (missing → "[plugin] hivemind disabled"
      # warn; nothing builds), like any feature. Context comes from the
      # packet-derived @attrs cache (seeded from RCON at startup, maintained
      # by packets); online players and stats are cached. Player admin is
      # stored in PlayerDatabase (players-cache.json); targeted RCON attrs
      # lookups happen once for newly joined players only.
      if @plugins.enabled?(:hivemind) && @rcon
        hivemind = @plugins[:hivemind]
        if hivemind
          hivemind.plugins[:followups]&.ensure_followup_scheduler
          puts "[hivemind] AI agent online — answering chat for \"#{hivemind.triggers.join(', ')}\" (model #{hivemind.model})"
        end
      end

      # Translation agent: auto-translates chat for foreign players. Needs
      # the `translation` plugin; no API key required.
      # Backend and Google API key come from config-translation.yaml
      # (`google_api_key:`) with the env overriding it.
      if @plugins.enabled?(:translation) && @rcon
        if (t = @plugins[:translation])
          backend = t&.backend
          if [:hybrid, :google].include?(backend) && t&.google_api_key?
            puts "[translate] Translation agent online — auto-translating foreign player chat (hybrid: argos + google cloud fallback)"
          else
            puts "[translate] Translation agent online — auto-translating foreign player chat (#{backend} backend)"
          end
        end
      end

      # Discord: relays chat between a Factorio channel and a Discord
      # channel, and lets Discord users address the Hivemind agent. Needs the
      # `discord` plugin + RCON (to post in-game) + DISCORD_TOKEN
      # (env-first) + channel_id from config-discord.yaml. Built as a plugin
      # feature by PluginSet (Discord.new(owner)) — it owns a live gateway
      # thread and reaches the agent through the shared publish_chat relay.
      if @plugins.enabled?(:discord) && @rcon
        begin
          discord = @plugins[:discord]
          # forward_message runs off the capture thread via the bridge's worker
          # (AgentEvents#enqueue); the agent publishes :hivemind replies through
          # the shared publish_chat relay instead of a reply_callback.
          puts "[discord] online — relaying chat with Discord channel #{discord.channel_id}" if discord
        rescue => e
          warn "[discord] disabled: #{e.message}"
        end
      end
    end


  end

  # What a feature gets as its owner: this host, and these are the shared
  # things most features want. Nil is a real answer — no RCON in client mode.
  # `attrs` is the live PlayerAttrs mirror (roster + play time): a feature
  # that keeps a name-keyed base it adds to the totals (player_backup) reads
  # it through set_foreign_bases.
  attr_reader :rcon, :player_db, :attrs, :options

  # THE EVENT CATALOGUE — what the sniffer tells features, and the whole
  # plugin API. Every event is a no-op on Plugins::Feature, so it is emitted
  # unconditionally and a feature implements only the ones it uses: adding a
  # feature never means editing this file, only adding an EVENT does (a
  # no-op on Plugins::Feature plus the emitter here).
  #
  # A player joined and the ONE targeted RCON query for them came back: their
  # name, their bound game index, and attrs (index, name, connected, admin,
  # online_time, afk_time, locale, plus on the join query the whole quickbar:
  # the 10×10 grid, nil for an empty bar, :failed if the Lua read raised).
  # Emitted on the join thread, so a feature may talk to the server here.
  def on_join_enriched(name, index, attrs)
    @plugins.emit(:on_join_enriched, name, index, attrs)
  end

  # A player changed their colour: 4 UNORM bytes from the set_player_color
  # action (2.0 wire 296, 2.1 312) as [r,g,b,a] 0..1. Only RGB is used; the
  # 4th wire byte is ignored by the game (see docs/protocol-notes.md). On the
  # packet thread, and only while the value actually CHANGES — the colour
  # picker sends ~25 samples/second while it is open, so an unchanged colour
  # must not reach the files.
  def on_player_color(name, rgba)
    @plugins.emit(:on_player_color, name, rgba)
  end

  # A new line from the server's factorio-current.log. Tailed by a single
  # host-owned thread (#start_log_watcher, NOT by the features) and fanned
  # out to every consumer over the plugin bus: action_validator (its
  # /toggle-action-logging join) and the Hivemind agent's logwatcher
  # (scenario `event=` lines). One reader thread on the inode, N consumers —
  # replacing the old design where each feature spawned its own LogTail. The
  # tailer thread only calls this; handlers are cheap, so it never blocks the
  # capture loop (which never reads the log).
  def on_log_line(line)
    @plugins.emit(:on_log_line, line)
  end

  # Chat relay hub: the single chat event every chat feature is reached by.
  # publish_chat fans :on_chat to the plugin features — discord, translation
  # and hivemind — all sync-light on_chat that enqueue their blocking work to
  # their OWN workers (emit itself runs on the capture thread). Sources:
  # :factorio (player chat, from log_action), :discord, :hivemind (an agent
  # reply). Each feature self-skips its own source: discord skips :discord;
  # translation translates :factorio in-game chat only (Discord text and
  # Hivemind replies are never re-translated); hivemind skips :hivemind (its
  # replies
  # are already in its conversation context). player_id is the packet's
  # 1-indexed game index (nil for non-Factorio sources): translation needs it
  # for its index-keyed relay, discord and the agent ignore it.
  def publish_chat(source, author, text, player_id: nil)
    @plugins.emit(:on_chat, source, author, text, player_id)
    nil
  end

  # Startup, once the RCON client exists (server mode only): the whole-roster
  # dump — every player the save knows, offline included, with colour and the
  # entire quickbar, in one helpers.write_file query (RconClient#roster_backup).
  # Features that keep per-player state they want for players who joined
  # BEFORE we started (the player_backup plugin's snapshot) seed from this;
  # a join can only ever tell a feature about players who come after.
  def on_start
    @plugins.emit(:on_start)
  end

  # Run the capture/analysis loop. Blocks until the source is exhausted
  # (pcap) or Interrupt is raised (live capture). Does NOT finalize — the
  # entry point calls #finish when actually shutting down.
  def run
    if @options[:server] && @host_ips.empty?
      puts 'Error: server mode could not determine the server IP.'
      puts '  Set `ip: <ip>` in config.yaml to set it explicitly.'
      exit 1
    end

    if @options[:server]
      puts 'SERVER MODE: analyzing only incoming (client→server) packets — no broadcast duplicates'
      puts "  server IP(s): #{@host_ips.join(', ')}"
      puts '  map-download TransferBlocks (save file) excluded from analysis and capture'
      if @pcap_writer && @capture_mode == 'normal'
        puts '  capture: incoming-only + no keepalive-only heartbeats (~20MB per 5h vs ~460MB; `capture: full` records everything)'
      end
    elsif @pcap_writer && @capture_mode == 'normal'
      puts '  capture: TransferBlocks (msg 13) and keepalive-only heartbeats excluded (`capture: full` records everything)'
    end

    # Client mode has no RCON and only sees players who join from now on, so
    # the map download is the only source for the players already in the game.
    if map_download_hook
      puts '  roster: seeded from the map download when we join (the only way to learn the players already here)'
    end

    if @options[:pcap]
      read_pcaps
    elsif @options[:interface]
      # Seed the roster before capturing so existing players' names are
      # known from the start (RCON is authoritative; later joiners are
      # learned from the packet stream).
      load_roster if @rcon
      load_player_attrs if @rcon
      # Server mode has no map download: the disk save is the only startup
      # roster source, so scan it synchronously. Client mode DEFERS it (see
      # maybe_seed_roster_from_disk): a fresh join's map download is the
      # same save and newer, so loading the stale disk copy would be pure
      # redundancy. The disk copy remains the fallback for starting while
      # already in-game (no join => no download) and for a failed download.
      seed_roster_from_disk_save if @options[:roster_save] && @options[:server]
      on_start if @rcon || log_consumers?
      # The single log-tailer thread (emits :on_log_line to the plugin bus).
      # Started after on_start so consumers are built first; idempotent. Needs
      # RCON in server mode (host-side log) OR a configured log_path in client
      # mode (where the player reads the server log).
      start_log_watcher if @rcon || log_consumers?
      @capturer ||= LiveCapture.new(
        interface: @options[:interface],
        port: @options[:port],
        transfer_block_sink: (@capture_mode == 'normal' ? nil : @pcap_writer),
        transfer_block_hook: map_download_hook,
      )
      puts "Listening on #{@options[:interface]} port #{@options[:port]}..."
      puts 'Decoded per-action lines hidden — use /debug (or --debug) to show them (chat + events + warnings always print).' unless @console.debug?
      if (ips = @options[:host_ips].to_a).any?
        puts ips.size > 1 ? "Filtering: #{@options[:server] ? 'to' : 'from'} #{ips.join(', ')}" : "Filtering: #{@options[:server] ? 'to' : 'from'} #{ips.first}"
      end
      @capturer.each_packet { |*args| process_packet(*args) }
    end
  end

  # Finalize the session: summary and close writers.
  # Memory is NOT distilled here — compaction is manual only (`/compact`).
  def finish
    @map_download&.stop
    @plugins[:hivemind]&.close_events
    @plugins[:translation]&.close_events
    @plugins[:discord]&.close
    print_summary
    @pcap_writer&.close
    @unknown_writer&.close
  end

  private

  # The single host-owned tailer for factorio-current.log: one LogTail thread
  # reads the file once and emits each new line to the plugin bus (:on_log_line),
  # so action_validator and the agent's logwatcher share ONE reader instead of
  # each tailing the inode. Path: explicit `log_path:` config, else auto-detected
  def log_consumers?
    @plugins.enabled?(:action_validator) ||
      (@plugins.enabled?(:hivemind) && (@plugins[:hivemind].plugins[:logwatcher] rescue nil))
  end

  # The single host-owned tailer for factorio-current.log: one LogTail thread
  # reads the file once and emits each new line to the plugin bus (:on_log_line),
  # fanned to every consumer (action_validator, hivemind logwatcher). Runs ONLY
  # for live capture — -r replay is offline, so it never tails the log (offline
  # validation against the log is tools/validate_actions.rb). Resolved path
  # cached on the same ivar so a re-check reads the same file instead of
  # another /proc scan. Idempotent: a live thread is left alone.
  def start_log_watcher
    return if @options[:pcap] # -r replay is offline — no log tailing
    @log_path = ServerDetect.log_path if @log_path.nil?
    path = @log_path && File.expand_path(@log_path) # expand ~; YAML keeps it literal
    if path && File.file?(path)
      return if @log_thread&.alive?
      @log_thread = Thread.new do
        LogTail.follow(path) { |line| @plugins.emit(:on_log_line, line) }
      rescue StandardError => e
        warn "[log] tail thread died: #{e.class}: #{e.message}"
      end
      puts "[log] tailing #{path} — feeding log-line consumers (action_validator, logwatcher)"
    else
      warn "[log] no factorio-current.log found (set log_path: in config.yaml) — log-line consumers idle"
    end
  end

  # Whether to persist this packet to the capture file. `capture: full`
  # keeps everything, `capture: save` only the TransferBlocks; the default
  # drops keepalive-only heartbeats (no input actions / sync actions /
  # heartbeat requests — ~40% of packets in a typical session) and keeps the
  # game host's traffic in either direction. Server-mode S→C broadcasts are
  # already deduped before this check, so one copy reaches the file.
  def capture_recordable?(src_ip, dst_ip, udp_data)
    return @capture_mode != 'save' unless @capture_mode == 'normal'
    if @options[:server]
      return false unless @host_ip_keys.key?(dst_ip) || @host_ip_keys.key?(src_ip)
    end
    recordable_heartbeat?(udp_data)
  end

  # Cheap flag-byte check: keep heartbeats that carry heartbeat requests
  # (0x01), a synchronizer action (0x10), or tick closures that are not
  # all-empty (0x02 set, 0x08 clear). Drop pure keepalives. Fragmented
  # heartbeats are always kept (byte 1 is message_id there, not flags).
  def recordable_heartbeat?(udp_data)
    return true if udp_data.bytesize < 2
    return true unless FactorioProtocol.heartbeat_payload?(udp_data)
    return true if (udp_data.getbyte(0) & 0x40) != 0
    f = udp_data.getbyte(1)
    (f & 0x01) != 0 || (f & 0x10) != 0 || ((f & 0x02) != 0 && (f & 0x08) == 0)
  end

  def process_packet(pkt_num, ts, src_ip, dst_ip, sport, dport, udp_data, raw_frame = nil)
    src_ip = PcapFormat.ip_bytes(src_ip)
    dst_ip = PcapFormat.ip_bytes(dst_ip)
    @stats[:packets] += 1

    # Server broadcasts every S→C message once per recipient. The copies are
    # byte-identical apart from the header's random bit (0x20), so keep the
    # first and drop the rest within a short window: one capture record, one
    # analysis pass. TransferBlocks (msg 13) are per-client map-download data,
    # not broadcasts — never dedupe those.
    if @options[:server] && @host_ip_keys.key?(src_ip) &&
       ((udp_data.getbyte(0) || 0) & 0x1F) != 13 && duplicate_s2c?(udp_data, ts)
      @stats[:duplicate_s2c] += 1
      return
    end

    # Client mode auto-named capture: resolve the server IP from the first
    # identifiable packet and create the writer (server mode creates it at
    # init — server-<port>).
    ensure_pcap_writer(src_ip, dst_ip) if @pending_capture

    # RequestForHeartbeatWhenDisconnecting (msg 14) is a C→S header-only
    # quit request. It is not an event source: the server-verified S→C
    # player_leave_game action is the reliable leave signal.
    return if (udp_data.getbyte(0) & 0x1F) == 14

    # Server mode: the server already has the save on disk, so the map
    # download (msg 13 TransferBlocks, ~40 MB per joining player) is dropped
    # entirely — no analysis, no capture. Avoids capture-buffer pressure and
    # pointless disk usage from N copies of the same save. `capture: full`
    # / `save` keep them (falls through to the msg-13 gate below, which
    # writes).
    if @options[:server] && (udp_data.getbyte(0) & 0x1F) == 13 && @capture_mode == 'normal'
      @stats[:capture_skipped] += 1 if @pcap_writer
      return
    end

    # TransferBlock (msg 13) packets carry raw save data — never analyzed,
    # and at ~20k pps the per-packet parse cost is what overflowed the
    # capture buffer before. Record them only when explicitly requested
    # (--save-transfer-blocks / --full-capture); the default is to drop them:
    # they contain no player actions and added ~12% to a 4.9M-packet capture.
    if (udp_data.getbyte(0) & 0x1F) == 13
      if @pcap_writer && @capture_mode != 'normal'
        @pcap_writer.write_frame(raw_frame, Time.at(ts))
      else
        @stats[:capture_skipped] += 1 if @pcap_writer
      end
      return
    end

    # Save to pcap if requested. When a raw frame is available (live capture)
    # write it as-is — much cheaper than rebuilding a fake IP/UDP packet per
    # packet, which matters during map-download bursts (~20k pps).
    # capture_recordable? drops keepalive-only heartbeats and (server mode)
    # outgoing broadcasts from the file — analysis-uninteresting packets.
    if @pcap_writer
      if capture_recordable?(src_ip, dst_ip, udp_data)
        @pcap_writer.write_frame(raw_frame, Time.at(ts))
      else
        @stats[:capture_skipped] += 1
      end
    end

    # Server mode: analyze ONLY incoming (client→server) packets. Every
    # player action arrives at the server exactly once; the server then
    # broadcasts it to all N clients, so the outgoing direction is N
    # duplicates. Tradeoff (documented): incoming packets have not yet been
    # validated/echoed by the server — cross-check with RCON if needed.
    if @options[:server]
      unless @host_ip_keys.key?(dst_ip)
        @stats[:outgoing_skipped] += 1
        # S→C sync actions are not the leave signal; the server broadcasts a
        # player_leave_game (wire 248) input action inside a tick closure.
        # Dedup above means this runs once per broadcast, not once per client.
        if FactorioProtocol.heartbeat_payload?(udp_data)
          handle_s2c_player_actions(FactorioProtocol.parse_udp_payload(udp_data), ts)
        end
        return
      end
    elsif @host_ip_keys.any?
      # Client mode: only packets FROM our game (the `ip:` setting).
      return unless @host_ip_keys.key?(src_ip)
    end

    parsed = FactorioProtocol.parse_udp_payload(udp_data)
    return unless parsed

    @stats[:factorio_packets] += 1
    hdr = parsed[:header]

    # Client mode: the first S→C heartbeat means either we are already in a
    # running game (no join/download will come — use the disk save) or a
    # join's map download has started/finished (the network copy wins).
    maybe_seed_roster_from_disk if hdr[:msg_type] == 7

    # Connection confirm carries this client's username. The packet is sent
    # by the client, so src_ip identifies us for self-index learning. A new
    # connection (e.g. joining a second server) may assign a new game index,
    # so reset the learned index to re-learn it from the next C→S heartbeat.
    if parsed[:connection_confirm]
      cc = parsed[:connection_confirm]
      if cc[:username]
        if @options[:server]
          # Server mode: every connecting client's username (not just a
          # "self" client). Bound to a game index by their first C→S
          # heartbeat action below.
          @ip_names[src_ip] = [cc[:username], false]
          ts_str = Time.at(ts).strftime('%H:%M:%S.%L')
          puts "#{ts_str}  #{cc[:username]} connected (from #{PcapFormat.ip_string(src_ip)})"
        else
          @self_ip = src_ip
          @self_name = cc[:username]
          @join_seen = true
        end
      end
    end

    # ConnectionAcceptOrDeny carries the server's player list: serverUsername
    # (host) + clientPeerInfo (peer_id + name for every online player). These
    # ids are NETWORK peer ids, NOT game indexes (they only coincide for brand
    # new players), so they map names for disconnect events and seed the
    # sequential peer-id counter — never players-cache.json. Game indexes come
    # from the save/RCON roster and from heartbeat actions.
    if parsed[:connection_accept]
      ca = parsed[:connection_accept]
      @join_seen = true unless @options[:server]
      ts_str = Time.at(ts).strftime('%H:%M:%S.%L')
      puts "#{ts_str}  [server]  game=\"#{ca[:game_name]}\" host=#{ca[:server_username]}"
      ca[:peers].each do |p|
        # Peer ids are a per-connection counter, NOT game indexes. Keep them
        # only for the disconnect name map; the save/RCON roster is what
        # gives id -> name. Storing peer_id+1 here is how stale high ids
        # (Player_749-style duplicates) got into players-cache.json.
        @peer_names[p[:peer_id]] = p[:name]
        @max_peer_id = p[:peer_id] if @max_peer_id.nil? || p[:peer_id] > @max_peer_id
        puts "#{ts_str}  [server]  online peer #{p[:peer_id]} -> #{p[:name]}"
      end
    end

    # A message whose STRING field would not decode is a misdecode (the
    # length ran past the buffer, or the bytes are not valid UTF-8 — FactorioWire
    # returns nil instead of scrubbing a different name). Keep the frame: a
    # scrubbed name would silently become another player.
    if raw_frame && string_decode_failed?(parsed)
      @stats[:bad_string] += 1
      @unknown_writer&.write_frame(raw_frame, Time.at(ts))
    end

    return unless (hb = parsed[:heartbeat])

    # Track the game tick (clock for lazy online_time): the last tick closure
    # carries the current tick. Anchor any connected players seeded from RCON
    # whose live-session start we haven't observed yet.
    if (last_tc = hb[:tick_closures]&.last) && last_tc[:tick]
      @game_tick = last_tc[:tick] if last_tc[:tick] > @game_tick
      @attrs.anchor_sessions(@game_tick)
    end

    # synchronizer actions
    join_misdecode = false
    hb[:sync_actions]&.each do |sa|
      # The joining client's own state machine (C→S ClientChangedState):
      # 2 CONNECTED → 3 DOWNLOADING → 4 LOADING → 6 WAITING_TCL → 7 INGAME.
      # Seeing any transition means a join started while we were watching;
      # an already-in-game start never sends one. This is the clean join
      # signal, independent of whether the first heartbeat beats the first
      # map-download block.
      if sa[:name] == 'ClientChangedState' && sa[:state]
        @client_state = sa[:state]
        @join_seen = true
      end
      if sa[:username]  # NewPeerInfo — a player joined (or is this client)
        # A join appends to the per-connection peer list: the next peer id is
        # max + 1. A different id is stream damage, not a player (and the
        # peer id is not a game index anyway — the save/RCON owns that map).
        # Peer ids are sequential per server lifetime, but the peers list we
        # seed from only contains CURRENTLY online peers: if the capture starts
        # late, the next real join can legitimately jump (803 -> 833). A real
        # join is therefore any id ABOVE the last one we saw, not exactly +1.
        # Going backwards is the misdecode (or a reused/duplicate peer).
        # Equal is not damage when it is the SAME peer/name: our own join is
        # listed by ConnectionAcceptOrDeny first, then announced again as
        # NewPeerInfo (live: peer 880 -> morganc twice). A different name or
        # a lower id is still a misdecode.
        already_known = @peer_names[sa[:peer_id]] == sa[:username]
        if sa[:peer_id] && @max_peer_id && sa[:peer_id] <= @max_peer_id && !already_known
          join_misdecode = true
          note_invalid_join(:peer_id, sa[:peer_id], sa[:username], @max_peer_id + 1)
          next
        end
        @max_peer_id = sa[:peer_id] if sa[:peer_id] && (@max_peer_id.nil? || sa[:peer_id] > @max_peer_id)
        @peer_names[sa[:peer_id]] = sa[:username]
        # Track the session start here; the :joined event itself is emitted
        # only by the server-verified S→C player_join_game action.
        @attrs.connect(sa[:username], @game_tick)
      end
      # PeerDisconnect is a C→S-only synchronizer action (the S→C leave is
      # the player_leave_game input action). No event here: the server-verified
      # S→C action owns joins/leaves in both modes.
    end

    # The SENDER's game index: in a C→S tick closure the first real action
    # carries the SENDER's game index (delta chain starts from 0xFFFF, so
    # the first delta IS the index+1).
    idx = nil
    if hdr[:msg_type] == 6 && hb[:tick_closures]&.any?
      hb[:tick_closures].each do |tc|
        real = tc[:actions]&.find { |a| a[:type] != 0 && a[:type] != 84 }
        if real
          idx = real[:game_player]
          break
        end
      end
    end

    # Bind usernames to game indexes from C→S heartbeat actions (joins:
    # msg 4 name + first real action's index → "confirmed as game player").
    if idx && hdr[:msg_type] == 6 && hb[:tick_closures]&.any?
      if @options[:server]
        # Server mode: learn EVERY client's name→index. msg 4 gave us
        # src_ip→name; the first real action in their C→S heartbeat gives
        # the game index. RCON /players is the authoritative cross-check.
        entry = @ip_names[src_ip]
        name = entry && !entry[1] ? entry[0] : nil  # unconfirmed only
        if name
          # Only check with an authoritative roster (live by default; replay
          # needs `strict_player_ids: true`), else every index would look
          # like it is past an empty/stale max.
          if !(@strict_player_ids && @roster_ready) || join_index_valid?(name, idx)
            entry[1] = true  # confirmed — never re-bind/re-enrich
            bind_player_index(name, idx)
            # No :joined here — the server-verified S→C player_join_game action
            # emits it. Keep the targeted RCON query for everything only the
            # server knows about a joiner, at this once-per-binding moment.
            # One targeted RCON query for everything only the server knows
            # about a joiner: their locale and their whole quickbar (the C→S
            # actions report it as deltas, so a join is the one moment the
            # bar is knowable). Rare event, off the capture thread.
            enrich_joined_player(name, idx)
            ts_str = Time.at(ts).strftime('%H:%M:%S.%L')
            puts "#{ts_str}  #{name} confirmed as game player ##{idx}"
          else
            join_misdecode = true
            note_invalid_join(:player_index, idx, name, "a roster slot or above #{roster_max_index}")
          end
        end
      elsif @self_name && src_ip == @self_ip
        # ONCE per binding: this block runs for every heartbeat that carries
        # an action, and re-stating the same index wrote the whole cache
        # (and printed the line) thousands of times in a 5h capture. A
        # validated index is also restated in attrs for the session's stats.
        if !(@strict_player_ids && @roster_ready) || join_index_valid?(@self_name, idx)
          if @player_db.id_for(@self_name) != idx
            # Stale cache entries may have this name at another slot; the
            # confirmed heartbeat index wins.
            bind_player_index(@self_name, idx)
            ts_str = Time.at(ts).strftime('%H:%M:%S.%L')
            puts "#{ts_str}  [self]  #{@self_name} confirmed as game player ##{idx}"
          else
            @attrs.set_index(@self_name, idx)
          end
        else
          join_misdecode = true
          note_invalid_join(:player_index, idx, @self_name, "a roster slot or above #{roster_max_index}")
        end
      end
    end

    # tick closures → player actions
    # Ghost flag is in bit 0 of next_receive timeshift
    @ghost_mode = hb[:next_receive] ? (hb[:next_receive] & 1) == 1 : false
    
    # Keep protocol-development packets that expose a decoder failure. Besides
    # hit_unknown, an action attributed to a player far outside the
    # authoritative roster is evidence that an earlier action length
    # desynchronized the stream.
    #
    known_players = @player_db.players.keys
    known_players.concat(@attrs.roster_pairs.map { |p| p[:index] })
    decoded_players = decoded_player_ids(hb)
    max_known_player = roster_max_index
    invalid_players = if known_players.empty?
                        []
                      elsif @strict_player_ids && @roster_ready
                        # Membership for ids INSIDE the roster (a gap there is
                        # a misdecode). Ids ABOVE the last known player can be
                        # new joiners the save/RCON seed predates — allow the
                        # same small window as replay; a real desync lands
                        # far outside it.
                        decoded_players.reject do |pid|
                          known_players.include?(pid) ||
                            (pid > max_known_player && pid <= max_known_player + UNKNOWN_PLAYER_WINDOW)
                        end
                      else
                        roster_ceiling = max_known_player + UNKNOWN_PLAYER_WINDOW
                        decoded_players.reject { |pid| known_players.include?(pid) || pid <= roster_ceiling }
                      end
    unless invalid_players.empty?
      @stats[:invalid_player] += 1
      invalid_players.each { |pid| note_invalid_player(pid) }
    end
    @desync_before = @stats[:desync]
    if hb[:hit_unknown] || invalid_players.any?
      # A desync: an action type with no length (or one before it desynced),
      # so the rest of this packet's actions were misread. Counted for the
      # summary — `undecoded actions` is the decoder's to-do list, this is the
      # damage it did.
      @stats[:desync] += 1
      last_act = hb[:tick_closures]&.filter_map { |tc| tc[:actions]&.last }&.last
      if @options[:validate] && hb[:hit_unknown] && last_act
        warn "[WARN] type #{last_act[:type]}(#{last_act[:name]}) triggered hit_unknown — previous action may have wrong data length"
      end
    end

    # Keep a frame when anything about this packet is undecoded or misread:
    # a suspected desync (above), an action type we have no name/layout for,
    # or a quickbar action whose payload implies a desync. One frame per
    # packet, no matter how many actions in it are affected.
    keep_frame = join_misdecode
    hb[:tick_closures]&.each do |tc|
      tc[:actions]&.each do |act|
        @stats[:actions] += 1
        # Decoder coverage: an action type we have no name/layout for. Counted
        # always (it is the answer to "what is still undecoded?"), not only
        # under --validate. The packet is kept too: an Unknown action in the
        # main list carries its MEASURED length, so the rest of the packet
        # still parses and hit_unknown never fires — without this the frame
        # holding the action we cannot decode was thrown away.
        if act[:name].is_a?(String)
          @stats[:unknown] += 1
          @unknown_names[act[:name]] = @unknown_names.fetch(act[:name], 0) + 1
          keep_frame = true
        end
        # NOT `keep_frame ||= track_quickbar(act)`: that would short-circuit
        # and skip the tracking itself on every action after the first hit.
        keep_frame = true if track_quickbar(act)
        # Roster events come ONLY from the server-verified S→C broadcasts.
        handle_s2c_roster_action(act, ts) if hdr[:msg_type] == 7
        log_action(ts, act, hdr[:msg_type] == 7, ghost: @ghost_mode, raw_frame: raw_frame)
      end
      # Runtime action-ID validation (action_validator plugin): the decoded
      # actions of one tick closure, joined against the server log's
      # "Action performed" lines by (tick, player). Server mode has only C→S;
      # client mode feeds the S→C echo too (deduped above), which is what the
      # log actually contains for every player.
      # The log's tick is the tick the SERVER processed the action, which is
      # the S→C echo's tick. Our C→S closure carries the LOCAL tick, often 1-2
      # ticks earlier, so feeding both makes the C→S copy consume the log line
      # first and shifts every later echo (266 precise/very-close chain). In
      # client mode the S→C echo already carries every player's action, so
      # feed it alone; server mode has only C→S.
      if tc[:tick] && ((@options[:server] && hdr[:msg_type] == 6) ||
                       (!@options[:server] && hdr[:msg_type] == 7))
        feed_action_validation(tc[:tick], tc[:actions])
      end
    end
    keep_frame ||= @stats[:desync] > @desync_before
    @unknown_writer&.write_frame(raw_frame, Time.at(ts)) if keep_frame && raw_frame
  rescue StandardError => e
    # ONE malformed packet costs ONE packet. The decoder reads lengths off
    # the wire and trusts them, so a length can point past the end of a
    # payload; the frame goes to unknown.packets-*.pcap (the same file the
    # hit_unknown / bad-string paths use) and the run continues. Without
    # this the exception escaped process_packet, escaped the pcap reader,
    # and ended the rest of the capture file ("stopped reading this file") —
    # on one 22MB capture that silently cost 36k packets and 43k actions.
    @stats[:decode_error] += 1
    @unknown_writer&.write_frame(raw_frame, Time.at(ts))
    warn_decode_error(e)
  end

  # Report a decode crash without flooding the console: the first few name
  # the error, then every 1000th. The frames themselves are all in
  # unknown.packets-*.pcap; the count is in the summary line.
  DECODE_ERROR_REPORT_EVERY = 1000
  def warn_decode_error(e)
    n = @stats[:decode_error]
    return unless n <= 5 || (n % DECODE_ERROR_REPORT_EVERY).zero?
    warn "[decode] packet #{@stats[:packets]} raised #{e.class}: #{e.message} " \
         "(#{n} so far, frame saved to unknown.packets)"
  end

  # Display formatting lives in ActionPresenter (lib/action_presenter.rb).
  def format_action_data(act)
    @presenter.format(act)
  end

  # Quickbar slot/page state from the quickbar input actions, kept in
  # players-cache.json (PlayerDatabase#set_quickbar_slot / _page). A
  # set_slot names the item and the slot but NOT the page, so the page the
  # slot lands on is the one the player last switched to.
  #
  # One identity write for every path that binds a game index to a name:
  # server-mode join confirm, client self-index confirm, S→C player_join_game.
  def bind_player_index(name, idx)
    # Only the NAME: a merge that also writes `locale: nil` would wipe the
    # locale the roster seeded for a returning player.
    @player_db[idx] = { name: name }
    @player_db.remove_other_entries_for(name, idx)
    @attrs.set_index(name, idx)
  end

  # Returns TRUE when the action could not be decoded, or named a page/slot
  # outside the quickbar. Both mean an EARLIER action's length desynced the
  # closure — the quickbar action is merely the first to show it — and the
  # caller forwards the frame to the unknown-packet writer, which is the
  # corpus for fixing that length. The generic flag (hit_unknown / unknown
  # player) misses those: the closure parsed to the end, just wrongly.
  # Measured over captures/server-*.pcap: 355 frames, 104 of which the
  # generic flag never sees (35080 packets of 496953).
  def track_quickbar(act)
    qb = FactorioProtocol::Actions::QuickBar.decode(act)
    return true if qb == :undecodable # a quickbar payload we cannot read
    return false unless qb            # not a quickbar action
    if qb.key?(:page)
      !@player_db.set_quickbar_page(act[:game_player], qb[:page])
    elsif act[:name] == :quick_bar_set_slot
      # op 1 = clear the slot (drop its filter)
      item = qb[:op] == 0 ? qb[:item] : nil
      !@player_db.set_quickbar_slot(act[:game_player], @player_db.quickbar_page(act[:game_player]),
                                    qb[:slot], item)
    else
      false # pick_slot: the selection, no state to keep and nothing to check
    end
  end

  # Ask the server about a joiner: ONE targeted RCON query
  # (RconClient#player_attributes_for) carrying their attrs AND their whole
  # quickbar, on its own thread — joins are minutes apart and a blocked
  # capture thread would drop packets. Folds the locale (used by the
  # translation agent) and the quickbar into players-cache.json; the active
  # quickbar page still comes from the packets, the game has no API for it.
  # Queried by game INDEX: the join heartbeat that triggered this already
  # bound it, so no name ever has to be quoted into Lua.
  # Returns the thread (tests join it) or nil when RCON isn't available.
  def enrich_joined_player(name, idx)
    return nil unless @rcon
    Thread.new do
      attrs = @rcon.player_attributes_for(idx)
      unless attrs
        warn "[join] #{name} ##{idx}: RCON enrichment returned nothing"
        next
      end
      @player_db.set_locale_by_id(idx, attrs[:locale]) if attrs[:locale]
      # The colour rides along with the locale: an identity the packets
      # carry but we do not decode yet, and a join is the one moment the
      # server hands it over.
      @player_db[idx] = { color: attrs[:color] } if attrs[:color]
      bar = attrs[:quickbar]
      if bar == :failed
        warn "[join] #{name} ##{idx}: quickbar read failed in Lua (API shape vs " \
             "#{@rcon.server_version || 'unknown version'}?) — attrs kept"
      else
        # The read is authoritative, empty bar included (nil clears the cache).
        @player_db.replace_quickbar(idx, bar)
      end
      # Features see every join, after the store: player_backup restores an
      # empty bar here and re-stores it, so its value is the one that sticks.
      on_join_enriched(name, idx, attrs)
      unless bar == :failed
        puts "[join] #{name} ##{idx}: locale=#{attrs[:locale] || '?'} " \
             "quickbar=#{Array(bar).flatten.compact.size} slot(s)"
      end
    rescue StandardError => e
      warn "[join] #{name} ##{idx}: RCON enrichment failed (#{e.class}: #{e.message})"
    end
  end

  # Decoded quickbar action, for the per-action console line. Item ids, not
  # names: the quickbar is stored and read as wire ids (see
  # PlayerDatabase#set_quickbar_slot), so nothing here needs item_db.
  def quickbar_str(qb)
    @presenter.quickbar_str(qb)
  end

  # Send one closure to the action validator, merging the two directions the
  # way tools/validate_actions.rb does: an exact echo is ignored, a different
  # fragment appends. Keeps the per-tick signature ring bounded.
  def feed_action_validation(tick, actions)
    sig = Array(actions).map { |a| [a[:game_player], a[:type]] }
    return if sig.empty?
    prev = @fed_action_sigs[tick]
    if prev.nil?
      @fed_action_sigs[tick] = sig
      @plugins.emit(:on_input_actions, tick, actions)
    elsif prev == sig
      # Already fed from the other direction.
    else
      @fed_action_sigs[tick] = prev + sig
      @plugins.emit(:on_input_actions_append, tick, actions)
    end
    @fed_action_sigs.shift while @fed_action_sigs.size > 4096
  end

  # Player indexes named by this heartbeat's real actions (type 0 is padding,
  # never a player event). Only indexes, not peer ids: peer ids live in a
  # different namespace and are not game indexes.
  def decoded_player_ids(hb)
    Array(hb[:tick_closures]).flat_map do |tc|
      Array(tc[:actions]).reject { |a| a[:type].to_i.zero? }.map { |a| a[:game_player] }
    end.compact.uniq
  end

  # The highest game player index we know from any authoritative source:
  # cache entries, RCON's full player dump (offline included), and attrs.

  # A join appends to the player list of THIS save: the index is either one
  # the roster already knows (a returning player) or above the highest index
  # the roster has (a new player). "Exactly max + 1" is too strict: two
  # players can join between two heartbeats, and the second one is then
  # rejected as a misdecode and never bound.
  def join_index_valid?(name, idx)
    return false unless idx.is_a?(Integer) && idx.positive?
    return true if @player_db.lookup(idx) == name
    return true if @roster[idx - 1] == name
    max = roster_max_index
    return true if idx > max && idx <= max + UNKNOWN_PLAYER_WINDOW
    false
  end

  def note_invalid_join(kind, id, name, expected)
    key = "#{kind}:#{id}"
    first = !@invalid_join_keys.key?(key)
    @invalid_join_keys[key] = true
    @stats[:invalid_join] += 1
    return unless first
    warn "[WARN] misdecoded join #{kind} #{id} for #{name.inspect} (expected #{expected}) — frame kept in unknown.packets"
  end

  # One warning per bad id per run: the same misdecode repeats every packet,
  # and the summary carries the total.
  def note_invalid_player(pid)
    first = !@invalid_player_ids.key?(pid)
    @invalid_player_ids[pid] = @invalid_player_ids.fetch(pid, 0) + 1
    return unless first
    warn "[WARN] invalid player id #{pid} has no players-cache entry — possible misdecoded packet; frame kept in unknown.packets"
  end

  def log_action(ts, act, is_server, ghost: false, raw_frame: nil)
    pid = act[:game_player]
    arrow = is_server ? '<-' : '->'

    # Dump raw type info for reverse engineering
    pname = @player_db.lookup(pid)

    # Any real input action (not server-internal padding) resets the
    # player's afk_time — mirrors LuaPlayer.afk_time, fed by C→S actions.
    @attrs.register_action(pname, @game_tick) if pname && act[:type] != 0 && act[:name] != 'server_tick_info'

    # Chat messages: ALWAYS printed (exempt from all filters) and fed to
    # the agent — chat is the important signal, filters are for action
    # spam. Split messages are reassembled across packets
    # (chat_action_data) before decoding.
    if act[:name] == :write_to_console
      data = chat_action_data(act, pname, ts)
      if data
        # A '?' in the printed chat means decode_chat's scrub() replaced
        # bytes: the payload is not valid UTF-8, so the chat decode (or the
        # segment split) is wrong — keep the frame for review. Checked on
        # the BYTES, not the string, so a real "?" never lands here.
        if raw_frame && !data.dup.force_encoding('UTF-8').valid_encoding?
          @unknown_writer&.write_frame(raw_frame, Time.at(ts))
        end
        msg = FactorioProtocol.decode_chat(data)
        if msg
          puts "#{log_ts(ts)}  #{arrow} #{pname}: #{msg}"
          publish_chat(:factorio, pname, msg, player_id: act[:game_player])
        end
      end
      return
    end

    # set_player_color (2.0 wire 296 / 2.1 312): FOUR UNORM bytes, 0..255.
    # Measured over the capture set (2313 occurrences, all one player with the
    # colour picker open, no desync around them): bytes 0..2 sweep the full
    # range — [0,0,255] alone is blue, [0,255,0] green, [255,255,255] white,
    # so the order is R,G,B. Byte 3 is 127 in every sample, but a live probe
    # showed the game IGNORES it (0/127/255 all leave alpha 0.5) and also sets
    # chat_color; PlayerBackup translates both. RCON is authoritative and
    # still seeds both files at startup; this keeps them current for a player
    # who changes colour while we run, without waiting for their next join. A colour with no NAME
    # (an index we never bound) is dropped: the cache is keyed by name, and a
    # nameless record would poison whoever takes that slot later.
    if act[:name] == :set_player_color && act[:data]&.bytesize == 4 && pname &&
       !pname.start_with?('Player_')
      rgba = act[:data].unpack('C4').map { |v| (v / 255.0).round(4) }
      @player_db[pid] = { color: rgba }
      on_player_color(pname, rgba)
    end

    return unless visible?(pname, act)

    return if act[:name].is_a?(String)
    # Skip server-internal actions (no real player)
    return if act[:game_player] <= 0
    # Skip 'nothing' (type 0) - these are server padding/metadata after echoed actions
    return if act[:type] == 0
    # Skip server_tick_info (type 84) - server wrapper action (hash+tick) in every server heartbeat
    return if act[:name] == :server_tick_info

    # Format action data (position, entity refs, etc.)
    data_str = format_action_data(act)
    suffix = ghost && act[:name] == :build ? ' [ghost]' : ''
    if @options[:dump_raw_types]
      hex = act[:data] ? act[:data].unpack1('H*') : ''
      data_str += " [#{hex}]"
    end
    # The decoded per-action line is the volume culprit with many players —
    # gated behind --debug. Everything important (chat, join/leave events,
    # and invalid/missing-decode warnings) prints regardless; this is only
    # the per-action dump, shown when inspecting decodes.
    return unless @console.debug?
    name = pname || "Player_#{act[:game_player]}"
    puts "#{log_ts(ts)}  #{arrow} #{name.ljust(16)} #{act[:name].to_s.ljust(28)}#{data_str}#{suffix}"
  end

  # Console timestamp. Built at the PRINT sites only: formatting it per
  # action cost ~13% of a full capture decode (Time.at + strftime on every
  # action, almost all of which are filtered out before printing).
  def log_ts(ts)
    Time.at(ts).strftime('%H:%M:%S.%L')
  end

  # ── Pcap replay (one process for the whole set) ──────────────────

  # Every -r path in order, in ONE process: the rolling set is hundreds of
  # files and N Ruby startups (~0.3s each) was minutes of the run. Sniffer
  # state carries across files (players, attrs, the name index), so a set
  # reads as one session — which is what it is. A file that cannot be read
  # (a .gz capture still being written, a truncated rotation) is reported and
  # skipped: whatever it yielded before failing is kept.
  def read_pcaps
    paths = Array(@options[:pcaps])
    paths = [@options[:pcap]] if paths.empty?
    on_start if log_consumers?
    paths.each_with_index do |path, i|
      puts "[pcap] #{i + 1}/#{paths.size} #{path}" if paths.size > 1
      begin
        PcapReader.new(path).each_packet { |*args| process_packet(*args) }
      rescue StandardError => e
        warn "[pcap] #{path}: #{e.class}: #{e.message} — stopped reading this file"
      end
    end
  end

  # The messages that carry strings (username, game name, mod list, peer
  # names). The key is PRESENT but nil when the parse failed — a fragment > 0
  # omits the key entirely, which is not a failure.
  STRING_MESSAGES = %i[connection_request connection_confirm connection_accept].freeze
  def string_decode_failed?(parsed)
    STRING_MESSAGES.any? { |k| parsed.key?(k) && parsed[k].nil? }
  end

  # ── Interactive filter console (stdin) ──────────────────────────

  # Output filters live in Console::ViewFilter. Kept as delegates because the
  # packet path reads them at many sites.
  def visible?(pname, act) = @console.visible?(pname, act)
  def player_visible?(name) = @console.player_visible?(name)

  # Query the RCON roster and merge {name -> index} into the player DB, so
  # players connected at startup are named immediately. Players who join
  # later are captured from the packet stream (msg 4 username + first C→S
  # heartbeat game index). A failed query is skipped silently.
  #
  # Runs once at startup (RCON is authoritative). Players who join later are
  # captured from the packet stream (msg 4 username + first C→S heartbeat
  # game index); the roster data lives on the persistent @attrs object.
  def load_roster
    return unless @rcon
    # Use player_attributes which now includes locale
    attrs = @rcon.player_attributes
    # load_player_attrs (same startup call site, back-to-back) reuses this
    # exact dump instead of re-querying RCON.
    @attrs_query = attrs
    return if attrs.nil?
    @roster_ready = true # RCON answered: membership is authoritative now
    return if attrs.empty?
    connected = attrs.select { |a| a[:connected] }
    return if connected.empty?
    connected.each do |a|
      @player_db[a[:index]] = {name: a[:name], locale: a[:locale], admin: a[:admin], color: a[:color]}
      @player_db.remove_other_entries_for(a[:name], a[:index])
      # Authoritative live-roster seed (connected + index); time accounting
      # is player_attributes' job (load_player_attrs).
      @attrs.roster_online(a[:name], a[:index])
    end
    ts = Time.now.strftime('%H:%M:%S.%L')
    puts "#{ts}  [rcon]  connected players (#{connected.size}): " +
         connected.map { |a| "#{a[:name]} (##{a[:index]})" }.join(', ')
  end

  public

  # Names of players currently in-game (online tracking): seeded from the
  # RCON roster at startup, updated from NewPeerInfo / PeerDisconnect and
  # bound to game indexes by C→S heartbeats. Sorted for stable output.
  # Used by the interactive console status line.
  def online_players
    @attrs.online_names
  end

  # ── Interactive filter console (stdin) ──────────────────────────

  # Handle one line from the interactive filter console (stdin thread in the
  # entry point). All commands live in lib/console.rb.
  def handle_command(line)
    @console.handle(line)
  end

  private

  # (everything below here is private as before)

  # One-shot seed of mirrored LuaPlayer attributes (connected /
  # online_time / afk_time) from RCON for ALL known players. Admin is
  # stored in PlayerDatabase (players-cache.json). After this, the packet
  # stream maintains attrs (PlayerAttrs). A failed/truncated query is
  # non-fatal — attrs are enrichment; the roster/stream keep working.
  def load_player_attrs
    return if @attrs_loaded
    @attrs_loaded = true
    return unless @rcon
    attrs = @attrs_query || @rcon.player_attributes
    @attrs_query = nil
    return if attrs.nil? || attrs.empty?
    roster = roster_array(attrs.to_h { |a| [a[:index], a[:name]] })
    apply_roster(roster)
    @roster = roster
    attrs.each do |a|
      # The RCON roster knows the NAME of every player of this save — the
      # wire only carries it on a join we happened to watch. Writing it here
      # is what makes a player who joined before we started stop chatting as
      # "Player_#N".
      @player_db[a[:index]] = roster_record(a)
      @attrs.seed(a[:name], index: a[:index], connected: a[:connected],
                   online_time: a[:online_time],
                   afk_time: a[:afk_time])  # connected seeds join the live roster
    end
    ts = Time.now.strftime('%H:%M:%S.%L')
    admins = attrs.select { |a| a[:admin] }.map { |a| a[:name] }
    puts "#{ts}  [rcon]  player attrs seeded (#{attrs.size} players): " +
         (admins.empty? ? 'no admins' : "admins: #{admins.join(', ')}")
  rescue => e
    warn "Player attrs seed failed: #{e.class}: #{e.message}"
  end

  # The roster row → a cache record. Only the fields the query actually
  # answered: a nil in the record would WIPE what the packet stream learned
  # (the merge in PlayerDatabase#[]= overwrites with nil too).
  def roster_record(a)
    rec = {name: a[:name]}
    rec[:locale] = a[:locale] if a[:locale]
    rec[:admin] = a[:admin] unless a[:admin].nil?
    rec[:color] = a[:color] if a[:color]
    rec
  end

  # The cache belongs to THIS save? The game hands out game indexes per
  # savefile, so two saves look alike (index 1, 2, 3 …) while holding
  # DIFFERENT players — a cache carried over from another save is not just
  # stale, it is WRONG (its quickbars and colours belong to other people,
  # and the player_backup feature would restore them to the wrong player).
  # The START of the roster tells the two apart: if the cache names one of
  # the first players differently, the cache is from another savefile and is
  # dropped whole.
  def apply_roster(roster)
    return if @player_db.valid_for?(roster)
    dropped = @player_db.clear!
    puts "  [roster]  cache is from another save — dropped #{dropped} entries"
  end

  # A roster (index → name) as an ARRAY of names in index order: the game
  # hands out the indexes sequentially, so game index N is roster[N-1] and
  # the array's length IS the highest index. A hole (no player at that
  # index) stays nil.
  def roster_array(index_by_name)
    arr = Array.new(index_by_name.keys.map(&:to_i).max.to_i)
    index_by_name.each { |index, name| arr[index.to_i - 1] = name }
    arr
  end

  # The highest game index this save has handed out: the roster's highest
  # (the RCON/save roster of THIS save), or — before a roster is known —
  # the cache's highest. ONE number for the validation window, the misdecode
  # logging and the join check.
  def roster_max_index
    (@roster.size.positive? ? @roster.size : @player_db.players.keys.max).to_i
  end

  def print_summary
    puts "[summary] packets=#{@stats[:packets]} factorio=#{@stats[:factorio_packets]} actions=#{@stats[:actions]}"
    puts "[summary] packets not captured (keepalives/outgoing/transfer)=#{@stats[:capture_skipped]}" if @stats[:capture_skipped]&.positive?
    puts "[summary] outgoing broadcasts skipped (server mode)=#{@stats[:outgoing_skipped]}" if @options[:server]
    puts "[summary] packets kept for a failed string decode=#{@stats[:bad_string]}" if @stats[:bad_string]&.positive?
    puts "[summary] packets whose decode RAISED (saved to unknown.packets)=#{@stats[:decode_error]}" if @stats[:decode_error]&.positive?
    puts "[summary] packets with a suspected desync: #{@stats[:desync]}" if @stats[:desync]&.positive?
    if @stats[:invalid_player]&.positive?
      ids = @invalid_player_ids.sort_by { |_, n| -n }.first(12).map { |id, n| "#{id}=#{n}" }.join(', ')
      puts "[summary] packets with an invalid player id (no players-cache entry): #{@stats[:invalid_player]} — ids: #{ids}"
    end
    puts "[summary] misdecoded join ids: #{@stats[:invalid_join]}" if @stats[:invalid_join]&.positive?
    return if @unknown_names.empty?
    puts "[summary] undecoded actions: #{@stats[:unknown]}/#{@stats[:actions]} " \
         "(#{@unknown_names.size} type(s)) — top: " \
         "#{@unknown_names.sort_by { |_, v| -v }.first(12).map { |k, v| "#{k}=#{v}" }.join(', ')}"
  end

  # S→C heartbeat tick-closure actions that carry roster state:
  # player_join_game (159) and player_leave_game (248). The server broadcasts
  # both, with the GAME INDEX as the action's player. They are the ONLY
  # :joined/:left producers: server-verified, deduped, and reliable for
  # accepted joins and every leave (clean quit or crash).
  def handle_s2c_player_actions(parsed, ts)
    hb = parsed && parsed[:heartbeat]
    return unless hb
    hb[:tick_closures]&.each do |tc|
      tc[:actions]&.each { |action| handle_s2c_roster_action(action, ts) }
    end
  end

  def handle_s2c_roster_action(action, ts)
    case action[:type]
    when 159 # player_join_game
      join = FactorioProtocol::Actions::PlayerJoin.decode(action)
      return unless join
      bind_player_index(join[:name], join[:index])
      @attrs.connect(join[:name], @game_tick)
      unless @s2c_joined[join[:name]]
        @s2c_joined[join[:name]] = true
        @plugins.emit(:on_player_event, :joined, join[:name])
        ts_str = Time.at(ts).strftime('%H:%M:%S.%L')
        puts "#{ts_str}  #{join[:name]} joined the game" if player_visible?(join[:name])
      end
    when 248 # player_leave_game
      name = @player_db.lookup(action[:game_player])
      return unless name
      @s2c_joined.delete(name)
      reason = action[:leave_reason_name] || (action[:leave_dropped] ? :dropped : :quit)
      leave_player(name, ts, reason: reason)
    end
  end

  def leave_player(name, ts, require_online: true, reason: :quit)
    return false if require_online && !@attrs.online_names.include?(name)
    @attrs.disconnect(name, @game_tick)
    @plugins.emit(:on_player_event, :left, name, reason, @attrs.online_time_ticks(name, nil))
    ts_str = Time.at(ts).strftime('%H:%M:%S.%L')
    text = FactorioProtocol::DisconnectReason.text(reason)
    puts "#{ts_str}  #{name} #{text}" if player_visible?(name)
    true
  end

  # One S→C broadcast copy per content within DEDUP_WINDOW seconds. Canonical
  # key clears the header's random flag (0x20): the server sends the same
  # payload to every client with a per-recipient random bit, so the raw bytes
  # differ even though the message does not.
  DEDUP_WINDOW = 1.0
  def duplicate_s2c?(udp_data, ts)
    key = udp_data.dup
    key.setbyte(0, key.getbyte(0) & ~0x20) if key.bytesize > 0
    seen = @s2c_seen[key]
    return true if seen && ts - seen <= DEDUP_WINDOW
    @s2c_seen[key] = ts
    if @s2c_seen.size > 4096
      cutoff = ts - DEDUP_WINDOW
      @s2c_seen.delete_if { |_k, at| at < cutoff }
    end
    false
  end

  # Reassemble a chat message split across input-action segments. The
  # segment metadata (total_segs/seg_no) marks split messages that arrive
  # in SEPARATE packets; fragments are buffered per (player, total_segs)
  # and merged in seg_no order when complete. Returns the merged payload,
  # or nil while the group is incomplete (skip printing/feeding until the
  # full message arrives). Buffers older than 15s are dropped (UDP loss
  # may strand a fragment).
  #
  # The (player, total_segs) key is reused across DIFFERENT messages from
  # the same player, so a stale partial group must be discarded before a
  # new message's first fragment lands in it — otherwise the old fragment
  # merges into the new message (client-20261027-201904: a 30s-old S→C
  # echo of "at hitting the bots" merged into a later
  # "uranium will be back…"). Age the group from its FIRST fragment and
  # prune BEFORE writing: refreshing `ts` on every write fed the eviction
  # gate its own stamp and a reused key escaped it.
  def chat_action_data(act, pname, ts)    total = act[:total_segs]
    data = act[:data]
    return data unless total && total > 1

    @chat_segments.delete_if do |_k, g|
      g[:ts] && (ts - g[:ts]) > 15
    end

    key = [pname, total]
    group = (@chat_segments[key] ||= {})
    group[:ts] ||= ts  # creation time of the group, NOT refreshed per fragment
    group[act[:seg_no]] = data

    return nil unless (0...total).all? { |n| group.key?(n) }
    merged = (0...total).map { |n| group[n] }.join
    @chat_segments.delete(key)
    merged
  end

  # ── Live map-download roster seed (client mode) ───────────────────

  # Client mode never sees the players who were already in the game: the
  # wire only carries joins from now on, and there is no RCON. The map
  # download is the server's own save, and a save holds the whole roster, so
  # we reassemble it off the live stream (MapDownload, off the capture
  # thread) and seed the roster from it. Server mode has both the save on
  # disk and RCON, so it does neither.
  def map_download_hook
    return nil if @options[:server] || !@options[:interface] || @options[:player_db].nil?
    @map_download ||= MapDownload.new(dir: default_capture_dir,
                                      on_incomplete: -> { start_disk_seed }) do |zip, blocks|
      seed_roster_from_save(zip, blocks)
    end
  end

  # Runs on the MapDownload worker thread, never the capture thread. The
  # roster scan lives in FactorioSave/PlayerDatabase; this only labels it and
  # drops the temporary archive once the roster is out of it.
  def seed_roster_from_save(zip, blocks)
    roster_from_save(zip, verbose: true, label: 'map-download')
    # the roster was the point; the pcap keeps the blocks if wanted
    File.delete(zip)
  rescue StandardError => e
    warn "[map-download] roster seeding failed: #{e.class}: #{e.message}"
  end

  # Client-mode disk-save fallback: only decide once, when the first S→C
  # heartbeat proves the connection is live. If we watched this client join
  # (connection accept/confirm or a ClientChangedState) OR a map download is
  # already arriving, that join's save is the same file and newer — skip the
  # disk scan entirely. The heartbeat can arrive BEFORE the first transfer
  # block, so join_seen must decide too. Otherwise we started while already
  # in-game, and the disk save is the only source for the players already there.
  def maybe_seed_roster_from_disk
    return unless @options[:roster_save] && !@options[:server] && @map_download
    return if @disk_seed_started
    @disk_seed_started = true
    if @join_seen || @map_download.blocks_seen.positive?
      puts '[roster-save] join/map download in progress — disk save seed skipped'
    else
      start_disk_seed
    end
  end

  # One background disk scan per session (also the map-download failure
  # fallback). PlayerDatabase serializes the merge with the capture thread.
  def start_disk_seed
    @disk_seed_started = true
    return if @disk_seed_thread
    @disk_seed_thread = Thread.new { seed_roster_from_disk_save }
  end

  # Startup roster seed from a configured save path (config.yaml
  # `roster_save:`): either a path to a save file directly, or a directory
  # from which the most recently written save is read. In server mode this
  # runs at startup; in client mode it is the deferred fallback above.
  def seed_roster_from_disk_save
    spec = File.expand_path(@options[:roster_save]) # expand ~; YAML keeps it literal
    save = File.directory?(spec) ? latest_save(spec) : spec
    return unless save
    puts "[roster-save] seeding from #{save}"
    roster_from_save(save, verbose: true, label: 'roster-save')
  end

  # Latest save (by mtime) in a directory. Factorio autosaves compress a
  # lot, so a directory is a useful default target; the newest is the one
  # that reflects the current roster.
  def latest_save(dir)
    zips = Dir.glob(File.join(dir, '*.zip')).sort_by { |f| File.mtime(f) }
    if zips.empty?
      warn "[roster-save] no .zip saves in #{dir}"
      return nil
    end
    zips.last
  end

  # Read a save (zip or a directory whose latest save is picked) and merge
  # its whole roster into the in-memory player DB. Save parsing and the
  # index anchoring live in FactorioSave/PlayerDatabase; this is only the
  # label + logging. Shared by the live map-download seed and the startup
  # save-seed. Returns false (and warns) on any failure; never raises.
  def roster_from_save(save, verbose: false, label: 'roster-save')
    scan = FactorioSave.scan_save(save)
    records = scan.records
    if records.empty?
      warn "[#{label}] no candidate names in #{save} — not a level.dat stream?"
      return false
    end
    known = @player_db.name_ids
    index = scan.indexed(known)
    if index.by_index.empty?
      warn "[#{label}] no player records in #{save}"
      return false
    end
    # The cache must belong to THIS save: the game's indexes are per
    # savefile, so a cache from another save names a different player at
    # the same index (and carries another player's quickbar).
    apply_roster(roster_array(index.by_index.transform_values { |r| r[:name] }))
    dropped = @player_db.merge_save_roster(index.by_index)
    @roster = roster_array(index.by_index.transform_values { |r| r[:name] })
    @roster_ready = true # the save's roster is authoritative now
    if verbose
      if known.empty?
        puts "[#{label}] candidates: #{records.size}   no known players in the cache — roster taken from the record structure alone"
      else
        puts "[#{label}] candidates: #{records.size}   known names anchoring the run: #{index.anchored}/#{index.known_count}"
      end
      if index.absent.any?
        puts "[#{label}] note: #{index.absent.size} cached player(s) joined after this save: " \
             "#{index.absent.first(5).inspect}#{'…' if index.absent.size > 5}"
      end
      if index.mismatched.any?
        puts "[#{label}] [warn] #{index.mismatched.size} known name(s) disagree with the run: #{index.mismatched.first(5).join(', ')}"
        puts "[#{label}] [warn] replacing those cache entries with the save's indexes (the save is authoritative)"
      end
      by_index = index.by_index
      keys = by_index.keys
      ticks = by_index.values.sum { |r| r[:online_time_ticks] || 0 }
      puts "[#{label}] roster: #{by_index.size} players (indexes #{keys.min}..#{keys.max})"
      puts "[#{label}] play time: #{by_index.values.count { |r| r[:online_time_ticks] }} records, #{ticks} ticks total " \
           "(#{'%.0f' % (ticks / 60 / 3600.0)} h), save tick #{scan.save_tick}, pair slots #{scan.slots.inspect}"
      locales = by_index.values.count { |r| r[:locale] }
      puts "[#{label}] locale: #{locales}/#{by_index.size} records (#{by_index.values.count { |r| r[:locale] == 'en' }} en)"
      colors = by_index.values.count { |r| r[:color] }
      puts "[#{label}] color: #{colors}/#{by_index.size} records (#{by_index.values.map { |r| r[:color] }.compact.uniq.size} distinct)"
      added = by_index.values.map { |r| r[:name] }.reject { |name| known.key?(name) }
      puts "[#{label}] new: #{added.size} -> #{added.first(10).inspect}#{'…' if added.size > 10}"
      puts "[#{label}] dropped #{dropped} stale duplicate name id(s)" if dropped.positive?
    end
    true
  rescue StandardError => e
    warn "[#{label}] seeding failed: #{e.class}: #{e.message}"
    false
  end

  # ── Always-on auto-named capture ────────────────────────────────

  def new_pcap_writer(path)
    PcapWriter.new(path, gzip: @options[:save_capture_gz], keep: effective_keep, rotate_size: effective_rotate_size, max_size: effective_max_size, timestamped: true)
  end

  # Default captures/ directory (created on demand), relative to cwd.
  def default_capture_dir
    dir = File.join(Dir.pwd, 'captures')
    FileUtils.mkdir_p(dir) unless File.directory?(dir)
    dir
  end

  # Capture identity path (never written directly): the writer timestamps
  # it on open (`server-<port>-<ts>.pcap`), so every file under the stem is
  # one identity and retention covers ALL runs, not just the current one.
  def capture_path(dir, id)
    ext = @options[:save_capture_gz] ? '.pcap.gz' : '.pcap'
    File.join(dir, "#{id}#{ext}")
  end

  # Human hint about rotation for the capture startup line.
  def retention_hint
    " (rotating hourly/at #{effective_rotate_size}MB, keep #{effective_keep}h / #{effective_max_size}MB total)"
  end

  # Effective retention: explicit flags win, otherwise the hardcoded
  # defaults above (capture is always on — unbounded is never an option).
  def effective_keep
    @options[:keep] || DEFAULT_KEEP_HOURS
  end

  def effective_rotate_size
    @options[:rotate_size] || DEFAULT_ROTATE_SIZE_MB
  end

  # Total budget for the rotated files (nil = age-only retention).
  def effective_max_size
    @options.key?(:max_size) ? @options[:max_size] : DEFAULT_MAX_SIZE_MB
  end

  # Client mode: the server IP is unknown at startup — resolve it from the
  # first packet where one endpoint is one of our host IPs (`ip:`) and the
  # other is the server; fall back to plain "client" otherwise.
  def ensure_pcap_writer(src_ip, dst_ip)
    return unless @pending_capture
    server_ip = if @host_ip_keys.key?(src_ip)
      dst_ip
    elsif @host_ip_keys.key?(dst_ip)
      src_ip
    end
    id = server_ip ? "client-#{PcapFormat.ip_string(server_ip)}" : 'client'
    path = capture_path(@pending_capture, id)
    @pcap_writer = new_pcap_writer(path)
    @pending_capture = nil
    # The writer timestamps the stem on open; print the file it actually made.
    puts "capturing to #{@pcap_writer.path}#{retention_hint}"
  end

  # Console host API (lib/console.rb).
  public :online_players, :print_summary
end
