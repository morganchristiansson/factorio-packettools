# Factorio Packet Tools — Agent Context

## Project Overview

Factorio multiplayer protocol reverse-engineering tool. Captures UDP traffic,
decodes the binary protocol, extracts player actions, and logs them. Runs
either on a client or on the game server host (server mode, with RCON).

## Key Files

- `factorio-packettools.rb` — Entry point: CLI, signal traps, single sniffer
  run (thin)
- `lib/factorio_packet_tools.rb` — Main class (`FactorioPacketTools`); a
  single sniffer instance runs the capture loop to completion (Ctrl-C
  Interrupting it shuts down cleanly via `#finish`).
- `lib/factorio_protocol.rb` — Protocol parser (2.1 stable ACTIONS table, parsing logic). Input actions use the one fixed 2.1 table; 2.0 is retired. parse_action + ActionLengths use name-based dispatch (never hardcode 2.1 type IDs). Also parses msg-17 GameInformationRequestReply payloads (`parse_game_info`), builds the one-byte msg-16 GameInformationRequest (`GAME_INFO_REQUEST`), and reassembles fragmented messages (`reassemble_fragments` — msg 4's mod blob and msg 17's split reply; `message_id` is a TYPE id, not a message id).
- `lib/factorio_protocol/quickbar.rb` — the quickbar input actions (`QuickBar.decode`, one hash per action, nil for a non-quickbar action and `:undecodable` for a payload shape we do not know). The sniffer keeps each player's bar in players-cache.json and forwards desync-implying actions to `captures/unknown.packets-*.pcap`; a join replaces the whole grid from the existing `player_attributes_for` RCON query. Payload layouts, the 231 length fix, and the desync rule: `docs/protocol-notes.md`.
- `lib/input_actions_21.rb` — THE stable-2.1 table: `ACTIONS_21` (name + C→S payload length per type id). Hand-maintained: corrections come from `tools/validate_actions.rb` diffing against `/toggle-action-logging`. 2.1 is the released stable version and the decode default; 2.0 is retired and kept only as reference (`external/input_actions_dump.txt` is documentation for improving 2.1).
- `lib/server_detect.rb` — Auto-detects a running factorio server
  (game port, RCON endpoint, server IPs, dedicated-server detection)
- `lib/player_backup.rb` — the `player_backup` feature (config.yaml `plugins:`), a class the sniffer's `Plugins::PluginSet` builds and dispatches `on_start` (one whole-roster RCON query: every player `game.players` knows, offline included, with colour + the entire quickbar + `online_time` — `RconClient#roster_backup`, so players who never join while we run are covered too) and `on_join_enriched` to — no glue in the sniffer at all. Keeps a NAME-keyed copy of every player's quickbar AND colour in `players-backup.json` (game indexes reset with a save, players-cache.json does not), RESTORES the bar AND the colour in ONE RCON command (`RconClient#restore_player` — `LuaPlayer.color` is writable, unlike `online_time`) whenever a player joins a NEW save: the game hands out the DEFAULTS (a starting quickbar, a palette colour) and both look like real state, so the play-time reset is what gates the restore, and the snapshot is skipped or the defaults would overwrite the backup. Otherwise (same save) the in-game state is the truth: a bar is snapshotted, a colour re-picked over the wire wins, and an EMPTY bar is the one that gets the saved one written back. ALSO keeps the play time that outlives a save: `online_time` (ticks from earlier saves) + `online_time_seen` (this save's total at the last sync) — `LuaPlayer.online_time` is read-only, so a base is the only way to add it; `#sync_times` turns a live total that DROPPED (the save's clock restarted) into a base — read off the game's own RCON number only (roster/join), since our PlayerAttrs mirror undercounts an unseeded player and a false reset would INVENT time — and pushes it into `PlayerAttrs#set_foreign_bases`, so `online_time_ticks` = live + earlier saves and the Hivemind join prompts stay right. Synced on the roster snapshot, every join and every leave (`on_player_left`) — Biter Battles' equivalent is `utils/datastore/session_data.lua` in their scenario. No copy of the file: it is the one artifact here that cannot be rebuilt from anywhere else, so `cp players-backup.json{,.bak}` by hand when starting a new save. This is the model for a feature: `lib/foo.rb` defines `class Foo`, one list entry, no edits to the host.
- `lib/rcon_client.rb` — RCON queries via `rcon.print` + `helpers.table_to_json` (JSON), `#say` (Lua-quoted `game.print`), `#command` (raw console cmd), `#server_version` (`helpers.game_version`), `#player_attributes_for(index_or_name)` (the join-time query, by game INDEX: attrs + the whole quickbar as item wire ids in ONE command, with the read loop chosen from `#server_version`; the live-verified API and its traps are in `docs/rcon-knowledge.md`)
- `lib/player_db.rb` — Player ID→name mapping (`players-cache.json`) + per-player language overrides (`players-locale.json`, set via `/locales`)
- `lib/player_attrs.rb` — Mirrors LuaPlayer attributes (connected/admin/online_time), seeded once from RCON, maintained by packets; online_time computed lazily from the game tick (never incremented), plus the `foreign_base` the player_backup feature adds (ticks from earlier saves — the game cannot be told, so it is additive)
- `lib/plugins.rb` — the plugin convention: a `plugins:` list in a config file IS the list (no registry, no catalogue), a name in it is a file, and the file's CamelCase CLASS is what gets built. Names are SYMBOLS inside the set (`:hivemind`, `:followups`) — YAML gives strings, so `Plugins.list!` normalizes at the boundary and a typo'd call site is a NameError, not a silent miss; a name reaches the filesystem as its text. `dispatch:` names the subset EVENTS are sent to: the sniffer's `hivemind`/`translation` are listed for their files but are objects it constructs, so nothing is dispatched to them and they are never built as features. One `Plugins::PluginSet` per OWNER, holding that owner's list (plus `dir:`/`prefix:`/`namespace:` for a host that keeps its features prefixed and namespaced — Hivemind's `hivemind_persistence.rb` → `HivemindPersistence`). Each feature is constructed with its OWNER, so it reads shared state (`hive_config`, `rcon`, `player_db`) through the interface the owner publishes. Dispatch is by name: `@plugins.emit(:on_join_enriched, …)` reaches every feature that implements it — no base class, no empty handlers, and the emitter call sites are the whole event catalogue, so a new feature never means editing the owner. A feature that is not there, or will not build, is reported and left out (never half-alive). `Plugins.list!` is the startup rejection of an absent `plugins:` and `Plugins.load_files(names)` requires the files the list names without building anything — how the sniffer's `hivemind`/`translation` entries (objects it constructs, NOT features) get their classes loaded before the first line asks them anything; `test/plugins_test.rb` reads the entry point's class references and resolves each one.

- `lib/hivemind.rb` — Hivemind AI agent (`HivemindAgent` — itself a plugin FEATURE (config.yaml `plugins:`): the sniffer's PluginSet builds it with the sniffer as owner, chat rides the `emit(:on_chat)` bus (sync-light `on_chat` → `handle_chat` on its own worker), joins/leaves ride `emit(:on_player_event)`, and replies flow back through `owner.publish_chat(:hivemind, …)`; prompts in `lib/hivemind_prompts.rb`, tools in `lib/hivemind_tools.rb`, and its OWN features — `persistence`/`compaction`/`followups`/`logwatcher`/`tags` (the `lib/hivemind_*.rb` files, classes built by the agent's own `Plugins::PluginSet` with the agent as owner; logwatcher, followups, tags and persistence are converted, compaction is still mixed in by the interim `mix_modules_into` (and named in `HivemindAgent.still_modules`) that their conversions delete). Listed in config-hivemind.yaml `plugins:`, so a feature that is off is never required and never built; the agent reaches one by name (`plugins[:compaction]`), and a converted call site needs no `plugin?` guard): `HivemindReply` [model-facing name "reply"], `RconQuery`, `ScheduleFollowUp`/`CancelFollowUp` (only while the `followups` plugin is on), `SetPlayerLanguages` (a Hivemind tool gated on `Plugins.enabled?('translation')`), and — in `lib/hivemind_tags.rb`, the `tags` plugin — `SetPlayerTag` (the model's only write to game state, so it is one list entry to remove): answers in-game chat containing "hivemind" (case-insensitive) via ruby_llm. Replies via RCON `game.print` (reply tool, Lua-quoted); read-only RCON queries via `rcon_query` tool; player tags via `set_player_tag` (the only state-changing tool, only while the `tags` plugin is listed; its instruction asks the model to set tags once it knows a player and revise them as their role changes). **Scheduled follow-ups**: `schedule_followup` / `cancel_followup` tools (JS `setTimeout`/`clearTimeout` analog) — the model sets a timer for a later turn (e.g. "check whether spawn is held in 10 minutes"); a single scheduler thread (condition-variable sleep, serialized with asks via the same mutex) fires a fresh turn with the current context + the task; entries persist with absolute deadlines, are re-armed on restart, and survive compaction. Tools re-registered before every ask (fresh instances each turn). To pick up code changes, stop and restart the sniffer. Hivemind's own plugin list is read once at startup; a module already mixed in can't be un-mixed, so swapping the list needs a restart. Personality: omniscient factory-consciousness with a touch of HAL (lives in `memories/SOUL.md`, seeded from `DEFAULT_SOUL`, evolved by compaction). Context per trigger: online players, play-time/admin stats (system prompt + per-turn snapshot) + INCREMENTAL console lines (chat/join/leave since the last prompt — never duplicated). LLM-generated join briefings (`greet_interval` in config: greet the player by name — their memory rides along — AND brief them on the run so far, since they cannot see what happened before they arrived; the prompt carries total play time + admin status). **Memory compaction** (`compact_memory!`): one single-pass LLM turn in a throwaway chat replaying the live thread (input-token cache reused) that rewrites every keyed memory as delimited plain-text sections (no tools — the gateway drops tool-call args); then trims the compacted range keeping a recent tail (distill-then-trim — `/compact` is now the only session clear; `/forget`/`/clear` were removed, and memories are kept). See `docs/ai-agent.md`.
- `lib/action_validator.rb` — the `action_validator` feature (config.yaml `plugins:`): runtime action-ID validation. RECEIVES factorio-current.log's `/toggle-action-logging` lines (`Action performed [tick player name]`) — the host tails the file ONCE and fans lines to every consumer as `:on_log_line` (one reader thread, not one per feature; see `FactorioPacketTools#start_log_watcher`) — and joins them against the decoded actions by (tick, player, position) — flags MISMATCH / NOT-IN-TABLE at runtime, votes (wire id → log name) for pinning unidentified action ids, and flags a lost action when the log and wire sequences differ in length. Segment payloads (chat, blueprint-shelf updates) are skipped: they carry `total_segs` and never appear as `Action performed` lines. Server mode feeds C→S only; client mode feeds the S→C echo only — the log's tick is the SERVER-processed tick, and the C→S closure carries the local tick (often 1–2 earlier), so feeding both let the C→S copy consume the log line first and shifted the later echoes. The S→C echo carries every player's action. Log lines older than the capture's tick window (a truncated/replaced log replayed from the top) are skipped, not counted as misdecodes. Buffers are tick-window-evicted (TICK_WINDOW) with a FIFO entry cap (MAX_BUFFER_ENTRIES); consumed entries purge after each correlation.
- `lib/pcap.rb` — PcapWriter / PcapReader
- `lib/live_capture.rb` — pcaprub live capture (msg-13 fast path)
- `lib/map_download.rb` — the CLIENT-MODE roster seed: reassembles the map download off the live stream (msg 13 blocks, one hash store under a mutex on the capture thread; a worker thread concatenates them once the stream goes quiet and hands the archive to the roster tool) — the only way a client learns the players who were already in the game. No config: on in client mode, off in server mode (the server has the save on disk and RCON). `config.yaml `roster_save:` seeds the same roster from a save on disk at startup (a specific `.zip` or a directory, auto-detecting the newest), so a restart gets the up-to-date roster without RCON. `docs/save-file-format.md`
- `tools/rcon.rb` — RCON CLI (status/players/exec/raw)
- `tools/server_rank.rb` — server rank by player count: API seed (cached) + live UDP refresh, `--say` prints in-game via RCON
- `tools/query_server.rb` — direct UDP probe of one server (msg 16→17, via lib/server_probe.rb): version/mods/tags/players for HOST:PORT args
- `lib/matchmaking.rb` — `FactorioMatchmaking`, the HTTPS matchmaking API (`multiplayer.factorio.com/get-games`, what the in-game server browser reads) + `~/.cache` seeding (every entry carries host_address, so no details call is needed). NOT the UDP probe: that is `FactorioProtocol::GAME_INFO_REQUEST` + `lib/server_probe.rb`
- `lib/server_probe.rb` — `FactorioServerProbe`, the TRANSPORT for that probe and nothing else: address/DNS, socket, timeout+retry, threaded refresh over a list. All wire format is on FactorioProtocol (`GAME_INFO_REQUEST`, `reassemble_fragments`, `parse_game_info`, `strip_markup`). Presentation (`format_info`) lives in the tool that prints it.
- `lib/factorio_save.rb` — the SAVE format's reader: the player-record
  fields (name anchor, play-time/last-online pair, locale framing) with
  `FactorioSave::Roster`, a streaming scanner over a decompressed level.dat,
  plus `lua_value`/`lua_table` — the LuaValue serialization a save uses for
  every Lua table, which is also how a client sends its mod settings in msg 4
  (shared with `FactorioProtocol::ConnectionConfirmPacket`, which now decodes
  each join's mod list and settings from fragment 0).
  `tools/extract_players_from_save.rb` is the CLI over the roster scanner.
- `lib/factorio_property_tree.rb` — the `mod-settings.dat` / msg-4 settings container
  (PropertyTree: `[type][any_type][payload]`, keys `[flag][len][bytes]`), implemented
  from the reference codec the server's `tools/sync-mod-settings` pins. Verified against
  a real join: 10 settings, the walk ends on the exact message end. Also reads a
  whole mod-settings.dat envelope (version + has_quality + data tree) — the
  server's own file decodes with zero bytes left over. The SAVE is a different
  format (no PropertyTree dictionary parses inside a player record), so this
  does not extend to save data.
- `lib/factorio_wire.rb` — the binary primitives BOTH formats are read with,
  used as a BASE: `extend FactorioWire` gives the format modules
  (`FactorioSave`, `FactorioProtocol`) the reader, `include FactorioWire`
  gives the packet classes (`FactorioProtocol::WireDecode`) the same one
  under the plain name. One length-prefixed string reader for both: the same
  `[length][bytes]` shape, with the packet protocol's uint32v length and no
  terminator vs the save's NUL-terminated one. A failed read is nil (a
  misdecode, never a scrubbed guess) so callers keep the frame.
- `tools/item_db.rb` — regenerate item/entity prototype ID→name dumps from RCON (wire IDs = `prototypes.item` / `prototypes.entity` iteration order)
- `tools/extract_players_from_save.rb` — recover the FULL roster (1-indexed game index → {name, online_time_ticks, last_online_tick, locale}, everyone who ever joined, from the save's player-record run; name + play time + last-online verified 338/338 against a live `game.players` dump, locale 290/338 with zero wrong values) from a save archive or a decompressed level.dat. It needs NO cache — a player record is a name with the play-time pair in front of it — which is what makes CLIENT MODE work: the map download is the server's save, so seeding players-cache.json from it names everyone already in the game (and their locale, which the wire never carries: zero locale codes in 380 MB of captures). When the cache does have names they also anchor the run; a name at a different index is flagged and REPLACED by the save's index (the save is authoritative; the old id's fields move to the new one, and stale duplicate-name ids are dropped). `--merge` writes names, and a locale only where the cache has none (a known locale is never overwritten; differences are reported, the cache can hold an older one). Recipe in `docs/save-file-format.md`, format in `docs/save/level-dat.md`
- `tools/validate_actions.rb` — validate input-action wire IDs against `/toggle-action-logging` output (correlate `Action performed [tick player Name]` lines with packet captures by tick; flags OK/MISMATCH/NOT-IN-TABLE; `--suggest` prints a corrected table). Offline, 2.1-only, streaming: streams the capture and the log sequentially in one paced merge (pre-capture log history skipped; O(1) memory — no threads). Run: `ruby tools/validate_actions.rb --pcap captures/*.pcap --suggest`. (Live validation lives in the `action_validator` plugin, not here.)
- `tools/measure_action_lens.rb` — the ONE tool for C→S action lengths (now audits the ACTION TABLE itself, the separate lens files are gone): default = what is still undecoded (worst first), `--decide` = what the wire settles that the table lacks, `--type N` = one type with its candidate tally, `--check` = do the table's fixed lengths still agree with the wire. It never writes the table — confirmed lengths fold into `lib/input_actions_21.rb` directly. Run over the FULL rolling captures, not the unknown-packet ones: those contain only what the old decoder got wrong, so rare actions appear once or twice there. Uses `tools/action_len_solver.rb` (the tested core).
- `players-cache.json` — 1-indexed player ID→name/locale cache (per-server/savefile; re-seeded from RCON), plus per-player `color` (`LuaPlayer.color` as [r,g,b,a] 0..1 — from RCON, and from the packets too: `set_player_color` (2.0 wire 296, stable 2.1 wire 312) is 4 UNORM bytes R,G,B,A, measured against the save in `docs/protocol-notes.md`) and `quickbar` (fixed 10 pages × 10 slots of item prototype ids) and `quickbar_page` tracked from the capture stream
- `players-locale.json` — name-keyed language overrides ({"<player>":["en","pt"]}), set via `/locales`
- `players-backup.json` — name-keyed copies (`{name: {quickbar: 10×10 item ids, color: [r,g,b,a], online_time: ticks from earlier saves, online_time_seen: this save's total at the last sync}}`) written by the `player_backup` plugin; the one cache that outlives a save change
- `external/` — Game dumps (`input_actions_dump.txt`, `data-raw-dump.json`, `item_prototypes_runtime.txt`, `entity_prototypes_runtime.txt`, …)

## Docs (details live here, not in this file)

- `docs/README.md` — Protocol reference (network layer, packets, actions)
- `docs/protocol-notes.md` — Session-verified protocol findings, fixed
  issues, unknown types, chat formats, echo lengths, version-dependent IDs
- `docs/ai-agent.md` — Hivemind agent: tools, context (online/stats/
  incremental console lines), join greetings, auth, personality
- `docs/grief-analysis.md` — investigating "who did X at position Y"
  from captures (position-bearing actions, mining's blind spot,
  correlation workflow)
- `docs/server-mode.md` — Server mode, auto-detection, RCON,
  interactive filter console
- `docs/rcon-knowledge.md` — RCON knowledge base: rcon.print / helpers.table_to_json
  data channel, `helpers.write_file` dumps to script-output, `prototypes.*`
  iteration order (= wire IDs), `helpers.game_version`, response-size cap,
  gotchas. Read this before writing new RCON queries.
- `docs/player-mapping.md` — Peer IDs vs game indexes, save-file findings
- `docs/save/`, `docs/save-file-format.md` — Save/map-download internals

## Critical Invariants

- **Player IDs**: 0-indexed in protocol, 1-indexed in game and
  `players-cache.json`. Add `+1` to decoded values. Network peer ids are NOT game
  indexes (see `docs/player-mapping.md`).
- **Online tracking**: the sniffer keeps a live `name → index` map of
  players currently in-game (`FactorioPacketTools#online_players`) — seeded
  from the RCON roster, updated on NewPeerInfo / PeerDisconnect / the C→S
  PeerDisconnect quit signal, indexes bound by C→S heartbeats. The Hivemind agent reads the packet-derived
  `@attrs` cache instead of querying RCON for roster/stats
  (targeted RCON lookup only for newly joined players).
- **Server mode captures and analyzes ONLY C→S packets** (the server's
  S→C broadcasts are N duplicates per event and the capture filter drops
  them; there is no S→C analysis at all). Every join/leave signal must
  come from the client side: joins = msg-4 username + first-C→S-heartbeat
  index confirm; clean quits = a `PeerDisconnect` synchronizer action in
  the client's FINAL C→S heartbeat (capture-verified: reason=0, no
  peer_id — the peer_id form is the S→C broadcast, which we never see).
  msg 14 (RequestForHeartbeatWhenDisconnecting) is kept as a fallback
  path but has never been observed in captures. Crashes/timeouts send
  neither — they are caught by the heartbeat watchdog instead: a
  server-mode thread tracks each player's last C→S heartbeat in their
  PlayerAttrs record (:hb on the name-keyed attrs record — one hash, one
  lock; hb stamped on EVERY incoming packet from the player's IP and at
  every roster/join/bind, plus by index for any heartbeat carrying real
  input actions — the sender's game index names it directly, which
  reaches roster-seeded and NAT'd players whose IP was never learned)
  and drops players silent for HEARTBEAT_TIMEOUT
  (30s, deliberately high — a false positive forces a rejoin, a false
  negative just registers late). Fires
  on_player_event(:timeout) → console line so the LLM sees the roster
  change. Client mode needs no watchdog: the server detects the drop and
  broadcasts S→C PeerDisconnect, which the normal leave path handles.
- **Join/leave in server mode (C→S only)**: joins are detected at the
  msg-4 + first-C→S-heartbeat confirm ("confirmed as game player #N") →
  `HivemindAgent#on_player_event(:joined, …)` (fires the greeting); clean
  leaves via the C→S `PeerDisconnect` sync action in the client's final
  heartbeat → `on_player_event(:left, …)` (console queue only, no reply).
  A join appends to the sequential player list: the confirmed game index
  must be max known index + 1 (a new player) or an index already owned by
  the same name (returning). Anything else is flagged as a misdecoded join
  (warned once, counted in the summary, frame kept in `unknown.packets`) and
  NOT written to `players-cache.json`. S→C `NewPeerInfo` peer ids are
  validated as strictly above the last observed id (gaps are real: the
  connection-accept list only holds CURRENTLY online peers, so a late capture
  can jump 803→833); peer ids are a per-connection counter, never game indexes
  — `ConnectionAcceptOrDeny` peer ids map
  disconnect names only, which is what keeps stale high ids (Player_749…)
  out of the cache.
- **PlayerAttrs** (`lib/player_attrs.rb`): mirrored LuaPlayer attributes
  (connected/admin/online_time) seeded once from RCON at startup, then
  maintained by packets (NewPeerInfo/PeerDisconnect/index binding).
  `online_time_ticks` is computed lazily from the game tick — previous
  sessions folded into a base, live session added on read; never
  auto-incremented.
- **Hivemind agent context** is built per trigger: system prompt carries
  online players + stats; each prompt ALSO carries only the console lines
  seen since the last prompt (a `@history_sent` pointer prevents
  duplication across calls). Agent replies live in the conversation
  (assistant messages) and are excluded from the console list. Console
  history/mutexes/pointers are plain ivars on this instance.
- **Client mode captures and analyzes BOTH directions** (no RCON, no
  broadcast duplicates — the client is one of the receivers), and has **no
  roster source except the map download**: the wire only shows players who
  join after us, and it carries no locale at all (measured — the save is the
  only copy that travels), so the save that arrives with the join is
  reassembled and the whole roster (names + locale) is seeded from it
  (`lib/map_download.rb`, runs off the capture thread). Server mode skips it
  (the save is on disk, RCON is authoritative). Setting `ip:` in config.yaml
  without `server:` forces client mode. Capture is ALWAYS on for live
  capture (pcap-read `-r` doesn't re-capture): auto-named timestamped files
  (`server-<port>-<ts>.pcap` / `client-<ip>-<ts>.pcap`) — the latest file
  IS the live one, no renames —
  and retention prunes across ALL runs of that identity (three bounds:
  rotate hourly / at 256 MB (`rotate_size:`), delete rotated files older
  than 72h (`keep:`), keep the rotated total under 512 MB (`max_size:`,
  oldest first); restarts open a new file (previous runs
  are already timestamped; empty files deleted on close). Captured
  pcaps are filtered by default: TransferBlocks (msg 13),
  keepalive-only heartbeats, and (server mode) outgoing S→C broadcasts are
  excluded — a 5h server capture went from ~460MB to ~20MB. `capture: full`
  records everything; `capture: save` keeps just the TransferBlocks
  (needed for `tools/extract_save_from_pcap.rb`). A `.gz` path compresses
  the pcap stream (~3-4x). See `docs/server-mode.md`.
- **Shutdown**: Ctrl-C raises `Interrupt`, caught by the entry point to call
  `FactorioPacketTools#finish` — closing the capture writers and printing the
  session summary. `players-cache.json` / `players-locale.json` persist between
  runs, and the always-on capture opens the next timestamped file on each run.
- **The action table is 2.1 stable** (measured C→S lengths folded
  INTO `ACTIONS_21`; 2026-10-26). 2.1 is the only RELEASED version and the
  only one a server runs. 2.0 is retired and removed from the runtime
  (`git tag protocol-2.0-final` keeps the old reference table). The stable
  numbering renumbered the experimental enum (+1 from the inserted action's
  band 16..40; start_walking 69→70, write_to_console 106→107, build 68→69)
  and dropped several defines the dump's build had (render_mode_changed has
  no dump slot; it lives at wire 310, log-verified). Two summary lines are the standing
  decoder-health measures: `undecoded actions:` (the to-do list) and
  `packets with a suspected desync:` (the damage — an unknown length desyncs
  the REST of that packet's actions). After the 2026-10-26 measured-length
  fold the full 11-capture replay reads **30 undecoded / 90,456 actions,
  24 desyncs** (was 170 undecoded types / 6,717 desynced packets before).
  The remaining unknowns: Unknown(255) (13×, host player, 1-2 byte small
  numbers — pin with the runtime validator) and Unknown(97) (1×).

  UPDATE 2026-10-27: S→C heartbeat wrapper identified and stripped. Type 85
  is a server_tick_info wrapper (12-byte body). Type 32 is
  stop_movement_in_the_next_tick (was mis-assigned
  toggle_enable_vehicle_logistics_while_moving in the dump — the 2.0 defines
  had it at id 82; 2.1 inserted it as a dedicated action at stable 32,
  shifting all dump ids >= 32 by +1, not >= 40 as previously coded). The
  full S→C capture (server-40220, 206k packets) decodes 25,045 real actions
  with 87 log-verified wire IDs and 0 mismatches (player index matched at
  player_off=0). Types 159 (player_join_game) and 248 (player_leave_game)
  added as S→C-only events.

  UPDATE 2026-10-28: Three client-mode captures (150048/161919/165529)
  with both C->S and S->C data pushed confirmed wire IDs from 87 to
  150-166. The generator pipeline (scratch/corr/gen_actions21.rb +
  experimental_actions.rb + OBS/MEASURED/SPECIAL hashes) was eliminated;
  lib/input_actions_21.rb is now hand-maintained directly, with
  corrections driven by tools/validate_actions.rb --suggest output.
  Key fixes:
  - Type 28/29: cycle_quality_up/down shifted +1 from dump positions (dump had
    names swapped — up/down in wrong order; an insertion at 27 pushes them to
    stable 28/29). 8+4 OK on old capture, 19+23 OK on latest.
  - Type 38: fast_entity_transfer (was delete_blueprint_library from dump+
    shift — the shift rule is wrong for this type; experimental table has a
    gap at 38). 10 MISMATCH on latest 165529 capture, 9 OK after adding
    length 1 (matching experimental type 279's shape).
  - Type 44: selected_entity_changed_very_close (was toggle_equipment_
    movement_bonus from dump; length fix nil→1 resolved 5→OK on old C->S).
  - Type 25: open_alerts_config_gui (1x on latest C->S capture; dump's
    cycle_blueprint_book_forwards likely shifted in 2.1). Length 0 (no body).
  - Type 304: display_scale_changed (3 OK) — new 2.1-only type.
  - Types 23/24 reverted to dump names (open_bonus_gui/open_achievements_gui)
    — the S->C-verified close_gui overrides (1-2 occurrences) were false
    correlations; C->S captures show different false matches. Type 5 left as
    open_gui (1 S->C match was too weak vs C->S fixtures).
  - All remaining MISMATCH/NOT-IN-TABLE entries are ≤4 occurrences, dominated
    by false correlations with common action names (stop_walking type 1,
    zoom_around_point type 129, selected_entity_cleared type 9, close_gui
    type 61, etc.) matching at wrong types due to desyncs from nil-length
    gap types. Cross-checked three captures (150048/161919/165529): all
    disagreements are at ≤4 occurrence false-correlation types. Type 7
    confirmed as close_gui (6129 OK on old C->S; the 165529 capture's 2
    take_equipment matches are false with type 124).
- **Chat payloads are `[uint16v player][uint32v len][text]`**, and the
  player index is 0xff-ESCAPED past 254: on a busy server every message
  starts `ff <u16 LE>`, and reading that as the 5-byte uint32v length escape
  printed 82 of 255 captured messages as `"?d\u0001$mod bug..."`. Structure,
  not observed index bytes (the old 0x05/0x0b/0x24/… prefixes), and one
  strict branch (declared length must equal the remaining bytes) covers
  every player. Split messages: segment 0 carries the header,
  continuations are raw text (`chat_action_data` merges first). Fixtures:
  `test/fixtures/chat_variations.rb` + two whole packets in
  `test/fixtures/packets.rb`.
- **Invalid player IDs are membership-checked on live capture, distance-
  checked on replay**: live capture seeds the roster from RCON (server mode)
  or the save/map download (client mode), so a decoded `game_player` with no
  players-cache entry is evidence of a misdecode — it is warned once per id,
  counted, and the frame goes to `unknown.packets` for audit. `-r` replay
  defaults to the old window (`UNKNOWN_PLAYER_WINDOW` = 100 above the highest
  known index) because an old capture and today's cache need not be the same
  world; `strict_player_ids: true` forces membership checking there too.
  History: membership on the 2026-10-03 set fired on 11,196 packets — 10,772
  for players 357/360, real players the cache had no name for — so the window
  cut it to 866 flagged packets, all signal. The live roster (RCON + save +
  join packets) is what makes membership trustworthy now. The check runs only
  once a roster source has answered (`@roster_ready`); an empty cold cache is
  not a reason to flag every player before the map download seeds it.
- **Fixture provenance** (test/fixtures/packets.rb): every fixture entry's
  `description` states its source. Entries regenerated from the stable
  captures carry file + packet number + game tick and COMPUTED expectations
  (scratch/gen_fixtures21.rb + scratch/splice_fixtures.rb) — never
  hand-edited bytes. A hand-patched hex (e.g. a type byte bumped 106→107 in
  2c9e2a0) is untrusted by definition: replace it from a capture or flag it
  in the description. S→C echo fixtures are GONE: server mode never captures
  S→C, no stable S→C corpus exists, and C→S carries all the info; the S→C
  direction tests use synthetic heartbeats (build_server_heartbeat).
- **Decode speed** (measured, not guessed; profile with vernier, recipe in
  Usage): a full `-r` replay of a 38 MB capture went **16s → 6.1s**, the
  25-capture rolling set ~4.8min → 1.8min. Three things were half the time,
  all found by sampling and all now load-bearing invariants:
  - **`players-cache.json` is written only when a record actually CHANGES**
    (`PlayerDatabase#[]=` no-ops an identical merge; `remove_other_entries_for`
    rebuilds the name index only when a slot moved). Re-stating the same
    mapping used to rewrite the whole file — thousands of times in one
    replay. Do not add a "persist on every call" path back.
  - **A join/index confirm fires ONCE per binding.** The client-mode
    `[self] confirmed as game player #N` line had no guard and re-fired on
    every action-carrying heartbeat (5868 identical lines + 5868 full cache
    writes in one capture).
  - **Console timestamps are built at the PRINT site** (`log_ts`), not per
    action: `Time.at` + `strftime` was ~13% of a replay.
  - Per-packet IP strings use `getbyte` + interpolation, not
    `bytes.join('.')` (4.5x faster, twice per packet).
- **`-r` takes a whole SET in one process** (`-r a.pcap -r b.pcap`, or one
  `-r` followed by a shell glob; sniffer state carries across files, so a
  set reads as one session). N processes cost N Ruby startups — for the 14
  uncompressed server captures that is 56s of shell + 30s of decode vs 30s
  total. A file that cannot be read (a .gz still being written, a truncated
  rotation) is warned about and skipped, keeping whatever it yielded.
- **Interactive filter console**: type `/show NAME`, `/actions`,
  `/noise`, `/debug` (toggle decoded per-action lines), `/stats`,
  `/compact` (distill the session into memory, then wipe it — starts
  fresh), `/locales NAME en,pt` (set a player's language overrides — used
  when their Factorio locale lies, e.g. pt-BR interface but English;
  `-` clears, bare `/locales` lists) at the sniffer's stdin to filter
  console output live. Chat is always printed.
  See `docs/server-mode.md`.
- **RCON data channel**: `rcon.print(data)` returns values through RCON;
  `helpers.table_to_json` for tables (JSON, parsed with stdlib
  `JSON.parse`); large payloads go through `helpers.write_file` (no 4KB
  cap). `/players` lists names only (no index). See
  `docs/rcon-knowledge.md` for the full API knowledge base (incl.
  `helpers.write_file` for large dumps, `prototypes.*` ordering).
- **RCON writes are SERVER-side only**: `helpers.write_file` is ALWAYS
  called with `for_player = 0` (explicit server target) — never a player
  index, which writes to that player's client and is skipped via `/sc`.
  Deterministic mod code would run on server + all clients, so `0` pins
  the write to the server's `script-output/` where the sniffer reads it
  locally. Guarded by a test (server_mode_test checks every write_file
  call's last arg is 0).

## Config surface policy

Keep the CLI/env surface from growing. Rules for adding any flag or env
var (applies to new AND existing knobs):

1. **Hardcode first.** Add a config option only when you can name a concrete
   run that sets it to a non-default value. (`memories/` remains hardcoded.)
2. **One source per setting.** Hivemind behavior comes from
   `config-hivemind.yaml`; no Hivemind CLI args or non-secret env vars.
   Sniffer features are plugins, switched by the ONE `plugins:` list in
   `config.yaml` (see `lib/plugins.rb`) — never by a per-feature flag. It is
   mandatory: the sniffer refuses to start without it, so the feature set is
   always an explicit choice, never a hardcoded default.
   Hivemind's own plugins are a `plugins:` list in ITS config file.
3. **Missing or auto-detect-failed is an ERROR**, never a silent fallback —
   and it fails WHERE IT IS USED, not from a validation list: every config
   key is read with `Hash#fetch` (a missing one raises `KeyError` naming
   itself), an argos install that isn't there raises, a Google backend with no
   key raises. A plugin whose prerequisites fail is reported disabled, never
   half-alive (a translation agent that starts and never translates a word is
   the failure mode this rule exists to prevent).
4. **Secrets are env-first**: env var, else auto-detection, else a key in the
   gitignored `config*.yaml` (`google_api_key:` in config-translation.yaml,
   `api_key:` on a Hivemind provider group) — never a CLI flag (shell
   history / `ps` / committed scripts leak it) and NEVER a literal in code
   (tools/rcon.rb once shipped the server's RCON password as its last
   fallback — a committed secret is leaked the moment it's pushed).
   `HIVE_API_KEY` is the only Hivemind env var.
5. **One feature = one toggle.** No flag AND env for the same on/off
   switch (there's no `--ai-agent`/`HIVE_AGENT` pair — the agent is
   implicit: the `hivemind` plugin plus server mode and a key for the
   startup model, env or the group's `api_key:`).
6. **Deterministic defaults don't get knobs.** If a value can only ever
   be one thing, hardcode it.

Current AI config surface:

| Knob | Source | Type |
|------|--------|------|
| features on/off (hivemind, translation) | `plugins:` in `config.yaml` — MANDATORY, no default | YAML list |
| hivemind's own plugins on/off (persistence, compaction, followups, logwatcher, tags) | `plugins:` in `config-hivemind.yaml` — required like every other key there | YAML list |
| agent actually started | `hivemind` listed + server-mode RCON + a key for the startup model — the feature's constructor enforces them (missing → `[plugin] hivemind disabled` warn at build) | YAML list + env |
| api key | `api_key_env` (default `HIVE_API_KEY`) / `api_key:` | env (secret), YAML fallback |
| required models, per-provider provider/api_base, prompts, limits | `config-hivemind.yaml` | YAML |
| followups keys (`min_followup_delay`, `max_pending_followups`) | `config-hivemind.yaml`, read by the plugin (missing → KeyError there) | YAML |
| logwatcher keys (`log_turn_events`, `log_event_interval`) | `config-hivemind.yaml`, read by the feature (missing → KeyError there) | YAML |
| shortest round that counts as a round ending | hardcoded `MIN_ROUND_MINUTES = 10` (the log line's own `minutes=`) | — |
| translation `backend`, `whitelist`, `min_interval` (no code defaults) | `config-translation.yaml`, read with fetch | YAML |
| google key | `GOOGLE_TRANSLATE_API_KEY` / `google_api_key:` | env (secret), YAML fallback |

## Usage

```bash
# Server host, everything auto-detected (interface, port, IP, RCON):
sudo ruby factorio-packettools.rb

# With the Hivemind AI agent — set HIVE_API_KEY and the agent starts in
# server mode (no flag, no extra args); features themselves are the
# `plugins:` list in config.yaml:
HIVE_API_KEY=... sudo ruby factorio-packettools.rb
# (Capture is always on; retention defaults bound disk. No key = no AI.
# Hivemind behavior is configured in config-hivemind.yaml.)

# Decode a pcap (2.1 stable; 2.0 is retired):
ruby factorio-packettools.rb -r capture.pcap

# Validate input-action wire IDs against /toggle-action-logging (runs
# offline, reverting a capture against the log; capture always on for
# live capture — the action_validator plugin is the live path):
ruby tools/validate_actions.rb --pcap captures/client-*.pcap.gz --suggest

# C→S action lengths (2.1): audit the table against the captures; confirmed
# lengths fold directly into lib/input_actions_21.rb:
ruby tools/measure_action_lens.rb captures/*.pcap.gz          # what is left
ruby tools/measure_action_lens.rb --decide captures/server-*.pcap.gz  # what the wire settles
ruby tools/measure_action_lens.rb --check captures/server-*.pcap.gz   # do the table's lengths still agree

# Whole roster (incl. everyone who left) + play time from a save, names merged
# (client mode: capture: save, then reassemble the map download first):
ruby tools/extract_save_from_pcap.rb captures/client-*.pcap outdir
ruby tools/extract_players_from_save.rb outdir/save.zip players-cache.json --merge

# Decode a whole capture set in one process (state carries across files):
ruby factorio-packettools.rb -r captures/*.pcap

# Client mode / pcap analysis (client mode: `ip: <client ip>` in config.yaml,
# with no `server:` key):
sudo ruby factorio-packettools.rb
ruby factorio-packettools.rb -r capture.pcap

# RCON admin:
ruby tools/rcon.rb status          # version/players/admins/time/evolution
ruby tools/rcon.rb exec "/shout hi"  # or /sc for silent Lua

# Profile a full capture decode (sampling profiler, dev-only gem):
# Profiling is a one-off and vernier is deliberately NOT in the Gemfile
# (no "optional gem" in bundler, and a profiler is not something every
# `bundle install` should fetch): gem install it once, outside the bundle,
# and run it without `bundle exec` — the child ruby still gets the app's
# gems, because factorio-packettools.rb requires bundler/setup itself.
gem install vernier
vernier run -- ruby factorio-packettools.rb -r captures/server-<port>-<ts>.pcap
vernier view --top 25 profile-*.vernier.json.gz

# Tests (bundle exec: server_mode/translation need the rcon gem, and it
# makes the whole suite runnable in one process — 365 runs, no version-table
# leakage between files):
#   bundle exec ruby -Ilib -e 'Dir["test/*_test.rb"].sort.each { |f| require File.expand_path(f) }'
#
# Individually:
bundle exec ruby -Ilib test/hivemind_test.rb             # hivemind agent core (triggers, context, greetings)
bundle exec ruby -Ilib test/hivemind_tools_test.rb       # RubyLLM tool classes
bundle exec ruby -Ilib test/hivemind_tags_test.rb        # the `tags` plugin: set_player_tag, on/off
bundle exec ruby -Ilib test/hivemind_persistence_test.rb # persistence plugin: session file round-trips
bundle exec ruby -Ilib test/hivemind_compaction_test.rb  # compaction plugin: long-term memory + /compact
bundle exec ruby -Ilib test/hivemind_followups_test.rb   # followups plugin: scheduled follow-ups
bundle exec ruby -Ilib test/plugins_test.rb              # the config.yaml `plugins:` list (hivemind sub-plugins: hivemind_test)
bundle exec ruby -Ilib test/server_mode_test.rb       # server mode + ops
bundle exec ruby -Ilib test/packet_fixtures_test.rb   # real captured packets
bundle exec ruby -Ilib test/factorio_protocol_test.rb # protocol unit tests
#   (2.0 lengths/entity refs/0xFF live in test/fixtures/packets.rb)
bundle exec ruby -Ilib test/action_len_solver_test.rb  # measured lengths re-derived from fixtures
bundle exec ruby -Ilib test/factorio_save_test.rb   # the save format's reader (strings, records)
bundle exec ruby -Ilib test/save_roster_test.rb        # roster recovery from a save (the CLI)
bundle exec ruby -Ilib test/map_download_test.rb      # live map-download reassembly + roster seed
```
