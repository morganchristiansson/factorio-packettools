# Sniffer Operations: Server Mode, Auto-Detection, RCON

Operational notes for running the sniffer on the game server host (the
current setup — dedicated server + RCON). Protocol internals live in
`docs/protocol-notes.md`; player mapping in `docs/player-mapping.md`.

## Capture-loop work

Decoding stays on the capture thread. Hivemind and translation receive events
through independent bounded worker queues (see `ai-agent.md`). Original chat
prints before either agent runs.

Heartbeat timeouts are checked after incoming packet processing, at most once
per monotonic second, only in live server mode. No watchdog thread: complete
traffic silence delays timeout announcements until another packet arrives.

Pcap records go directly to buffered Ruby IO/GzipWriter; no custom buffer,
flush thread, per-record flush, or fsync. Close/rotation finalizes the stream.
Live readers may see buffered batches. Rotation counts uncompressed bytes
(conservative for gzip); the total-size budget counts actual disk sizes.
Slow storage can still block capture—this is not a lossless-capture
guarantee.

**Restart fully when installing this threading change.** Existing objects
retain the old writer/watchdog state across a restart.

## Server Mode (`--server`)

Run the sniffer ON the game server host.

```bash
# Everything auto-detected — even the interface (only non-loopback
# interface wins; else server's --bind IP, else default route):
sudo ruby factorio-packettools.rb

# Server mode is AUTO-ENABLED for live capture when no explicit mode is
# given (no `server:`, no `ip:` in config.yaml) and a serving factorio
# process is detected on this host:
sudo ruby factorio-packettools.rb -i ens18
#   → "Auto-enabled SERVER mode: running factorio server detected (pid N)"

# Explicit overrides live in config.yaml:
#   server: true     # force server mode
#   ip: 10.0.99.121  # this host's Factorio IP(s) — filters, and (without
#                    # `server:`) forces client mode

# Force client mode: set `ip:` to your game client's IP in config.yaml
# (no `server:` key) — or `server: false`.
```

Behavior:
- **Incoming-only analysis**: only client→server (msg 6) packets are parsed.
  Every player action arrives at the server exactly once; the server then
  broadcasts it to all N clients, so the outgoing direction is N duplicates.
  Tradeoff (documented): incoming packets have NOT yet been validated/echoed
  by the server — cross-check with RCON (`tools/rcon.rb`) if needed.
- **Save downloads excluded**: map-download TransferBlocks (msg 13, ~40 MB
  per joining player) are dropped entirely — no analysis, no capture. The
  server already has the save on disk.
- **Capture is C→S only by default** (capture is always on in live
  mode): the capture filter records only packets destined for the server,
  so the pcap mirrors the analysis (no S→C broadcast duplicates).
  `capture: full` records both directions (still excepting
  TransferBlocks).
- **Roster learning**: every client's ConnectionRequestReplyConfirm (msg 4,
  incoming) registers `src_ip → username`; their first C→S heartbeat action
  binds the real game index (like the old client-side "self" learning, but
  for every client).
- **RCON roster load**: at startup (live capture, server mode) one
  `player_attributes` query seeds `PlayerAttrs` and the player DB, so
  existing players are named immediately. Later joiners are learned from
  the packet stream (msg 4 + heartbeat), so no periodic refresh is needed.
  `--no-rcon` disables.
- **Join/leave events**: joins are seen via msg 4 ("X connected") + the
  first-C→S-heartbeat index confirm ("confirmed as game player #N").
  Clean leaves are seen via the C→S `PeerDisconnect` synchronizer action
  in the client's final heartbeat (the S→C broadcast form with a peer_id
  is never seen — no S→C analysis). Crashes/timeouts send nothing and
  linger in the live roster until reload/restart; poll RCON `/players`
  for authoritative roster changes.

### Auto-enable rule

Server mode auto-engages for LIVE capture only (an `-i` interface) when no
explicit mode flag is passed and `ServerDetect.serving?` is true.
`serving?` = dedicated flags OR hosting flags OR a wildcard-bound listening
UDP socket. Pcap reads are NEVER auto-enabled — the capture may be from a
different machine, and applying this host's server IPs as a direction
filter would silently drop everything.

## Auto-Detection (`lib/server_detect.rb`, shared with `tools/rcon.rb`)

- Finds the factorio process (`pgrep -x factorio` or /proc cmdline scan).
  With multiple factorio processes it prefers the one with a listening UDP
  socket (the actual game server).
- **Game port** = listening UDP socket owned by the process (fd socket
  inodes matched against `/proc/<pid>/net/udp[6]`; state column is field 3,
  NOT 2 — the remote address sits at field 2).
- RCON host/port/password from the cmdline `--rcon-bind`/`--rcon-password`.
- **Dedicated server detection** (two tiers):
  - `DEDICATED_ONLY_FLAGS` — `--start-server`, `--rcon-bind`,
    `--rcon-password`, `--server-settings`, `--console-log`, `--max-players`,
    autosave/whitelist/adminlist/banlist flags. Any match ⇒ dedicated server
    (the full client never accepts these).
  - `CLIENT_ALSO_FLAGS` — `--start-server-load-scenario`,
    `--start-server-load-latest`, `--map-settings`, `--map-gen-settings`.
    The full client technically accepts these (usually to host), so they
    only count as "hosting", not "dedicated".
  - Flag matching is whole-arg (`cmdline.split.include?`), so
    `--start-server` never matches `--start-server-load-scenario`.
- Server IPs = local IPv4s, default-route interface first (`/proc/net/route`).
- CLI precedence: explicit flags > auto-detect > defaults (34197 / all
  local IPs).

## RCON Client (`lib/rcon_client.rb`)

Getting data OUT of a Lua command over RCON: the console's `rcon` object
sends its argument back through the RCON connection as the command response
— the one clean channel:

RCON data queries use `rcon.print` with `helpers.table_to_json`; the
`player_attributes` query carries the 1-indexed game id, name, flags,
online/afk ticks, and locale. The built-in `/players` works but lists names
only, so it cannot bind packet actions to players.

**The startup roster is the identity source.** `game.players` knows EVERY
player of the current savefile (offline included), so the startup query
gives us index → name for all of them — the wire carries a name only for a
join we happened to watch, and a player who joined before the sniffer
started has no other source. The cache (`players-cache.json`) is therefore
seeded from that roster at startup, and it is VALID or NOTHING: it cannot
hold more players than the save has, no index may sit above the save's
last one, and its names must match the roster's. Fails any of those ⇒ the
whole cache is dropped — the file is per-SAVE (game indexes are handed
out per savefile), and a leftover from another save names a different
player at the same index: its quickbar and colour belong to someone else,
and the `player_backup` feature would restore them to the wrong player.
- Auth quirk: `authenticate!(ignore_first_packet: false)` — Factorio sends
  ONE auth reply, the gem's default expects two and times out.
- `/sc` (silent) instead of `/c` so commands don't print to players.

Protocol version (`RconClient#server_version`):
`rcon.print(helpers.game_version)` → `"2.1.14"`. Used for the
version-dependent RCON quickbar getter; input actions use the fixed 2.1
table (2.0 is retired). `tools/validate_actions.rb` re-validates IDs
against `/toggle-action-logging` output. See docs/protocol-notes.md.

`tools/rcon.rb` — CLI wrapper: `status`, `players`, `exec`, `raw`; env
overrides `RCON_HOST` / `RCON_PORT` / `RCON_PASSWORD`.

## Interactive Filter Console (stdin)

While running in a terminal, type commands at the sniffer (no restart, no
Ctrl-C needed) to filter the console output:

```
/show morganc              only show this player's actions
/show morganc alice        only show these players
/show +alice               add a player to the whitelist
/show -alice               remove a player
/show *                    clear the whitelist (show everyone)
/actions build             only show these action types
/noise change_multiplayer_config   hide these action types
/debug                     toggle decoded per-action lines (default hidden)
/filter                    show current filter state
/players                   list online players
/stats                     session summary
/locales                   list per-player language overrides
/locales NAME en,pt        set a player's languages (e.g. pt-BR interface
                           but actually English: /locales somePlayer en,pt)
/locales NAME -            clear a player's languages
/help                      list commands
```

- Language overrides are persisted to `players-locale.json` (name-keyed,
  unlike the id-keyed `players-cache.json`) and steer the translation
  agent: a player's effective languages = Factorio locale + overrides, so
  an `en` override stops their messages being translated and stops them
  receiving relay lines for English/pt/ru messages they already read.
  The translation agent itself is the `translation` plugin (config.yaml
  `plugins:`; see docs/ai-agent.md). Its config (config-translation.yaml) is
  required while it is on — `backend`, `whitelist`, `min_interval` all have
  no code defaults, and a backend that can't run (no argos binary or packs, a
  Google key missing) is a startup error reported as
  `[translate] Translation agent disabled: …`, never a silent no-op. The
  Hivemind agent can set the same overrides itself with `set_player_languages`
  — a Hivemind tool only offered while the translation plugin is loaded.

- Chat (`write_to_console`) is **always printed and exempt from all
  filters** — including the agent's decoded chat feed.
- Player/action matching is case-insensitive; filters survive Ctrl-C hot
  reloads (they're plain ivars on the persistent sniffer instance).
- The console reads stdin in a background thread and dispatches to the one
  long-lived sniffer instance. It exits silently when stdin isn't
  available (nohup/systemd/pcap mode).

## Shutting Down

Ctrl-C raises `Interrupt`, caught by the entry point to call
`FactorioPacketTools#finish` -- closing the capture writers and printing the
session summary. The always-on capture opens the next timestamped file on each
run, and `players-cache.json` / `players-locale.json` persist between runs.

## Tests

- `ruby -Ilib test/server_mode_test.rb` — server mode, auto-detect,
  dedicated detection, RCON roster parsing.
- `ruby -Ilib test/plugins_test.rb` — the `plugins:` feature list and the
  file resolution.
- `ruby -Ilib test/packet_fixtures_test.rb` — real captured packet fixtures.
- `ruby -Ilib test/factorio_protocol_test.rb` — protocol unit tests.
