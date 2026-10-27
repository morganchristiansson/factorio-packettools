# frozen_string_literal: true

# Factorio UDP protocol parser.
# Based on Hornwitser's Wireshark dissector (reverse-engineered from factorio.pdb).
module FactorioProtocol
  require_relative 'factorio_protocol/packets/heartbeat_packet'
  require_relative 'factorio_protocol/packets/connection_packets'
  require_relative 'factorio_protocol/position'
  require_relative 'factorio_protocol/quickbar'
  require_relative 'input_actions_20'
  require_relative 'input_actions_21'
  require_relative 'factorio_types'

  # ── Message Types ──────────────────────────────────────────────────
  MESSAGE_TYPES = {
    0 => 'Ping', 1 => 'PingReply',
    2 => 'ConnectionRequest', 3 => 'ConnectionRequestReply',
    4 => 'ConnectionRequestReplyConfirm', 5 => 'ConnectionAcceptOrDeny',
    6 => 'ClientToServerHeartbeat', 7 => 'ServerToClientHeartbeat',
    8 => 'GetOwnAddress', 9 => 'GetOwnAddressReply',
    10 => 'NatPunchRequest', 11 => 'NatPunch',
    12 => 'TransferBlockRequest', 13 => 'TransferBlock',
    14 => 'RequestForHeartbeatWhenDisconnecting',
    15 => 'LANBroadcast', 16 => 'GameInformationRequest',
    17 => 'GameInformationRequestReply', 18 => 'Empty',
  }.freeze

  SYNCHRONIZER_ACTIONS = {
    0x00 => 'GameEnd', 0x01 => 'PeerDisconnect', 0x02 => 'NewPeerInfo',
    0x03 => 'ClientChangedState', 0x04 => 'ClientShouldStartSendingTickClosures',
    0x05 => 'MapReadyForDownload', 0x06 => 'MapLoadingProgressUpdate',
    0x07 => 'MapSavingProgressUpdate', 0x08 => 'SavingForUpdate',
    0x09 => 'MapDownloadingProgressUpdate', 0x0a => 'CatchingUpProgressUpdate',
    0x0b => 'PeerDroppingProgressUpdate', 0x0c => 'PlayerDesynced',
    0x0d => 'BeginPause', 0x0e => 'EndPause',
    0x0f => 'SkippedTickClosure', 0x10 => 'SkippedTickClosureConfirm',
    0x11 => 'ChangeLatency', 0x12 => 'IncreasedLatencyConfirm',
    0x13 => 'SavingCountDown', 0x14 => 'AuxiliaryDataReadyForDownload',
    0x15 => 'AuxiliaryDataDownloadFinished',
  }.freeze

  # Data lengths for synchronizer action types (bytes after type byte, before peer_id).
  # nil = variable-length (handled by parse_synchronizer_action case logic).
  # 0x0f/0x10 carry an 8-byte (uint64) tick and 0x12 carries tick(8) +
  # latency(1) — NOT the dissector's 4-byte tick / 5-byte len. Verified
  # against server-34197.pcap pkt 1311: 21 sync actions consume the packet
  # byte-exactly only with these sizes (4-byte ticks desync the stream and
  # fabricate a NewPeerInfo "join" out of tick bytes — garbage username).
  SYNC_ACTION_LENS = {
    0x00 => 0, 0x01 => 1, 0x02 => nil, 0x03 => nil, 0x04 => 8,
    0x05 => nil, 0x06 => 1, 0x07 => 1, 0x08 => 0,
    0x09 => 1, 0x0a => 1, 0x0b => 1, 0x0c => 0,
    0x0d => 0, 0x0e => 0, 0x0f => 8, 0x10 => 8,
    0x11 => 1, 0x12 => 9, 0x13 => 8, 0x14 => 8, 0x15 => 0,
  }.freeze

  # ── Input Actions ──────────────────────────────────────────────────
  # [action_id] => [name, data_len]. ONE table per version, both
  # generated and log-verified (no experimental base + merge chain):
  #   2.1 (the released stable numbering): input_actions_21.rb —
  #       defines dump + measured +1 renumbering + log-verified overlays;
  #   2.0: input_actions_20.rb — defines dump + validated internal actions.
  #   data_len: 0 = no data, N = fixed N bytes, nil = variable/unknown
  #   (hit_unknown keeps the frame in unknown.packets; MEASURED lengths —
  #   tools/measure_action_lens.rb over the captures — are folded INTO the
  #   tables and marked in their source files).

  extend WireDecode

  # ── Action Name / Length Lookup ────────────────────────────────────

  def self.action_name(type)
    entry = actions[type]
    entry ? entry[0] : "Unknown(#{type})"
  end

  def self.action_len(type)
    entry = actions[type]
    entry ? entry[1] : nil
  end

  # ── Version-dependent tables (2.0 vs 2.1) ───────────────────────

  # The wire numbering of input actions is version-dependent: 2.1's stable
  # enum renumbered the low ids relative to 2.0 (start_walking 67 → 70,
  # write_to_console/chat 104 → 107 — verified on live 2.0.77 sessions and
  # on the 2026-10-26 stable captures). The stable numbering drifted again
  # (+1 from the inserted action's band in ids 16..40; input_actions_21.rb
  # tells the whole story). ACTIONS_20 is the 2.0 table.

  #
  # **2.1 is the DEFAULT** (2026-10-26): 2.1 is the released stable version
  # and the numbering servers run, so an undetectable version decodes as
  # 2.1 (2.0 is retired). The 2.0 tables stay selectable for replaying old
  # captures: the connection request's version string
  # (`FactorioProtocol.detect_version`, pre-scanned on `-r`) or
  # `protocol_version: "2.0"` in config.yaml picks them. The measured
  # C→S lengths ride along per version, so the default decode is also the
  # measured one.
  #
  # ONE table per version: 2.0 = ACTIONS_20 + SEGMENT_TYPES_20 (segments
  # separate there — chat rides its own segment enum), 2.1 = ACTIONS_21
  # for both (main action types and input-action segments share the
  # stable enum). Survives hot
  # reloads: the sniffer re-applies #select_version after reloading (its  # @protocol_version ivar outlives the `load`).
  class << self
    attr_accessor :actions, :segment_types
  end
  self.actions = ACTIONS_21
  self.segment_types = ACTIONS_21

  # Name for an input-action segment type under the selected protocol
  # version. SEGMENT_TYPES_20 values are bare strings; ACTIONS_21 entries
  # are [name, data_len] pairs.
  def self.segment_action_name(type)
    entry = segment_types[type]
    name = entry.is_a?(Array) ? entry[0] : entry
    name || "Unknown(#{type})"
  end

  # Pick the main-action + segment-type mapping for a server version
  # string ("2.0.77", "2.1", or a bare "2.0"). Anything 2.0.x uses the
  # 2.0.x keeps the 2.0 tables (replay of old captures); anything else —
  # 2.1, a future 3.0, empty, undetectable — decodes as 2.1, the release
  # numbering. Returns the chosen label ("2.0" / "2.1+") for logging.
  # Inspect one UDP payload for a ConnectionRequest (msg 2) and return the
  # advertised Factorio version. Returns nil when the payload is not a
  # complete ConnectionRequest. Pcap and capture callers can use this to
  # choose the version-dependent action tables before decoding heartbeats.
  def self.detect_version(data)
    hdr = parse_network_header(data)
    return nil unless hdr && hdr[:msg_type] == 2
    parsed = ConnectionRequestPacket.parse(data)
    parsed&.result&.dig(:connection_request, :version)
  rescue StandardError
    nil
  end

  def self.select_version(version)
    if version.to_s.match?(/\A2\.0(\.|\z)/)
      self.actions = ACTIONS_20
      self.segment_types = SEGMENT_TYPES_20
      '2.0'
    else
      self.actions = ACTIONS_21
      self.segment_types = ACTIONS_21
      '2.1+'
    end
  end

  # Restore the DEFAULT (2.1) mappings. Exposed for tests so version-
  # dependent fixtures don't leak their tables into later cases.
  def self.reset_version
    self.actions = ACTIONS_21
    self.segment_types = ACTIONS_21
  end

  # ── Network Header ─────────────────────────────────────────────────

  # Message types that always carry a 2-byte message_id after the flags
  # byte, even without the fragmented flag (per factorio_dissector).
  ALWAYS_HAS_MESSAGE_ID_TYPES = [2, 4].freeze

  def self.parse_network_header(data)
    return nil if data.bytesize < 1
    flags = data.getbyte(0)
    msg_type = flags & 0x1F
    hdr = {
      flags: flags,
      msg_type: msg_type,
      msg_name: MESSAGE_TYPES[msg_type] || "Unknown(#{msg_type})",
      has_random: (flags & 0x20) != 0,
      fragmented: (flags & 0x40) != 0,
      last_frag: (flags & 0x80) != 0,
      header_size: 1,
    }

    # Variable-length header: flags(1), then when fragmented or the type
    # always carries it: message_id(2, bit15=confirm) + frag_number(1 if
    # fragmented) + confirm_count(1) + count*4 confirm items.
    # Verified: ConnectionAcceptOrDeny pkt header = 9 bytes
    # (0xc5 2f 85 00 01 01 00 00 00: flags + msg_id(0x852f, confirm) +
    #  frag_number + confirm_count(1) + confirm_item(0x00000001)).
    if hdr[:fragmented] || ALWAYS_HAS_MESSAGE_ID_TYPES.include?(msg_type)
      return hdr if data.bytesize < 3
      msg_id = data.unpack1('v', offset: 1)
      hdr[:message_id] = msg_id
      hdr[:confirm] = (msg_id & 0x8000) != 0
      hdr[:header_size] = 3
      if hdr[:fragmented]
        hdr[:frag_number] = data.getbyte(3)
        hdr[:header_size] = 4
      end
      if hdr[:confirm] && data.bytesize > hdr[:header_size]
        count = data.getbyte(hdr[:header_size])
        hdr[:confirm_count] = count
        hdr[:header_size] += 1
        hdr[:confirm_items] = []
        count.to_i.times do
          break if hdr[:header_size] + 2 > data.bytesize
          hdr[:confirm_items] << data.unpack1('V', offset: hdr[:header_size])
          hdr[:header_size] += 4
        end
      end
    end
    hdr
  end

  # ── Heartbeat Payload Check ────────────────────────────────────────

  # True when the UDP payload is a synchronizer heartbeat: packet type 6
  # rides the low 5 bits of the first byte (C→S InputActions, the
  # tick-closure carrier) or 7 (the server's S→C echo of the same). The
  # action validators decode exactly these. ONE shared check — the callers
  # used to duplicate the `getbyte(0) & 0x1F` test (and one copy had an
  # `&&`/`||` precedence bug that crashed on nil): FactorioPacketTools
  # #recordable_heartbeat? and tools/validate_actions.rb.
  def self.heartbeat_payload?(data)
    b = data&.getbyte(0)
    return false unless b
    t = b & 0x1F
    t == 6 || t == 7
  end

  # Length-prefixed strings are decoded by WireDecode#decode_string, which is
  # the shared FactorioWire reader (same `[length][bytes]` shape, no
  # terminator on the wire) — see lib/factorio_wire.rb.

  # Factorio rich text ([color=…], [img=…], [entity=…], [virtual-signal=…])
  # → plain text. A LocalisedString concern, next to decode_localized_string
  # above: server descriptions and game names arrive as markup.
  def self.strip_markup(s)
    s.to_s.gsub(/\[[^\]]*\]/, '').strip.squeeze(' ')
  end

  # ── Fragmented messages ──────────────────────────────────────────

  # A big message is split into UDP payloads: the 0x40 flag, a frag_number and
  # the 0x80 flag on the last one (see parse_network_header). Two messages in
  # our captures do this: a modded client's msg 4 (its mod list + settings,
  # split past ~343 bytes of payload into 508-byte chunks) and the msg 17
  # GameInformationReply a server sends when asked (a 505-mod server splits
  # too). Order the fragments by frag_number and concatenate the payloads.
  #
  # NOTE: message_id does NOT identify a message — it is 2 for EVERY msg 4
  # (all 407 fragmented packets in the captures), so it identifies the message
  # TYPE. Key the fragments by their source and their arrival, not by it.
  #
  # frames: the raw UDP payloads, in any order.
  # => the reassembled message payload (headers stripped) once fragments
  #    0..last_frag have all arrived, else nil.
  def self.reassemble_fragments(frames)
    by_number = {}
    last = nil
    type = nil
    frames.each do |f|
      hdr = parse_network_header(f)
      next unless hdr && hdr[:fragmented]
      type ||= hdr[:msg_type]
      next unless hdr[:msg_type] == type
      by_number[hdr[:frag_number].to_i] = f.byteslice(hdr[:header_size], f.bytesize - hdr[:header_size])
      last = hdr[:frag_number].to_i if hdr[:last_frag]
    end
    return nil if type.nil? || last.nil?
    return nil unless (0..last).all? { |i| by_number.key?(i) }
    (0..last).map { |i| by_number[i] }.join
  end

  # ── GameInformationRequest (16) ──────────────────────────────────
  #
  # The whole request is one byte: msg type 16, no flags, no session — what
  # the game client (and the server browser) sends to probe a server. The
  # reply is msg 17, parsed by parse_game_info. Both are plain UDP and belong
  # here with the rest of the wire format; FactorioServerProbe does the socket.
  GAME_INFO_REQUEST = "\x10".b

  # ── Full UDP Payload Parse ─────────────────────────────────────────

  def self.parse_udp_payload(data)
    hdr = parse_network_header(data)
    return nil unless hdr

    # Fragments 1+ are mid-message slices, not whole messages: only frag 0
    # carries the leading fields. Parsing later frags as whole messages
    # reads mid-payload bytes as headers — e.g. a modded client's
    # multi-KB msg-4 confirm (mod list for deterministic sync) arrives as
    # frags 0..N, and frags 1+ decode windows of the mod blob as fake
    # "usernames" (phantom joins that steal the player slot). Frag 0
    # still parses (username/peers/game-name all live up front).
    # (Full reassembly: skipped — nothing we extract lives past frag 0.)
    return { header: hdr } if hdr[:fragmented] && hdr[:frag_number].to_i > 0

    case hdr[:msg_type]
    when 6, 7
      # Heartbeat payload always starts at byte 1. The random flag (0x20) is
      # header metadata only — it does NOT add bytes before the heartbeat
      # (verified against factorio_dissector and live captures; treating it
      # as a 4-byte offset silently dropped ~half of all heartbeat actions).
      return nil if hdr[:fragmented]  # fragment payload is not a full message
      HeartbeatPacket.parse(data).result
    when 2
      ConnectionRequestPacket.parse(data).result
    when 4
      ConnectionConfirmPacket.parse(data).result
    when 5
      ConnectionAcceptPacket.parse(data).result
    when 17
      # GameInformationRequestReply: only whole payloads parse — fragmented
      # replies reassemble in FactorioProtocol.reassemble_fragments.
      return { header: hdr } if hdr[:fragmented]
      { header: hdr, game_info: parse_game_info(data[1..]) }
    else
      { header: hdr }
    end
  end

  # ── Game Information Reply (msg 17) ──────────────────────────────

  # Parse a REASSEMBLED msg-17 payload (header byte already stripped;
  # unfragmented replies have a 1-byte header, fragmented ones 4 — see
  # lib/server_probe.rb). Reverse-engineered live against 2.0.77/2.1.14 servers:
  #   [u32 token][u64 zero][uint32v len][name][3B version][u32le build]
  #   [uint32v len][description][u32le time_min*65536][u32 ?]
  #   [uint32v len][host:port][01 00 01][uint32v nmods][mods: len+name+3B ver+u32 crc]
  #   [uint32v ntags][tags][uint32v nplayers][player names][01]
  # Every length/count is a uint32v: a 0xFF lead byte means [0xFF][u32 LE]
  # follows (a 505-mod 2.0.76 server encodes its mod count as FF F9 01 00 00;
  # reading it as a plain u8 yields 255 mods and desyncs tags/players into
  # garbage — "114 players" that are really mod-list bytes). Returns nil
  # on overrun (truncated/corrupt datagram). String lengths
  # are BYTES (multi-byte UTF-8 names/tags walk fine).
  def self.parse_game_info(p)
    return nil if p.nil? || p.bytesize < 13
    pos, nl = decode_uint32v(p, 12) # opaque server id block
    return nil if nl.nil? || p.bytesize < pos + nl + 7
    info = { name: p[pos, nl],
             version: p[pos + nl, 3].bytes.join('.'),
             build: p[pos + nl + 3, 4].unpack1('V') }
    pos += nl + 7
    pos, dl = decode_uint32v(p, pos)
    return nil if dl.nil? || p.bytesize < pos + dl + 8
    info[:description] = p[pos, dl]; pos += dl
    info[:time_min] = p[pos, 4].unpack1('V') / 65536.0; pos += 8
    pos, hl = decode_uint32v(p, pos)
    return nil if hl.nil? || p.bytesize < pos + hl + 4
    info[:host] = p[pos, hl]; pos += hl
    pos += 3 # 01 00 01 prefix
    pos, nm = decode_uint32v(p, pos)
    return nil if nm.nil?
    info[:mods] = []
    nm.times do
      pos2, l = decode_uint32v(p, pos)
      return nil if l.nil? || p.bytesize < pos2 + l + 7
      info[:mods] << [p[pos2, l], p[pos2 + l, 3].bytes.join('.')]
      pos = pos2 + l + 7
    end
    info[:tags], pos = read_info_strings(p, pos)
    return nil if info[:tags].nil?
    info[:players], = read_info_strings(p, pos)
    return nil if info[:players].nil?
    info
  end

  # Read a [uint32v count][len+str]* block at pos.
  # Returns [values, next_offset], or [nil, nil] on overrun.
  def self.read_info_strings(p, pos)
    pos, n = decode_uint32v(p, pos)
    return [nil, nil] if n.nil?
    values = n.times.map do
      pos2, l = decode_uint32v(p, pos)
      return [nil, nil] if l.nil? || pos2 + l > p.bytesize
      pos = pos2 + l
      p[pos2, l]
    end
    [values, pos]
  end

  # ── Chat Message Decoding (write_to_console) ─────────────────────

  # Decode a write_to_console message payload into a plain string.
  # Returns nil when the data is empty or not decodable.
  #
  # Wire shape (2.0.77, measured over every chat message in captures/):
  # the payload is the ACTION's own serialization — the surrounding
  # input-action segment header carries the player as well:
  #   [uint16v player][uint32v len][text...]
  # `player` is the sender's 0-based index and is 0xff-escaped past 254
  # ([ff][u16 LE]) — a server with players past 255 sends the 3-byte form,
  # which is every message on a busy server. `len` is the FULL message
  # length, so it equals the remaining bytes for a complete message only.
  # Continuation segments of a split message are raw text, no header (the
  # sniffer merges them — chat_action_data — before decoding).
  #
  # Structure wins over byte values here: earlier code enumerated observed
  # player slots (0x05/0x0b/0x24/0x29/0x2d/0x30) as special prefixes and
  # every new player (or a player past 255) decoded as garbage — the 0xff
  # escape was read as a 5-byte uint32v length, so 82/255 captured messages
  # printed as "?d\u0001$mod bug or are we talking actual bug".
  def self.decode_chat(data)
    return nil unless data && data.bytesize >= 2
    d = data.dup.force_encoding('BINARY')

    # Strict: the declared length must equal the remaining bytes, so a text
    # byte is never misread as a length (that truncated long messages
    # mid-word: "...feelings toward" instead of the full text).
    p_off, = decode_uint16v(d, 0)
    l_off, len = decode_uint32v(d, p_off)
    if len && l_off + len == d.bytesize # Note: Ruby treats 0 as truthy, so
      # len=0 (empty chat) reaches the zero-check below correctly.
      return nil if len.zero? # [player][0x00] — an empty message, not text
      return d[l_off..-1].force_encoding('UTF-8').scrub('?')
    end

    # Localized string format: [key_uint32v][mode(1)][params_count(1)][params...]
    # mode: 0=Empty, 1=Translation, 2=Literal, 3=LiteralTranslation
    msg = decode_localized_string(d)
    return msg if msg

    # Main action list format: [uint32v len][text] — exact fit only. A
    # prefix-fit here reintroduces the truncation bug above (slot byte read
    # as a length, returning a chopped prefix of the real message).
    off, slen = decode_uint32v(d, 0)
    if slen > 0 && off && off + slen == d.bytesize
      return d[off, slen].force_encoding('UTF-8').scrub('?')
    end

    # Raw text (no prefix) — a lone continuation segment, decoded standalone.
    # Reject non-printable bytes (e.g. [0x00] from non-chat write_to_console
    # console-open/close events) that the strict format checks above didn't
    # capture: a single NUL byte is not text.
    text = d.force_encoding('UTF-8').scrub('?')
    text if text.match?(/\S/)
  end

  # Recursively decode a localized string (Factorio's protobuf-like format).
  # Format: [key_uint32v][mode(1)][params_count(1)][params...]
  # mode: 0=Empty, 1=Translation, 2=Literal, 3=LiteralTranslation
  def self.decode_localized_string(data, depth = 0)
    return nil if depth > 6 || data.bytesize < 4

    off, slen = decode_uint32v(data, 0)
    return nil unless slen && slen > 0 && off + slen + 2 <= data.bytesize

    key = data[off, slen].force_encoding('UTF-8').scrub('?')
    mode = data.getbyte(off + slen)
    pcount = data.getbyte(off + slen + 1)
    pos = off + slen + 2

    case mode
    when 0 then return ''                           # Empty
    when 2 then return key                          # Literal: key is the text
    when 3 then                                     # LiteralTranslation
      parts = [key]
      pcount.times do
        sub = decode_localized_string(data[pos..], depth + 1)
        break unless sub
        parts << sub
        pos = advance_ls(data, pos)
      end
      return parts.join('')
    when 1                                          # Translation
      parts = []
      pcount.times do
        sub = decode_localized_string(data[pos..], depth + 1)
        break unless sub
        parts << sub
        pos = advance_ls(data, pos)
      end
      return "[#{key}](#{parts.join(', ')})" if parts.any?
      return "[#{key}]"
    end
    nil
  end

  # Advance past one localized string, return next byte offset
  def self.advance_ls(data, offset)
    return data.bytesize if offset >= data.bytesize
    off, slen = decode_uint32v(data, offset)
    return data.bytesize unless slen
    off += slen
    return data.bytesize if off + 2 > data.bytesize
    pcount = data.getbyte(off + 1)
    off += 2
    pcount.to_i.times do
      off = advance_ls(data, off)
      break if off >= data.bytesize
    end
    off
  end
end
