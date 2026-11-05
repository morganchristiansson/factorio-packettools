# frozen_string_literal: true

require_relative 'packet'

module FactorioProtocol
  # GameInformationRequestReply (17) — what a server sends the server browser
  # or our probe. One class like every other network message; the payload
  # parser is also used directly on a REASSEMBLED reply (FactorioServerProbe
  # strips the header first).
  #
  # Reverse-engineered live against 2.0.77/2.1.14 servers:
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
  class GameInformationReplyPacket < FactorioProtocol::Packet
    # Header-stripped payload (unfragmented) or reassembled fragments.
    def self.parse_payload(p)
      return nil if p.nil? || p.bytesize < 13
      pos, nl = FactorioProtocol.decode_uint32v(p, 12) # opaque server id block
      return nil if nl.nil? || p.bytesize < pos + nl + 7
      info = { name: p[pos, nl],
               version: p[pos + nl, 3].bytes.join('.'),
               build: p[pos + nl + 3, 4].unpack1('V') }
      pos += nl + 7
      pos, dl = FactorioProtocol.decode_uint32v(p, pos)
      return nil if dl.nil? || p.bytesize < pos + dl + 8
      info[:description] = p[pos, dl]; pos += dl
      info[:time_min] = p[pos, 4].unpack1('V') / 65536.0; pos += 8
      pos, hl = FactorioProtocol.decode_uint32v(p, pos)
      return nil if hl.nil? || p.bytesize < pos + hl + 4
      info[:host] = p[pos, hl]; pos += hl
      pos += 3 # 01 00 01 prefix
      pos, nm = FactorioProtocol.decode_uint32v(p, pos)
      return nil if nm.nil?
      info[:mods] = []
      nm.times do
        pos2, l = FactorioProtocol.decode_uint32v(p, pos)
        return nil if l.nil? || p.bytesize < pos2 + l + 7
        # name + 3-byte version + u32 CRC32, then the next length-prefixed
        # name. The CRC is the same per-mod checksum the server prints as
        # "Checksum of <mod>" and the client repeats in msg 4, so a probe is
        # enough to learn a server's whole mod list (tools/query_server.rb
        # prints only name+version).
        info[:mods] << [p[pos2, l], p[pos2 + l, 3].bytes.join('.'), p[pos2 + l + 3, 4].unpack1('V')]
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
      pos, n = FactorioProtocol.decode_uint32v(p, pos)
      return [nil, nil] if n.nil?
      values = n.times.map do
        pos2, l = FactorioProtocol.decode_uint32v(p, pos)
        return [nil, nil] if l.nil? || pos2 + l > p.bytesize
        pos = pos2 + l
        p[pos2, l]
      end
      [values, pos]
    end
    private_class_method :read_info_strings

    private

    def parse_body
      @result[:game_info] = self.class.parse_payload(
        @data.byteslice(@header[:header_size], @data.bytesize - @header[:header_size])
      )
    end
  end
end
