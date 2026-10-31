# frozen_string_literal: true

require 'socket'
require_relative 'factorio_protocol'

# A direct UDP probe of ONE server: one header-only GameInformationRequest
# (msg 16), then the server's GameInformationReply (msg 17) -- no login, no
# session, no save download, the same exchange the game client does when it
# talks to a server directly. `tools/query_server.rb HOST:PORT` is the CLI;
# `tools/server_rank.rb` keeps a whole list live with `refresh_counts`.
#
# The transport here is the only thing in this file. The wire format lives
# with the rest of it on FactorioProtocol: `GAME_INFO_REQUEST` builds the
# request, `reassemble_fragments` puts a split reply back together
# (a 505-mod server's reply splits), `parse_game_info` parses it and
# `strip_markup` de-tags the rich text in the description.
#
# NOT the server browser: that is the HTTPS matchmaking API
# (FactorioMatchmaking, lib/matchmaking.rb).
class FactorioServerProbe
  # Resolve host to [[family, ip]] with IPv6 first. Literal IPs pass
  # through untouched; unresolvable names yield [].
  def self.resolve(host, port)
    Addrinfo.getaddrinfo(host, port, :UNSPEC, :DGRAM, nil, Socket::AI_NUMERICHOST)
              .map { |a| [a.afamily, a.ip_address] }
  rescue SocketError
    begin
      Addrinfo.getaddrinfo(host, port, :UNSPEC, :DGRAM)
              .sort_by { |a| a.afamily == Socket::AF_INET6 ? 0 : 1 }
              .map { |a| [a.afamily, a.ip_address] }
    rescue SocketError
      []
    end
  end

  # Raw reassembled reply payload for an address (header stripped), or nil
  # when the server stays silent. Accepts "ip:port", "[v6]:port", bare IPs
  # (default port 34197) and DNS names. A name resolving to both families
  # tries IPv6 first (the matchmaking list is v4 only, so v6 comes from DNS
  # or word of mouth). Retries on fragment gaps (UDP loss).
  def self.probe(addr, timeout: 1, tries: 2)
    host, _, port = addr.rpartition(':')
    if host.empty? || (host.count(':') > 0 && !addr.match?(/\[.*\]/))
      host, port = addr.delete('[]'), '34197' # bare v6 / bare name
    end
    targets = resolve(host.delete('[]'), port.to_i)
    return nil if targets.empty?
    targets.each do |family, ip|
      tries.times do
        s = UDPSocket.new(family)
        s.bind(family == Socket::AF_INET6 ? '::' : '0.0.0.0', 0)
        begin
          s.connect(ip, port.to_i)
        rescue StandardError
          s.close
          next
        end
        s.send(FactorioProtocol::GAME_INFO_REQUEST, 0)
        frames = []
        payload = nil
        while IO.select([s], nil, nil, timeout)
          data, = s.recvfrom(65535)
          hdr = FactorioProtocol.parse_network_header(data)
          next unless hdr && hdr[:msg_type] == 17
          if hdr[:fragmented]
            frames << data
            payload = FactorioProtocol.reassemble_fragments(frames)
          else
            payload = data.byteslice(hdr[:header_size], data.bytesize - hdr[:header_size])
          end
          break if payload
        end
        s.close
        return payload if payload
      end
    end
    nil
  end

  # Parsed info hash for "ip:port" (see parse_game_info), or nil.
  def self.info(addr, **opts)
    raw = probe(addr, **opts)
    raw && FactorioProtocol.parse_game_info(raw)
  end

  # Live player count for "ip:port", or nil if unanswered/unparsable.
  def self.player_count(addr, **opts)
    player_count_from_payload(probe(addr, **opts))
  end

  # Player count from a header-stripped msg-17 payload (what `probe` returns
  # and `reassemble_fragments` yields), or nil if none/unparsable.
  def self.player_count_from_payload(payload)
    i = FactorioProtocol.parse_game_info(payload)
    i && i[:players].length
  end

  # Counts for many addresses -- ONE socket per address family, every query
  # fired from it, every reply drained in a single timed select loop. No
  # threads, no per-server socket churn, no per-server timeout: a Factorio
  # server answers the one-byte msg-16 probe in milliseconds, so one short
  # drain catches the lot. (Single-server probing stays on `probe`, which
  # keeps a retry for UDP loss.) Returns {addr => Integer or nil}.
  def self.refresh_counts(addrs, timeout: 1)
    live = {}
    return live if addrs.empty?

    # Resolve each address to concrete (family, ip, port) targets, grouped by
    # family so one socket serves each. Matchmaking host_address is IPv4
    # "ip:port", so this is normally a single IPv4 socket.
    by_af = Hash.new { |h, k| h[k] = [] } # af => [[ip, port, addr]]
    addrs.each do |addr|
      host, _, port = addr.rpartition(':')
      port = (port =~ /\A\d+\z/ ? port.to_i : 34197)
      host = host.delete('[]')
      resolve(host, port).each do |af, ip|
        by_af[af] << [ip, port, addr]
      end
    end
    return live if by_af.empty?

    # One socket per family; send all that family's queries from it so every
    # reply lands back on the socket that asked.
    sockets = by_af.map do |af, eps|
      s = UDPSocket.new(af)
      s.bind(af == Socket::AF_INET6 ? '::' : '0.0.0.0', 0)
      eps.each { |ip, port, _| s.send(FactorioProtocol::GAME_INFO_REQUEST, 0, ip, port) }
      [s, eps]
    end
    select_list = sockets.map { |s, _| s }
    src_to_addr = {} # [ip, port] => addr
    by_af.each { |af, eps| eps.each { |ip, port, addr| src_to_addr[[ip, port]] = addr } }
    fragments = Hash.new { |h, k| h[k] = [] } # [ip, port] => frames awaiting completion
    answerable = by_af.values.flatten(1).map { |_, _, addr| addr }.uniq.size

    deadline = Time.now + timeout
    begin
      while (remaining = deadline - Time.now) > 0
        ready = IO.select(select_list, nil, nil, remaining)
        break unless ready
        ready[0].each do |s|
          # Drain every queued reply on this socket before returning to select.
          loop do
            begin
              data, sender = s.recvfrom_nonblock(65_535)
            rescue IO::WaitReadable, Errno::EAGAIN
              break
            end
            # sender = [family, port, host, ip]; match by ip+port (family is per-socket).
            src = [sender[3], sender[1]]
            addr = src_to_addr[src]
            next unless addr
            next if live.key?(addr) # first reply wins
            hdr = FactorioProtocol.parse_network_header(data)
            next unless hdr && hdr[:msg_type] == 17
            if hdr[:fragmented]
              fragments[src] << data
              payload = FactorioProtocol.reassemble_fragments(fragments[src])
              live[addr] = player_count_from_payload(payload) if payload
            else
              payload = data.byteslice(hdr[:header_size], data.bytesize - hdr[:header_size])
              live[addr] = player_count_from_payload(payload)
            end
          end
        end
        break if live.size >= answerable # all answers in; stop early
      end
    ensure
      sockets.each { |s, _| s.close }
    end

    # Unanswered addresses stay nil (offline, or filtered by a firewall).
    by_af.each_value { |eps| eps.each { |_, _, addr| live[addr] = nil unless live.key?(addr) } }
    live
  end
end
