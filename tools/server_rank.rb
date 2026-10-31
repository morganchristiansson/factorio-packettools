#!/usr/bin/env ruby
# frozen_string_literal: true
# Server rank by player count — without leaving the game, without hammering
# Wube's API.
#
# Seed once from the matchmaking API (cached at ~/.cache/factorio-server-list.json),
# then refresh counts directly from the servers over UDP (FactorioServerProbe).
# Cache hits mean zero official-API traffic.
#
# Usage:
#   ruby tools/server_rank.rb --server "my server"              # rank + top 10 (snapshot from matchmaking API cache)
#   ruby tools/server_rank.rb --matchmaking                     # fresh API fetch (auto-reseed), no UDP
#   ruby tools/server_rank.rb --server foo --matchmaking --udp  # fresh API + live UDP counts on all servers
#   ruby tools/server_rank.rb --server foo --udp                # cache + live UDP counts on all servers
$LOAD_PATH.unshift File.expand_path('../lib', __dir__)
require 'optparse'
require 'matchmaking'
require 'server_probe'

# Keep the historical top-level helper while sharing the implementation.

def player_count(s)
  (s['players'] || []).length
end

# Descending by player count. Missing "players" key = empty server (0).
# Passworded servers hidden by default (like browsing for a server to join).
def ranked_servers(list, version = nil, include_locked: false)
  list = list.reject { |s| s['has_password'] } unless include_locked
  list = list.select { |s| (gv = s.dig('application_version', 'game_version')) && (gv == version || gv.start_with?("#{version}.")) } if version
  list.sort_by { |s| -player_count(s) }
end

# Lines to print: top N plus the rank of every --server match (even outside top N).
# live: {host_address => Integer or nil} — nil = UDP unanswered.
# version_filter: when set (--version), only show servers whose matchmaking
# API version matches. UDP is not used to correct versions.
def rank_report(sorted, top:, match: nil, live: {}, version_filter: nil)
  # The matchmaking API count is the baseline and is always shown.
# A live UDP reply is only a (live: N) count annotation when the server
# answered; it never replaces the API count or version.
  lines = sorted.first(top).each_with_index.map do |s, i|
    udp_count = live.fetch(s['host_address'], nil)
    api_count = player_count(s)
    cache_version = s.dig('application_version', 'game_version')
    next if version_filter && cache_version && !(cache_version == version_filter || cache_version.start_with?("#{version_filter}."))
    n = api_count
    extra = live.key?(s['host_address']) && !udp_count.nil? ? " (live: #{udp_count})" : ''
    ver = cache_version
    "##{i + 1} #{FactorioProtocol.strip_markup(s['name'])} — #{n || player_count(s)} players (#{ver}#{', 🔒' if s['has_password']}) @ #{s['host_address']}#{extra}"
  end
  if match
    hits = sorted.each_with_index.select { |s, _| FactorioProtocol.strip_markup(s['name']).downcase.include?(match.downcase) }
    if hits.empty?
      lines << "No server matching #{match.inspect} in list (#{sorted.length} servers)."
    else
      hits.each do |s, i|
        udp_count = live.fetch(s['host_address'], nil)
        api_count = player_count(s)
        cache_version = s.dig('application_version', 'game_version')
        next if version_filter && cache_version && !(cache_version == version_filter || cache_version.start_with?("#{version_filter}."))
        n = api_count
        extra = live.key?(s['host_address']) && !udp_count.nil? ? " (live: #{udp_count})" : ''
        lines << "=> #{FactorioProtocol.strip_markup(s['name'])} is ##{i + 1} with #{n.nil? ? api_count : n} players @ #{s['host_address']}#{', 🔒' if s['has_password']}#{extra}."
      end
    end
  end
  lines << "(#{sorted.length} servers listed)"
  lines
end

if $PROGRAM_NAME == __FILE__
  opts = { top: 10, version: nil, server: nil, matchmaking: false, udp: false, interactive: false }
  OptionParser.new do |o|
    o.banner = 'Usage: ruby tools/server_rank.rb --server NAME [--top N] [--version 2.0] [--matchmaking] [--udp] [--interactive]'
    o.on('--top N', Integer, 'show top N (default 10)') { |v| opts[:top] = v }
    o.on('--version V', 'filter by game version (e.g. 2.0)') { |v| opts[:version] = v }
    o.on('--server NAME', 'your server name (substring, case-insensitive)') { |v| opts[:server] = v }
    o.on('--include-locked', 'show passworded servers (hidden by default)') { opts[:include_locked] = true }
    o.on('--matchmaking', 'fresh matchmaking API fetch (auto-reseed; without it, use cached list)') { opts[:matchmaking] = true }
    o.on('--udp', 'query all servers over UDP for live player counts') { opts[:udp] = true }
    o.on('--interactive', 'prompt for row numbers to expand details via UDP (implies --udp)') { opts[:interactive] = true; opts[:udp] = true }
  end.parse!
  list = FactorioMatchmaking.seed(reseed: opts[:matchmaking])
  version = opts[:version]
  in_scope = version ? list.select { |s| (gv = s.dig('application_version', 'game_version')) && (gv == version || gv.start_with?("#{version}.")) } : list
  hidden = opts[:include_locked] ? 0 : in_scope.count { |s| s['has_password'] }
  sorted = ranked_servers(list, version, include_locked: opts[:include_locked])
  live = {}
  if opts[:udp]
    # Query ALL servers over UDP for live counts (not just the top N shown).
    addrs = sorted.map { |s| s['host_address'] }.compact.uniq
    live = FactorioServerProbe.refresh_counts(addrs)
    # Re-rank by live UDP count (nil keeps snapshot).
    sorted = sorted.sort_by { |s| -(live.fetch(s['host_address'], player_count(s)) || player_count(s)) }
  end
  lines = rank_report(sorted, top: opts[:top], match: opts[:server], live: live, version_filter: version)
  lines << "(#{hidden} 🔒 hidden, --include-locked to show)" if hidden > 0
  puts lines
  if opts[:interactive] && $stdin.tty?
    by_rank = {}
    sorted.each_with_index { |s, i| by_rank[i + 1] = s }
    loop do
      print 'row (q)? '
      ans = $stdin.gets.to_s.strip
      break if ans.empty? || ans.downcase.start_with?('q')
      s = by_rank[ans.to_i]
      if s.nil?
        puts 'no such row'
        next
      end
      info = FactorioServerProbe.info(s['host_address'])
      if info.nil?
        puts "#{s['host_address']}: no reply"
      else
        mods = info[:mods].map { |m| m.join(' ') }.join(', ')
        players = info[:players].join(', ')
        puts "#{s['host_address']}: #{info[:name]} (#{info[:version]}) players=#{info[:players].length} mods=#{info[:mods].length}"
        puts "  description: #{info[:description]}" unless info[:description].to_s.empty?
        puts "  mods: #{mods}"
        puts "  players: #{players}"
      end
    end
  end
end
