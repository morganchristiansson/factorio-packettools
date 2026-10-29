#!/usr/bin/env ruby
# Recover the player roster (game index -> name, play time, last-online, locale)
# from a Factorio save. The parsing, anchoring and merge live in the library
# (lib/factorio_save.rb + lib/player_db.rb); this is only the CLI: report,
# optionally merge.
#
# The roster is an array of LuaPlayer records in GAME-INDEX ORDER (see
# docs/save/level-dat.md). A record is found by its name field; the play-time
# pair and the locale are read out of it, and the game index is the record's
# position in the run — anchored (and validated) with players-cache.json when
# it has names, assumed to start at index 1 when it does not (client mode,
# before anyone has joined; the first join seen on the wire corrects it).
#
# Usage:
#   ruby tools/extract_players_from_save.rb SAVE.zip [players-cache.json] [--merge]
#   ruby tools/extract_players_from_save.rb level.dat  [players-cache.json] [--merge]
#
#   SAVE.zip    a save archive (level.dat0..N chunks, joined in NAME order;
#               needs `unzip` on PATH)
#   level.dat   the already decompressed/joined stream
#   --merge     write the recovered names (and any locale the cache lacks) into
#               players-cache.json, keeping its admin/quickbar fields
#
# Output: {game index (1-indexed) => {name:, online_time_ticks:,
# last_online_tick:, locale:}}, plus what was added.

require 'json'
require_relative '../lib/factorio_save'
require_relative '../lib/player_db'

SAVE = ARGV.find { |a| !a.start_with?('--') } or abort(<<~USAGE)
  usage: ruby tools/extract_players_from_save.rb SAVE.zip|level.dat [players-cache.json] [--merge]
USAGE
CACHE = ARGV.reject { |a| a.start_with?('--') }[1] || PlayerDatabase::DEFAULT_CACHE_BASENAME
MERGE = ARGV.include?('--merge')

scan = FactorioSave.scan_save(SAVE)
records = scan.records
abort 'no candidate names found — not a level.dat stream?' if records.empty?

db = PlayerDatabase.new(CACHE)
known = db.name_ids
index = scan.indexed(known)
roster = index.by_index
if roster.empty?
  abort 'no player records found — not a level.dat stream?'
end

if known.empty?
  puts 'no known players in the cache — roster taken from the record structure alone'
else
  puts "candidates: #{records.size}   known names anchoring the run: #{index.anchored}/#{index.known_count}"
end
if index.mismatched.any?
  puts "[warn] #{index.mismatched.size} known name(s) disagree with the run: #{index.mismatched.first(5).join(', ')}"
  puts '[warn] replacing those cache entries with the save\'s indexes (the save is authoritative)'
end
if index.absent.any?
  puts "note: #{index.absent.size} cached player(s) joined after this save: #{index.absent.first(5).inspect}#{'…' if index.absent.size > 5}"
end

puts "roster: #{roster.size} players (indexes #{roster.keys.min}..#{roster.keys.max})"
ticks = roster.values.sum { |r| r[:online_time_ticks] || 0 }
puts "play time: #{roster.values.count { |r| r[:online_time_ticks] }} records, #{ticks} ticks total " \
     "(#{'%.0f' % (ticks / 60 / 3600.0)} h), save tick #{scan.save_tick}, pair slots #{scan.slots.inspect}"
locales = roster.values.count { |r| r[:locale] }
puts "locale: #{locales}/#{roster.size} records (#{roster.values.count { |r| r[:locale] == 'en' }} en)"
colors = roster.values.count { |r| r[:color] }
puts "color: #{colors}/#{roster.size} records (#{roster.values.map { |r| r[:color] }.compact.uniq.size} distinct)"

named = roster.transform_values { |r| r[:name] }
added = named.reject { |_, name| known.key?(name) }
puts "new: #{added.size} -> #{added.values.first(10).inspect}#{'…' if added.size > 10}"
renamed = named.select { |id, name| known.key?(name) && !known[name].include?(id) }
puts "renamed: #{renamed.map { |id, n| "#{id}: #{known[n].join('|')} -> #{n}" }.join(', ')}" if renamed.any?

if MERGE
  dropped = db.merge_save_roster(roster)
  puts "dropped #{dropped} stale duplicate name id(s)" if dropped.positive?
  puts "wrote #{CACHE} (#{db.players.size} players)"
else
  out = roster.to_h { |id, r|
    [id.to_s, {name: r[:name], online_time_ticks: r[:online_time_ticks],
               last_online_tick: r[:last_online_tick], locale: r[:locale],
               color: r[:color]}.compact]
  }
  puts JSON.pretty_generate(out)
end
