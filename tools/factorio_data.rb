#!/usr/bin/env ruby
# frozen_string_literal: true

# Run Factorio's data stage once and keep data.raw + checksums. See
# lib/factorio_data.rb for what/why; this is only the CLI.
#
#   ruby tools/factorio_data.rb [OUT_DIR]
#   ruby tools/factorio_data.rb --mod-directory /tmp/factorio-server/mods out
#
# OUT_DIR defaults to external/factorio-data. With no --mod-directory the
# built-in mods are loaded (base enabled, expansion mods disabled — the same
# list tools/test_server.sh writes); a supplied directory must contain
# mod-list.json.

require 'optparse'
require_relative '../lib/factorio_data'

options = {
  factorio: FactorioData::DEFAULT_FACTORIO,
  data_dir: FactorioData::DEFAULT_DATA_DIR,
  mod_directory: nil,
  out: FactorioData::DEFAULT_OUT
}
OptionParser.new do |o|
  o.banner = 'Usage: ruby tools/factorio_data.rb [OUT_DIR] [options]'
  o.on('--mod-directory DIR', 'mods directory containing mod-list.json') { |v| options[:mod_directory] = v }
  o.on('--factorio PATH', 'Factorio executable') { |v| options[:factorio] = v }
  o.on('--data-dir PATH', 'Factorio read-data directory') { |v| options[:data_dir] = v }
  o.on('-h', '--help', 'this text') { puts o; exit }
end.parse!
options[:out] = ARGV.shift if ARGV[0]

dumper = FactorioData.new(**options)
result = dumper.run
puts "core=#{result.core} prototype_list=#{result.prototype_list}"
result.mods.each { |name, crc| puts "  #{name}: #{crc}" }
puts "wrote #{result.data_raw} (#{File.size(result.data_raw)} bytes)"
puts "wrote #{result.checksums}"
