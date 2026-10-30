# frozen_string_literal: true

require 'minitest/autorun'
require 'tmpdir'
require 'fileutils'
require_relative '../lib/factorio_data'

class FactorioDataTest < Minitest::Test
  LOG = <<~LOG
       0.094 Loading mod core 0.0.0 (data.lua)
       0.116 Loading mod base 2.1.24 (data.lua)
       0.376 Loading mod recycler 2.1.24 (data.lua)
       0.461 Checksum for core: 3668028660
       0.461 Checksum of base: 3864816957
       0.461 Checksum of recycler: 3293728126
       0.686 Prototype list checksum: 2725040850
  LOG

  def test_parse_checksums
    got = FactorioData.parse_checksums(LOG)
    assert_equal 3_668_028_660, got[:core]
    assert_equal 2_725_040_850, got[:prototype_list]
    assert_equal({ 'base' => 3_864_816_957, 'recycler' => 3_293_728_126 }, got[:mods])
  end

  def test_parse_checksums_needs_both_core_and_prototype
    assert_nil FactorioData.parse_checksums('Checksum of base: 1')
    assert_nil FactorioData.parse_checksums("Checksum for core: 1\n")
  end

  def test_cache_key_tracks_mod_file_contents
    Dir.mktmpdir do |dir|
      file = File.join(dir, 'data.lua')
      File.write(file, '--a')
      before = FactorioData.new(mod_directory: dir).cache_key
      File.write(file, '--a longer')
      after = FactorioData.new(mod_directory: dir).cache_key
      refute_equal before, after
    end
  end
end
