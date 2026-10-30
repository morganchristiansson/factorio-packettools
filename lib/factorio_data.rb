# frozen_string_literal: true

require 'digest'
require 'fileutils'
require 'json'
require 'open3'
require 'tmpdir'

# Run Factorio's data stage once and keep both useful outputs:
#
#   out/data-raw-dump.json  — data.raw as JSON (what --dump-data writes)
#   out/checksums.json      — core, prototype-list and per-mod CRC32s
#
# No server, port, RCON or map is started: --dump-data loads every enabled
# mod, prints the checksums, then dumps data.raw and exits. This is the same
# loader the game/server uses, so it is authoritative for CRCs. The log lines
# parsed here are "Checksum for core", "Checksum of <mod>" and "Prototype
# list checksum". The dump is copied, never parsed; 14 MB for base+recycler,
# larger with mods, and subsets can be read from the saved file later.
#
# How the checksums are actually calculated (reverse-engineered; do not
# "optimise" this into a file-tree hash):
#
#   * A per-mod checksum is one standard CRC32 (the zlib/PNG polynomial,
#     seed 0) over the bytes of every file Factorio *reads* while that mod's
#     data stage runs, appended in read order. It is not a sum of per-file
#     CRCs: order matters. A mod with one data.lua therefore has exactly
#     Zlib.crc32(data.lua).
#   * Reads are first-load only: if mod A requires a file that mod B already
#     loaded, A's checksum does not include it again. Files never read are
#     excluded (an unreferenced extra.lua does not change anything, and an
#     info.json version bump does not either).
#   * util.sprite_load(path, ...) is literally `require(path)` in core, so
#     the generated graphics/*.lua sprite-definition files count too.
#   * Phases matter: data.lua, then data-updates.lua, then data-final-fixes.lua.
#   * The core checksum is the same mechanism over the core mod's own stage,
#     including some files the engine preloads.
#   * The prototype-list checksum is NOT a file CRC. It is computed from the
#     resulting prototype set after all data phases, so it cannot be derived
#     by hashing a directory.
#
# Exact read order is the product of executing mod Lua (loops and computed
# `require`/`sprite_load` paths make static grep insufficient), so the only
# reliable source is Factorio itself: this wrapper reads the lines it emits
# rather than trying to reproduce that read stream.
class FactorioData
  DEFAULT_FACTORIO = '/factorio/bin/x64/factorio'
  DEFAULT_DATA_DIR = '/factorio/data'
  DEFAULT_OUT = 'external/factorio-data'

  Result = Struct.new(:core, :prototype_list, :mods, :data_raw, :checksums,
                      keyword_init: true)

  attr_reader :factorio, :data_dir, :mod_directory, :out

  def initialize(factorio: DEFAULT_FACTORIO, data_dir: DEFAULT_DATA_DIR,
                 mod_directory: nil, out: DEFAULT_OUT, save_data: true)
    @factorio = factorio
    @data_dir = data_dir
    @mod_directory = mod_directory
    @out = out
    @save_data = save_data
  end

  # The same mod set always produces the same checksums, so a process that
  # calls this repeatedly (FactorioClient reconnects) should not run Factorio
  # again. The key includes the executable/data directory signatures and every
  # mod file's path + size + mtime, so editing a custom mod's data.lua is a
  # different key. In-memory only: a new process starts with an empty cache.
  def self.cached(**options)
    dumper = new(**options)
    key = dumper.cache_key
    @cache_mutex ||= Mutex.new
    @cache_mutex.synchronize do
      @cache ||= {}
      @cache[key] ||= dumper.run
    end
  end

  def self.clear_cache!
    @cache_mutex ||= Mutex.new
    @cache_mutex.synchronize { @cache = {} }
  end

  def cache_key
    [fingerprint, out, @save_data].freeze
  end

  def run
    raise "Factorio executable not found: #{factorio}" unless File.executable?(factorio)
    raise "read-data directory not found: #{data_dir}" unless Dir.exist?(data_dir)
    raise "mod directory not found: #{mod_directory}" if mod_directory && !Dir.exist?(mod_directory)

    Dir.mktmpdir('factorio-data-') do |run_dir|
      write_config(run_dir)
      write_builtin_mod_list(run_dir) unless mod_directory

      _out, err, status = Open3.capture3(*command(run_dir))
      log_path = File.join(run_dir, 'factorio-current.log')
      log = File.exist?(log_path) ? File.read(log_path) : ''
      unless status.success?
        raise "Factorio failed (#{status.exitstatus}):\n#{err}\n#{log.lines.grep(/Error/).join}"
      end

      parsed = self.class.parse_checksums(log)
      raise "no checksums in #{log_path}" unless parsed

      data_raw = checksums = nil
      if @save_data
        dump = File.join(run_dir, 'script-output', 'data-raw-dump.json')
        raise 'Factorio did not write data-raw-dump.json' unless File.exist?(dump)

        FileUtils.mkdir_p(out)
        data_raw = File.join(out, 'data-raw-dump.json')
        checksums = File.join(out, 'checksums.json')
        FileUtils.cp(dump, data_raw)
        File.write(checksums, JSON.pretty_generate(parsed) + "\n")
      end

      Result.new(core: parsed[:core], prototype_list: parsed[:prototype_list],
                 mods: parsed[:mods], data_raw: data_raw, checksums: checksums)
    end
  end

  # Pull the checksums out of Factorio's own log. The calculation lives in
  # the loader; this method only reads its output (see the class comment for
  # why reimplementing it from the file tree is not equivalent).
  def self.parse_checksums(log)
    core = log[/^.*Checksum for core: (\d+)/, 1]
    prototype = log[/^.*Prototype list checksum: (\d+)/, 1]
    return nil unless core && prototype

    mods = log.scan(/^.*Checksum of ([^:]+): (\d+)/).to_h { |name, crc| [name, crc.to_i] }
    { core: core.to_i, prototype_list: prototype.to_i, mods: mods }
  end

  private

  # Cheap identity of the inputs that affect checksums. /factorio/data is
  # huge, so only its top-level stat is included (a Factorio update replaces
  # its contents); a custom mod directory is walked because editing any mod
  # file must invalidate the cache.
  def fingerprint
    d = Digest::SHA256.new
    [factorio, data_dir].each do |path|
      st = File.stat(path)
      d << path << "\0" << st.size.to_s << "\0" << st.mtime.to_f.to_s << "\0"
    rescue SystemCallError
      d << path << "\0missing\0"
    end
    if mod_directory && Dir.exist?(mod_directory)
      Dir.glob(File.join(mod_directory, '**', '*'), File::FNM_DOTMATCH).sort.each do |path|
        st = File.lstat(path)
        d << path << "\0" << (st.symlink? ? File.readlink(path) : st.size.to_s)
        d << "\0" << st.mtime.to_f.to_s << "\0"
      rescue SystemCallError
        d << path << "\0missing\0"
      end
    end
    d.hexdigest
  end

  def write_config(run_dir)
    FileUtils.mkdir_p(File.join(run_dir, 'mods'))
    File.write(File.join(run_dir, 'config.ini'), <<~INI)
      [path]
      read-data=#{data_dir}
      write-data=#{run_dir}

      [other]
      no-log-rotation=true
    INI
  end

  # tools/test_server.sh's list: base on, the expansion mods off (recycler is
  # a built-in dependency and still loads).
  def write_builtin_mod_list(run_dir)
    File.write(File.join(run_dir, 'mods', 'mod-list.json'), <<~JSON)
      {"mods":[
        {"name":"base","enabled":true},
        {"name":"elevated-rails","enabled":false},
        {"name":"quality","enabled":false},
        {"name":"space-age","enabled":false}
      ]}
    JSON
  end

  def command(run_dir)
    cmd = [factorio, '--config', File.join(run_dir, 'config.ini'), '--dump-data']
    cmd += ['--mod-directory', mod_directory] if mod_directory
    cmd
  end
end
