# frozen_string_literal: true

# Small binary value types used by position-bearing protocol actions.
# Positions are int32 fixed-point with 8 fractional bits: 256 units = 1 tile.
# (Not the chunk size — a chunk is 32 tiles.)
module FactorioProtocol
  module Actions
    module Types
      # Direction in the Factorio world (0-15).
      # 0=north, 1=northnortheast, ..., 15=northnorthwest
      DIR_NAMES = %w[
        north northnortheast northeast eastnortheast east eastsoutheast
        southeast southsoutheast south southsouthwest southwest
        westsouthwest west westnorthwest northwest northnorthwest
      ].freeze
      TilePos = Struct.new(:x, :y) do
        def self.from_data(data, offset = 0)
          return nil if offset + 8 > data.bytesize
          new(data.unpack1('i', offset: offset), data.unpack1('i', offset: offset + 4))
        end

        def to_tiles
          [x / 256.0, y / 256.0]
        end
      end

      TileRect = Struct.new(:top_left, :bottom_right) do
        def self.from_data(data, offset = 0)
          return nil if offset + 16 > data.bytesize
          new(TilePos.from_data(data, offset), TilePos.from_data(data, offset + 8))
        end
      end
    end
  end
end
