# frozen_string_literal: true

module FactorioProtocol
  # S→C player_join_game body, decoded by HeartbeatPacket#parse_action while
  # it measures the echo (the name length is what sets the action's length).
  # This module is only the interpretation: which game index the joining
  # player owns and what their name is.
  #
  # Body: 6-byte peer/mode header, [u8 name len], name, 2 trailing bytes.
  module PlayerJoin
    NAME_MAX = 64

    # => {index:, name:} or nil when the action is not a valid join.
    # `act[:join_name]` is set by the heartbeat parser; no byte offsets here.
    def self.decode(act)
      index = act[:game_player]
      name = act[:join_name]
      return nil unless name && index.to_i.positive?
      { index: index, name: name }
    end
  end
end
