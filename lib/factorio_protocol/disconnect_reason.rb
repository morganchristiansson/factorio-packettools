# frozen_string_literal: true

# Factorio's `defines.disconnect_reason` — the reason code the server writes
# into an S→C leave's 9-byte metadata block and into the synchronizer's
# PeerDisconnect action. One enum, two places on the wire, so it lives here
# instead of in either parser.
#
# The order is the game's own definition order (/factorio/doc-html/defines.html)
# and the values are the 2.1.24 server's `defines.disconnect_reason` table
# (dumped live via RCON — the docs' `order` field is NOT the wire value).
# Verified against captures: 0 = quit (bunjae/Xell_XS), 1 = dropped
# (MrHanniZap), 7 = kicked (BURMALDAMELLSTROY's /kick on 2026-11-05).
# 10 has no entry in defines on 2.1.24; 11 is switching_servers, not 10.
module FactorioProtocol
  module DisconnectReason
    NAMES = {
      0 => :quit, 1 => :dropped, 2 => :reconnect, 3 => :wrong_input,
      4 => :desync_limit_reached, 5 => :cannot_keep_up, 6 => :afk,
      7 => :kicked, 8 => :kicked_and_deleted, 9 => :banned,
      11 => :switching_servers
    }.freeze

    module_function

    # Numeric code → symbol. An unknown number is still named, as :reason_N:
    # the metadata must be consumed so the rest of the closure stays aligned,
    # so "unknown" is not a reason to refuse the block.
    def name(code)
      return nil unless code.is_a?(Integer)
      NAMES[code] || :"reason_#{code}"
    end

    # Phrase for "<name> <phrase>" lines (console, Discord, Hivemind). Only the
    # reasons actually observed on this server get specific wording; the rest
    # read as a plain quit rather than inventing a cause we have not measured.
    def text(symbol)
      case symbol
      when :dropped then 'was dropped from the game'
      when :kicked, :kicked_and_deleted then 'was kicked from the game'
      when :banned then 'was banned from the game'
      else 'left the game'
      end
    end
  end
end
