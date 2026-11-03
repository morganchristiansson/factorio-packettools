# frozen_string_literal: true

module FactorioProtocol
  # Quickbar input actions (2.0 wire IDs in parentheses). Single source of
  # truth for what each payload means, so the sniffer's tracker and its
  # console formatter agree.
  #
  # Measured on the 2.0.77 captures in captures/ (2026-09-25, 14 files,
  # ~500k heartbeats); see docs/protocol-notes.md.
  #
  #   quick_bar_set_slot (245) — 5 bytes on stable 2.1:
  #     [item u8][slot u8][op u8][src u16 LE]
  #     op 0 = set the slot's filter, 1 = clear it. src = the inventory slot
  #     the item came from, 0xFFFF = none. 2.0 carried a trailing client tick
  #     (9 bytes); stable 2.1 dropped it — measured 2026-11-03, 102 closures.
  #     byte 0 is the ITEM, not the slot (base-game item prototype id); byte 1
  #     is the slot. The page the slot belongs to is announced separately
  #     (quick_bar_set_selected_page / change_active_quick_bar).
  #
  #   quick_bar_pick_slot (246) — 4 bytes: [item u8][slot u8][op u8][pad u8]
  #     Measured 2026-11-03: 2576 closures against 18 for the runner-up. The
  #     table's 0 here used to leave these 4 bytes to be re-parsed as phantom
  #     actions (and every pick looked like an undecodable quickbar action).
  #
  #   quick_bar_set_selected_page (247) — 2 bytes: [pad u8][page u8]
  #     byte 0 is 0 in every clean sample; page is byte 1 (0..4 observed).
  #
  #   change_active_quick_bar (302) — 1 byte: [page u8]
  #
  # ponytail: the item field is read as a plain u8. No capture shows 0xFF
  # there, so an item id >= 255 (a possible 3-byte uint16v escape) has
  # never been observed; if one shows up the payload will be 6 bytes and
  # .decode returns :undecodable rather than misrecording a slot.
  module QuickBar
    # Decode a quickbar action's payload into a hash, or:
    #   nil           — not a quickbar action at all (every other input action)
    #   :undecodable  — a quickbar action whose payload shape we do not know
    #     (see the ponytail note above); callers treat it as desync evidence
    def self.decode(act)
      d = act[:data]
      case act[:name]
      when :quick_bar_set_slot
        return :undecodable unless d && d.bytesize == 5
        src = d.unpack1('v', offset: 3)
        {item: d.getbyte(0), slot: d.getbyte(1), op: d.getbyte(2),
         src: (src == 0xFFFF ? nil : src)}
      when :quick_bar_pick_slot
        return :undecodable unless d && d.bytesize == 4
        {item: d.getbyte(0), slot: d.getbyte(1), op: d.getbyte(2)}
      when :quick_bar_set_selected_page
        d && d.bytesize >= 2 ? {page: d.getbyte(1)} : :undecodable
      when :change_active_quick_bar
        d && !d.empty? ? {page: d.getbyte(0)} : :undecodable
      end
    end
  end
end
