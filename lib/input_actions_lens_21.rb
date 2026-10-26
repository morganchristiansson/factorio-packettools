# frozen_string_literal: true

# MEASURED client→server payload lengths for the 2.1.23 stable protocol —
# by wire ID. Same discipline as input_actions_lens_20.rb: these are read
# off the wire, not copied from any table: every C→S heartbeat's actions
# end at a known byte (see tools/action_len_solver.rb), so with the rest of
# a closure's actions known, the one unknown length is arithmetic.
#
# Measured from captures/server-34197-20261025-084429.pcap.gz (a 2.1.23 /
# build 87750 server, 83,746 C→S packets). Every entry below held by >=4
# closures and a 3× lead over the runner-up, except where the comment says
# otherwise. Observation-count drift at the tail of the capture set
# re-verifies for free on any future run: DO NOT hand-edit to "match the
# table".
#
# ── What the lens COVERS ────────────────────────────────────────────
# Only types whose ACTION table length is wrong or nil on stable 2.1.23:
# the experimental ACTIONS table (which ACTIONS_21 inherits from by name)
# misnames or mis-lengthed several actions, so the table value cannot be
# trusted for these. The lens provides the measured ground truth.
#
# ── What the lens EXCLUDES ──────────────────────────────────────────
# Types handled by name-based length hacks in parse_action (the trailer-
# absorbing family: selected_entity_cleared/9, hover/zoom/pan family
# 262–268/310, open_character_gui/61, build/69) are NOT here — the hacks
# compute their lengths from structure (is_last, is_server) and a lens
# value would clobber the trailer byte. Neither are types whose table
# length already matches the wire (drop_item/68, start_walking/70,
# wire_dragging/86, setup_assembling_machine/88, pipette/90, stack_split/91,
# inventory_split/92, start_repair/130, fast_entity_transfer/279,
# rotate_entity/280, set_linked_container_link_i_d/315, cursor_split/79,
# server_tick_info/84) — for those the table is correct and no override
# is needed.
#
# The override order in parse_action is: table → name hacks → lens →
# content computations (build_terrain/translate_string). Since hack types
# are intentionally absent from this lens, the hacks retain control for
# trailer absorption and the lens only corrects the non-hack types below.
#
# ── Key corrections vs the experimental table ─────────────────────
#  66: table nil — stable has an Unknown(66) action (1 byte measured)
#  89: table nil — stable has an Unknown(89) action (3 bytes measured)
#  94: table nil — set_filter carries no C→S body (0 bytes across 7 closures)
# 110: table 15 — stable type 110 is NOT change_active_item_group_for_filters
#       (the experimental name); it is 0 bytes (SurfaceDeleted on the wire
#       per factorio_dissector/factorio.lua). 0 across 170 closures.
# 269: table nil — set_combinator_description carries no C→S body (0 bytes)
# 282: table nil — fast_entity_split carries no C→S body (0 bytes across 131
#       closures)
C2S_LENS_21 = {
  66  => 1,
  89  => 3,
  94  => 0,
  110 => 0,
  269 => 0,
  282 => 0,
}.freeze
