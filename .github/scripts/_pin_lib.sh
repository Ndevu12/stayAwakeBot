#!/usr/bin/env bash
# Single source of truth for the worm-guard scanner pin. ALL enforcement paths build on this so
# "what is the detection engine", "how the pin is written", and "which files carry it" are defined
# exactly ONCE (DRY):
#   - in-band  : check_pin_freshness.sh  (fails a PR that changes the engine without a pin bump)
#   - in-band  : check_pins_synced.sh    (fails when the two pin copies disagree — no silent drift)
#   - out-of-band: check_pin_drift.sh    (opens an issue when the pinned engine falls behind main)
# Sourced, never executed. Leading underscore marks it a library (cf. prevent/hooks/_worm_lib.sh).

# Include guard: sourcing twice must not fail on the readonly reassignment below.
[ -n "${PIN_LIB_LOADED:-}" ] && return 0
PIN_LIB_LOADED=1

# The detection-engine subtree. Engine ONLY — so report/signature-doc commits never count as drift,
# and a PR that touches only tests/docs never demands a pin bump. This is the seam the pin tracks.
readonly PIN_ENGINE_SUBTREE='src/stayawake/bots/security'
# The gate whose pinned scanner we track (the drift backstop compares main against THIS pin).
readonly PIN_GUARD_FILE='.github/workflows/worm-guard.yml'
# The release pipeline's self-scan carries a SECOND, independent copy of the pin. It must stay
# identical to the guard pin or the release gate silently scans with a different engine — exactly
# the drift check_pins_synced.sh exists to prevent. Add any further pin carrier to PIN_FILES below.
readonly PIN_RELEASE_FILE='.github/workflows/release.yml'
# Every file that pins the scanner. All of them must hold the SAME reviewed SHA.
readonly PIN_FILES=("$PIN_GUARD_FILE" "$PIN_RELEASE_FILE")
# The pin token: `sentinel-ref: <40-hex SHA>`. A 40-char SHA is REQUIRED — a floating ref
# (`sentinel-ref: main`) violates the pin doctrine and must NEVER read as a valid pin, in either
# the drift extraction or the freshness "was it bumped?" check.
readonly PIN_TOKEN_RE='sentinel-ref:[[:space:]]*[0-9a-f]{40}'

# extract_pin <file> → prints the pinned 40-char SHA on stdout (empty if none/floating).
extract_pin() {
  grep -oE "$PIN_TOKEN_RE" "${1:?usage: extract_pin <file>}" | grep -oE '[0-9a-f]{40}' | head -1
}
