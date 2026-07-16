#!/usr/bin/env bash
# In-band gate: every workflow that pins the scanner (sentinel-ref) must pin the SAME reviewed SHA.
# There are two independent copies — the worm-guard gate (PIN_GUARD_FILE) and the release self-scan
# (PIN_RELEASE_FILE) — and check_pin_freshness.sh only requires *a* bump somewhere on engine
# changes, never that the two AGREE. Without this, the release pin drifts silently behind the guard
# (found 2026-07: worm-guard at #1193 while release.yml was stranded at #1138, its comment still
# claiming "in sync"). Companion to check_pin_freshness.sh, run in the same required pin-freshness
# job. Standalone + GitHub-free so the logic is unit-tested (tests/test_pin_tooling.py).
#
# Usage: check_pins_synced.sh [file ...]   (defaults to the PIN_FILES set in _pin_lib.sh)
# Exit:  0 = all pins present and identical · 1 = a pin is missing/floating, or the pins disagree.
set -euo pipefail

source "$(dirname "${BASH_SOURCE[0]}")/_pin_lib.sh"

files=("$@")
[ "${#files[@]}" -eq 0 ] && files=("${PIN_FILES[@]}")

ref=""; ref_file=""; status=0
for f in "${files[@]}"; do
  pin="$(extract_pin "$f")"
  if [ -z "$pin" ]; then
    echo "::error::no 40-char sentinel-ref SHA in $f — a floating ref ('sentinel-ref: main') is not" \
         "a valid pin. Every pin carrier must hold the same reviewed main SHA."
    status=1
    continue
  fi
  if [ -z "$ref" ]; then
    ref="$pin"; ref_file="$f"
  elif [ "$pin" != "$ref" ]; then
    echo "::error::scanner pin mismatch — $ref_file pins $ref but $f pins $pin. Bump BOTH to the" \
         "same reviewed main SHA (the worm-guard gate and the release self-scan must scan with the" \
         "same engine)."
    status=1
  fi
done

[ "$status" -eq 0 ] && echo "Scanner pins in sync: $ref across ${#files[@]} file(s)."
exit "$status"
