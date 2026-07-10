#!/usr/bin/env bash
# In-band scanner-pin freshness check — companion to scanner-pin-drift.yml (the weekly, OUT-OF-BAND
# backstop). The worm-guard gate pins its detection engine to a reviewed SHA (`sentinel-ref` in
# worm-guard.yml). If a PR changes the engine subtree but doesn't bump that pin, the gate keeps
# running an out-of-date scanner — the exact silent drift #1172 fixes. This decides, from a PR's
# diff alone, whether that invariant is violated. Kept as a standalone, GitHub-free script so the
# logic is unit-testable (tests/test_pin_tooling.py) instead of buried in workflow YAML.
#
# Usage: check_pin_freshness.sh <changed-files> <unified-diff>
#   <changed-files>  file with one changed path per line   (from: gh pr diff --name-only)
#   <unified-diff>   file with the PR's unified diff        (from: gh pr diff)
# Env:
#   DEFERRED  'yes' when the PR carries the deferral label  (default 'no')
# Exit: 0 = OK (pass) · 1 = engine changed without a pin bump and not deferred.
set -euo pipefail

changed_files="${1:?usage: check_pin_freshness.sh <changed-files> <unified-diff>}"
unified_diff="${2:?usage: check_pin_freshness.sh <changed-files> <unified-diff>}"
deferred="${DEFERRED:-no}"

# Shared definitions (engine subtree + pin token) — one source, also used by check_pin_drift.sh.
source "$(dirname "${BASH_SOURCE[0]}")/_pin_lib.sh"

# The engine seam as a --name-only path anchor. --name-only gives bare paths (no a/ b/ prefix);
# the trailing slash keeps it from matching a sibling like `.../security_helpers/`.
engine_re="^${PIN_ENGINE_SUBTREE}/"
# An ADDED (+) pin line carrying a 40-char SHA = a deliberate bump. Reusing PIN_TOKEN_RE means the
# floating-ref rejection (`sentinel-ref: main` doesn't count) is defined once, for both paths.
pin_re="^\\+[[:space:]]*${PIN_TOKEN_RE}"

engine_changed=no
if grep -qE "$engine_re" "$changed_files"; then engine_changed=yes; fi
pin_bumped=no
if grep -qE "$pin_re" "$unified_diff"; then pin_bumped=yes; fi

if [ "$engine_changed" = no ]; then
  echo "Pin freshness: PR does not touch the detection engine — nothing to enforce."
  exit 0
fi
if [ "$pin_bumped" = yes ]; then
  echo "Pin freshness: engine changed and sentinel-ref was bumped in this PR — OK."
  exit 0
fi
if [ "$deferred" = yes ]; then
  echo "::notice::Pin freshness: the engine changed and the pin was NOT bumped, but this PR is" \
       "labeled 'pin-bump-deferred' — deferral acknowledged. Remember to bump sentinel-ref before" \
       "or at the end of this line of work."
  exit 0
fi

echo "::error::This PR changes the detection engine (src/stayawake/bots/security/**) but does not" \
     "bump 'sentinel-ref' in .github/workflows/worm-guard.yml — the worm-guard gate would keep" \
     "scanning with the OLD pinned engine. Fix: bump sentinel-ref to a current reviewed main SHA in" \
     "this PR, or add the 'pin-bump-deferred' label to defer the bump deliberately (e.g. one bump at" \
     "the end of an epic)."
exit 1
