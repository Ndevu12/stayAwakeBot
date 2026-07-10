#!/usr/bin/env bash
# Out-of-band drift detector (companion to check_pin_freshness.sh, the in-band PR gate). Compares
# the worm-guard gate's pinned scanner (sentinel-ref) against the detection engine on the current
# HEAD and opens/updates/closes a tracking issue accordingly. Run by scanner-pin-drift.yml (weekly
# + on demand) as the backstop for drift that bypasses the PR gate (e.g. an admin direct-push).
# Extracted from the workflow YAML so the logic lives beside — and shares one source of truth with
# — the freshness check (SRP + DRY); requires a full-history checkout (the pin must be reachable).
#
# Env: GH_TOKEN (for gh). Exit: 0 always on success (drift is reported as an issue, not a failure).
set -euo pipefail

source "$(dirname "${BASH_SOURCE[0]}")/_pin_lib.sh"

pin="$(extract_pin "$PIN_GUARD_FILE")"
if [ -z "$pin" ]; then
  echo "::error::could not read a 40-char sentinel-ref SHA from $PIN_GUARD_FILE"; exit 1
fi
echo "Pinned scanner: $pin"

title="worm-guard scanner pin is behind main"
existing="$(gh issue list --state open --search "$title in:title" \
             --json number,title --jq ".[] | select(.title==\"$title\") | .number" | head -1)"

if git diff --quiet "$pin" HEAD -- "$PIN_ENGINE_SUBTREE"; then
  echo "Engine pin is current with main — no drift."
  if [ -n "$existing" ]; then
    gh issue close "$existing" --comment "Engine pin is current again (resolved automatically)."
  fi
  exit 0
fi

echo "::warning::engine has drifted from the pinned scanner ($pin)"
changed="$(git diff --name-only "$pin" HEAD -- "$PIN_ENGINE_SUBTREE" | sed 's/^/- /')"
# Build the body with printf so no YAML/heredoc indentation leaks in as leading spaces (which
# markdown would render as a code block).
body="$(printf '%s\n\n%s\n\n%s\n%s\n\n%s' \
  "The worm-guard gate pins \`sentinel-ref: $pin\`, but the detection engine (\`$PIN_ENGINE_SUBTREE/\`) on \`main\` has changed since. **The gate is running an out-of-date scanner.**" \
  "Bump \`sentinel-ref\` in \`$PIN_GUARD_FILE\` to a current reviewed \`main\` SHA (after confirming the change is intended), then merge." \
  "Engine files changed since the pin:" \
  "$changed" \
  "_Auto-opened by the \`scanner-pin-drift\` workflow; it closes itself when the pin catches up._")"

if [ -n "$existing" ]; then
  gh issue comment "$existing" --body "Still drifting as of $(git rev-parse --short HEAD)."
else
  gh issue create --title "$title" --body "$body"
fi
