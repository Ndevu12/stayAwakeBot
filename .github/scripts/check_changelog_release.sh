#!/usr/bin/env bash
# Release gate: a vX.Y.Z tag must have its CHANGELOG section already cut. Releases were tagged
# straight onto main without cutting [Unreleased], so v0.1.15 and v0.1.16 shipped unlisted and three
# versions piled up under [Unreleased] before #1283 had to reconstruct them. This fails the release
# BEFORE anything publishes when CHANGELOG.md has no `## [X.Y.Z]` heading for the version being
# tagged — forcing the [Unreleased] → [X.Y.Z] cut first. Standalone + GitHub-free so the logic is
# unit-tested (tests/test_changelog_release.py), like the scanner-pin scripts.
#
# Usage: check_changelog_release.sh <version> [changelog-path]   (version may include a leading v)
# Exit:  0 = the version's section exists · 1 = it's missing (or the changelog is unreadable).
set -euo pipefail

version="${1:?usage: check_changelog_release.sh <X.Y.Z> [changelog]}"
changelog="${2:-CHANGELOG.md}"
version="${version#v}"                                   # tolerate a leading v (GITHUB_REF_NAME = vX.Y.Z)

if [ ! -f "$changelog" ]; then
  echo "::error::$changelog not found — cannot verify the release section for $version."
  exit 1
fi

# A cut section is a real heading `## [X.Y.Z]` (optionally ` - DATE`). The dots are escaped so the
# version isn't read as a regex. The still-open [Unreleased] pile is deliberately NOT a match.
if grep -qE "^## \[${version//./\\.}\]" "$changelog"; then
  echo "CHANGELOG: found the [$version] section — OK to release."
  exit 0
fi

echo "::error::CHANGELOG.md has no '## [$version]' section for the tag being released. Cut" \
     "[Unreleased] into '## [$version] - <date>' (add a fresh empty [Unreleased] + the compare" \
     "link), merge that via PR, and re-tag v$version. This gate stops the [Unreleased] drift that" \
     "left v0.1.15/v0.1.16 unlisted (reconstructed in #1283)."
exit 1
