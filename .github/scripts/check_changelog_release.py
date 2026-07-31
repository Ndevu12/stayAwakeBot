#!/usr/bin/env python3
"""Release gate: a vX.Y.Z tag must have its CHANGELOG section already cut. Releases were tagged
straight onto main without cutting [Unreleased], so v0.1.15 and v0.1.16 shipped unlisted and three
versions piled up before #1283 had to reconstruct them. Run in release.yml's build job on tag
pushes, this fails the release BEFORE anything publishes when CHANGELOG.md has no `## [X.Y.Z]`
heading for the version being tagged — forcing the [Unreleased] -> [X.Y.Z] cut first.

Stdlib-only and importable (`is_cut`), so the logic is unit-tested in tests/test_changelog_release.py.

Usage: check_changelog_release.py <version> [changelog-path]   (version may include a leading v)
Exit:  0 = the version's section exists · 1 = missing / unreadable changelog · 2 = bad usage.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path


def is_cut(version: str, changelog_text: str) -> bool:
    """True when `changelog_text` has a real `## [X.Y.Z]` heading for `version` (a leading `v` is
    tolerated). The still-open `## [Unreleased]` pile is deliberately NOT a match, and the version
    is matched literally (dots escaped), so `0X1X17` never satisfies a check for `0.1.17`."""
    version = version.lstrip("v")
    return re.search(rf"^## \[{re.escape(version)}\]", changelog_text, re.MULTILINE) is not None


def main(argv: list[str]) -> int:
    if not argv:
        print("usage: check_changelog_release.py <X.Y.Z> [changelog]", file=sys.stderr)
        return 2
    version = argv[0].lstrip("v")
    path = Path(argv[1]) if len(argv) > 1 else Path("CHANGELOG.md")
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        print(f"::error::cannot read {path} to verify the release section for {version}: {exc}",
              file=sys.stderr)
        return 1
    if is_cut(version, text):
        print(f"CHANGELOG: found the [{version}] section — OK to release.")
        return 0
    print(f"::error::CHANGELOG.md has no '## [{version}]' section for the tag being released. Cut "
          f"[Unreleased] into '## [{version}] - <date>' (add a fresh empty [Unreleased] + the "
          f"compare link), merge that via PR, and re-tag v{version}. This gate stops the "
          f"[Unreleased] drift that left v0.1.15/v0.1.16 unlisted (reconstructed in #1283).",
          file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
