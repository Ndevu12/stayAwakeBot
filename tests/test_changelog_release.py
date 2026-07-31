#!/usr/bin/env python3
"""Guard for .github/scripts/check_changelog_release.sh — the release gate that a vX.Y.Z tag must
have its CHANGELOG section already cut (the guardrail against the [Unreleased] drift that shipped
v0.1.15/v0.1.16 unlisted, #1283). GitHub-free (a version + a file path in, exit code out), so the
boundaries are pinned here, not only in the release workflow."""
from __future__ import annotations

import subprocess
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
SCRIPT = REPO / ".github" / "scripts" / "check_changelog_release.sh"

CHANGELOG = """\
# Changelog

## [Unreleased]

## [0.1.17] - 2026-07-31

### Added
- a thing (#1)

## [0.1.16] - 2026-07-23
"""


class TestChangelogRelease(unittest.TestCase):
    def _run(self, version: str, text: str | None = CHANGELOG):
        with tempfile.TemporaryDirectory() as d:
            cl = Path(d) / "CHANGELOG.md"
            if text is not None:
                cl.write_text(text)
            return subprocess.run(
                ["bash", str(SCRIPT), version, str(cl)],
                capture_output=True, text=True, env={"PATH": "/usr/bin:/bin"})

    def test_script_exists(self):
        self.assertTrue(SCRIPT.exists(), f"missing gate script: {SCRIPT}")

    def test_cut_version_passes(self):
        r = self._run("0.1.17")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)

    def test_leading_v_tolerated(self):
        r = self._run("v0.1.17")           # GITHUB_REF_NAME is vX.Y.Z
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)

    def test_uncut_version_fails(self):
        # 0.1.18 is not in the changelog (still under [Unreleased]) — must block the release.
        r = self._run("0.1.18")
        self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
        self.assertIn("0.1.18", (r.stdout + r.stderr))

    def test_unreleased_pile_is_not_a_match(self):
        # A version whose entries sit only under [Unreleased] (no `## [x]` heading) is NOT cut.
        text = "# Changelog\n\n## [Unreleased]\n\n### Added\n- 0.2.0 work\n"
        r = self._run("0.2.0", text)
        self.assertEqual(r.returncode, 1, r.stdout + r.stderr)

    def test_dots_are_literal_not_regex(self):
        # The version must match literally — `0X1X17` must NOT satisfy a check for `0.1.17`.
        r = self._run("0.1.17", "# Changelog\n\n## [0X1X17] - 2026-07-31\n")
        self.assertEqual(r.returncode, 1, r.stdout + r.stderr)

    def test_missing_changelog_fails(self):
        r = self._run("0.1.17", text=None)     # no CHANGELOG.md written
        self.assertEqual(r.returncode, 1, r.stdout + r.stderr)


if __name__ == "__main__":
    unittest.main()
