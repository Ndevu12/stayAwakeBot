#!/usr/bin/env python3
"""Guard for .github/scripts/check_changelog_release.py — the release gate that a vX.Y.Z tag must
have its CHANGELOG section already cut (the guardrail against the [Unreleased] drift that shipped
v0.1.15/v0.1.16 unlisted, #1283). Imports the script by path (it lives outside the package) and
exercises `is_cut` directly, plus one `main()` exit-code check."""
from __future__ import annotations

import importlib.util
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
SCRIPT = REPO / ".github" / "scripts" / "check_changelog_release.py"

_spec = importlib.util.spec_from_file_location("check_changelog_release", SCRIPT)
ccr = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(ccr)

CHANGELOG = """\
# Changelog

## [Unreleased]

## [0.1.17] - 2026-07-31

### Added
- a thing

## [0.1.16] - 2026-07-23
"""


class TestIsCut(unittest.TestCase):
    def test_cut_version_is_found(self):
        self.assertTrue(ccr.is_cut("0.1.17", CHANGELOG))

    def test_leading_v_tolerated(self):
        self.assertTrue(ccr.is_cut("v0.1.17", CHANGELOG))  # GITHUB_REF_NAME is vX.Y.Z

    def test_uncut_version_not_found(self):
        self.assertFalse(ccr.is_cut("0.1.18", CHANGELOG))

    def test_unreleased_pile_is_not_a_match(self):
        self.assertFalse(ccr.is_cut("0.2.0", "# Changelog\n\n## [Unreleased]\n\n- 0.2.0 work\n"))

    def test_dots_are_literal_not_regex(self):
        self.assertFalse(ccr.is_cut("0.1.17", "# Changelog\n\n## [0X1X17] - 2026-07-31\n"))


class TestMainExit(unittest.TestCase):
    def _main(self, version: str, text: str | None):
        with tempfile.TemporaryDirectory() as d:
            cl = Path(d) / "CHANGELOG.md"
            if text is not None:
                cl.write_text(text)
            return ccr.main([version, str(cl)])

    def test_exit_zero_when_cut(self):
        self.assertEqual(self._main("v0.1.17", CHANGELOG), 0)

    def test_exit_one_when_uncut(self):
        self.assertEqual(self._main("0.1.18", CHANGELOG), 1)

    def test_exit_one_when_changelog_missing(self):
        self.assertEqual(self._main("0.1.17", None), 1)

    def test_exit_two_on_bad_usage(self):
        self.assertEqual(ccr.main([]), 2)


if __name__ == "__main__":
    unittest.main()
