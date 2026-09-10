#!/usr/bin/env python3
"""Pins for the footprint excision authority: full-footprint removal, and fail-closed results."""
from __future__ import annotations

import re
import unittest

from stayawake.bots.security.models import CONFIRMED, Finding, Severity
from stayawake.bots.security.remediation import footprint
from stayawake.bots.security.signatures import load_signatures


def _flat():
    return [s for group in load_signatures().values() for s in group]


def _finding(category, path, sig="x"):
    return Finding(sig, category, Severity.MEDIUM, path, "d", confidence=CONFIRMED)


class TestLineMarkerStrip(unittest.TestCase):
    _P = [re.compile(r"temp_auto_push\.bat|branch_structure\.json", re.IGNORECASE)]

    def test_removes_every_matching_line_and_keeps_the_rest(self):
        text = ("node_modules\ntemp_auto_push.bat\ndist/\nbranch_structure.json\n.env\n")
        out = footprint.line_marker_strip(text, self._P)
        self.assertEqual(out, "node_modules\ndist/\n.env\n")

    def test_removes_a_repeat_of_the_marker_not_just_the_first(self):
        text = "temp_auto_push.bat\nkeep\ntemp_auto_push.bat\n"
        self.assertEqual(footprint.line_marker_strip(text, self._P), "keep\n")

    def test_none_when_nothing_matches(self):
        self.assertIsNone(footprint.line_marker_strip("a\nb\n", self._P))

    def test_only_ever_removes_never_fabricates(self):
        text = "keep\ntemp_auto_push.bat\n"
        out = footprint.line_marker_strip(text, self._P)
        self.assertTrue(all(ch in iter(text) for ch in out))  # subsequence


class TestCarriesFootprint(unittest.TestCase):
    def test_loader_check_does_not_flag_a_gitignore_marker(self):
        # Why the clean-mode gate needs a per-finding oracle: the loader check is blind to a marker.
        loader = footprint.carries_footprint(_finding("code-loader", "x.mjs"), _flat())
        self.assertFalse(loader("temp_auto_push.bat\n"))

    def test_marker_check_flags_the_marker_line(self):
        marker = footprint.carries_footprint(_finding("git-marker", ".gitignore"), _flat())
        self.assertTrue(marker("node_modules\ntemp_auto_push.bat\n"))
        self.assertFalse(marker("node_modules\ndist/\n"))


class TestCorrectorFor(unittest.TestCase):
    def test_no_corrector_for_an_unmodelled_category(self):
        self.assertIsNone(footprint.corrector_for(_finding("camouflage", "README.md"), _flat()))
        self.assertIsNone(footprint.carries_footprint(_finding("camouflage", "README.md"), _flat()))

    def test_marker_corrector_strips_the_footprint(self):
        clean = footprint.corrector_for(_finding("git-marker", ".gitignore"), _flat())
        out = clean("node_modules\ntemp_auto_push.bat\nbranch_structure.json\n")
        self.assertEqual(out, "node_modules\n")

    def test_marker_corrector_is_none_when_the_file_is_clean(self):
        clean = footprint.corrector_for(_finding("git-marker", ".gitignore"), _flat())
        self.assertIsNone(clean("node_modules\ndist/\n"))


if __name__ == "__main__":
    unittest.main()
