#!/usr/bin/env python3
"""A finding's preview of the scanned file starts at a whole word, close before what was found."""
from __future__ import annotations

import io
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

from stayawake.bots.security.matchers.base import evidence
from stayawake.bots.security.redaction import PREVIEW_LEN, redact

_IGNORE_FILE = "node_modules/\nnode_modules\ntemp_auto_push.bat\nbranch_structure.json\n"


def _window(text: str, found: str) -> str:
    """The preview window saw cuts around the first `found` in `text`."""
    start = text.index(found)
    return evidence(text, start, start + len(found))


class TestAPreviewStartsAtAWholeWord(unittest.TestCase):
    def test_the_ignore_file_finding_starts_at_the_marker(self):
        window = _window(_IGNORE_FILE, "temp_auto_push.bat")
        self.assertTrue(window.startswith("temp_auto_push.bat"), window)

    def test_a_preview_starts_at_the_next_whole_word_before_the_match(self):
        self.assertEqual(_window("alphabetical omega MATCH tail", "MATCH"), "omega MATCH tail")

    def test_a_preview_inside_one_long_word_starts_at_the_match(self):
        text = "x" * 40 + "MATCH" + " tail"
        self.assertEqual(_window(text, "MATCH"), "MATCH tail")

    def test_a_whole_word_where_the_preview_opens_is_kept(self):
        self.assertEqual(_window("aaaa bbbbbbbbbbb MATCH tail", "MATCH"), "bbbbbbbbbbb MATCH tail")

    def test_a_match_near_the_start_of_the_file_keeps_everything_before_it(self):
        self.assertEqual(_window("abc MATCH tail", "MATCH"), "abc MATCH tail")


class TestAPreviewStaysClose(unittest.TestCase):
    def test_a_preview_never_opens_more_than_twelve_characters_before_the_match(self):
        cases = [("alphabetical omega MATCH tail", "MATCH"), ("x" * 40 + "MATCH tail", "MATCH"),
                 (_IGNORE_FILE, "temp_auto_push.bat"), ("first second third MATCH tail", "MATCH"),
                 ("a_b_c_d_e_f_g_h_i_j MATCH tail", "MATCH")]
        for text, found in cases:
            start = text.index(found)
            window = _window(text, found).rstrip("…")
            opens_at = text.replace("\n", " ").find(window)
            self.assertTrue(start - 12 <= opens_at <= start, (text, window))

    def test_the_shown_preview_is_still_forty_eight_characters_from_its_start(self):
        text = "alphabetical omega " + "MATCH" * 30
        preview = redact(_window(text, "MATCH"))["preview"]
        self.assertEqual(len(preview), PREVIEW_LEN)
        self.assertTrue(preview.startswith("omega MATCH"), preview)


class TestTheScanShowsTheWholeWord(unittest.TestCase):
    def test_a_scan_shows_the_marker_as_written(self):
        from stayawake.bots.security import service
        folder = Path(tempfile.mkdtemp())
        (folder / ".gitignore").write_text(_IGNORE_FILE, encoding="utf-8")
        config = folder / "c.yml"
        config.write_text("allowlist: []\n", encoding="utf-8")
        out = io.StringIO()
        with redirect_stdout(out), redirect_stderr(io.StringIO()):
            service.scan(str(config), paths=[str(folder)], no_stream=True)
        self.assertIn("found: `temp_auto_push.bat", out.getvalue())
        self.assertNotIn("ode_modules", out.getvalue().replace("node_modules", ""))


if __name__ == "__main__":
    unittest.main()
