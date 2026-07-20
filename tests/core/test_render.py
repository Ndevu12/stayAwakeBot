#!/usr/bin/env python3
"""Unit tests for the shared terminal-render toolkit (core.render): colour gating, the palette,
width-aware wrapping, rules, and terminal-width fallback. These are the MECHANISM both the scan
sink and the audit report compose, so they are pinned here once."""
from __future__ import annotations

import unittest
from unittest import mock

from stayawake.utils import render


class TestPaint(unittest.TestCase):
    def test_on_wraps_code_and_resets(self):
        self.assertEqual(render.paint("x", "\033[31m", on=True), "\033[31mx\033[0m")

    def test_off_is_identity_even_with_a_code(self):
        self.assertEqual(render.paint("x", "\033[31m", on=False), "x")

    def test_on_without_a_code_is_identity(self):
        # A palette miss (code=None) must never emit a bare RESET or raise.
        self.assertEqual(render.paint("x", None, on=True), "x")

    def test_no_reset_leaks_when_off(self):
        self.assertNotIn("\033", render.paint("x", "\033[31m", on=False))


class TestRule(unittest.TestCase):
    def test_width(self):
        self.assertEqual(render.rule(5), "─────")

    def test_zero_and_negative_are_empty(self):
        self.assertEqual(render.rule(0), "")
        self.assertEqual(render.rule(-4), "")

    def test_custom_char(self):
        self.assertEqual(render.rule(3, "="), "===")


class TestWrap(unittest.TestCase):
    def test_short_text_one_line_with_indent(self):
        self.assertEqual(render.wrap("hello world", 40, indent=2), ["  hello world"])

    def test_wraps_to_width(self):
        lines = render.wrap("one two three four five six", 12)
        self.assertTrue(all(len(l) <= 12 for l in lines))
        self.assertGreater(len(lines), 1)
        self.assertEqual(" ".join(lines).split(), "one two three four five six".split())

    def test_hanging_indent_on_continuations(self):
        lines = render.wrap("alpha beta gamma delta", 16, indent=0, hanging=4)
        self.assertFalse(lines[0].startswith(" "))          # first line flush
        self.assertTrue(lines[1].startswith("    "))         # continuations hang 4

    def test_long_unbreakable_token_is_not_split(self):
        # A path/URL longer than width must survive intact (a mangled path is worse than a long line).
        url = "https://example.com/a/very/long/unbreakable/path/segment/token"
        lines = render.wrap(f"see {url} now", 20)
        self.assertIn(url, "\n".join(lines))                 # token never chopped
        self.assertTrue(any(url in l for l in lines))

    def test_empty_text_yields_no_lines(self):
        self.assertEqual(render.wrap("", 40), [])

    def test_tiny_width_does_not_raise(self):
        self.assertEqual(render.wrap("hi there", 1, indent=3), ["   hi there"])


class TestTermWidth(unittest.TestCase):
    def test_uses_reported_columns(self):
        with mock.patch.object(render.shutil, "get_terminal_size",
                               return_value=mock.Mock(columns=123)):
            self.assertEqual(render.term_width(), 123)

    def test_falls_back_on_exception(self):
        with mock.patch.object(render.shutil, "get_terminal_size", side_effect=OSError):
            self.assertEqual(render.term_width(default=77), 77)

    def test_falls_back_on_nonpositive(self):
        with mock.patch.object(render.shutil, "get_terminal_size",
                               return_value=mock.Mock(columns=0)):
            self.assertEqual(render.term_width(default=80), 80)


class TestBlock(unittest.TestCase):
    def test_plain_paragraph_indented(self):
        self.assertEqual(render.block("hello world", indent=2, width=40), ["  hello world"])

    def test_marker_on_first_line_text_hangs_under_it(self):
        # First line: indent + marker + text; continuations align under the TEXT (indent+len(marker)).
        out = render.block("alpha beta gamma delta epsilon", indent=2, width=20, marker="→ ")
        self.assertTrue(out[0].startswith("  → alpha"))
        self.assertTrue(out[1].startswith("    "))          # 2 indent + 2 marker = 4-space hang
        self.assertFalse(out[1].startswith("     "))

    def test_marker_coloured_only_when_on(self):
        on = render.block("x", marker="• ", code="\033[31m", color=True)
        off = render.block("x", marker="• ", code="\033[31m", color=False)
        self.assertIn("\033[31m", on[0])
        self.assertNotIn("\033[", off[0])
        self.assertEqual(off, ["• x"])

    def test_empty_text_yields_no_lines(self):
        self.assertEqual(render.block("", indent=4, marker="• "), [])


class TestMarkedList(unittest.TestCase):
    def test_bulleted(self):
        out = render.marked_list(["one", "two"], indent=2, width=40)
        self.assertEqual(out, ["  • one", "  • two"])

    def test_numbered(self):
        out = render.marked_list(["a", "b", "c"], ordered=True, indent=0, width=40)
        self.assertEqual(out, ["1. a", "2. b", "3. c"])

    def test_numbers_right_align_past_nine(self):
        out = render.marked_list([f"i{n}" for n in range(1, 11)], ordered=True, width=40)
        self.assertTrue(out[0].startswith(" 1. "))          # padded to width of "10"
        self.assertTrue(out[9].startswith("10. "))

    def test_start_offset(self):
        self.assertEqual(render.marked_list(["x"], ordered=True, start=3), ["3. x"])

    def test_wraps_each_item_with_hanging_indent(self):
        out = render.marked_list(["short", "a much longer item that will certainly wrap here"],
                                 ordered=True, indent=0, width=24)
        self.assertEqual(out[0], "1. short")
        self.assertTrue(out[2].startswith("   "))           # continuation hangs under the text (3)

    def test_empty_list_is_empty(self):
        self.assertEqual(render.marked_list([], ordered=True), [])


class TestPalette(unittest.TestCase):
    def test_severity_has_every_level_both_surfaces_grade(self):
        for k in ("critical", "high", "medium", "low", "warning", "info", "ok"):
            self.assertIn(k, render.SEVERITY)
            self.assertTrue(render.SEVERITY[k].startswith("\033["))

    def test_status_covers_the_scan_verdicts(self):
        for k in ("INFECTED", "SUSPECT", "ERROR", "clean"):
            self.assertIn(k, render.STATUS)
            self.assertTrue(render.STATUS[k].startswith("\033["))


if __name__ == "__main__":
    unittest.main()
