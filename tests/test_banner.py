#!/usr/bin/env python3
"""Tests for `cli._banner` — the welcome / intro string builders (issue #1177).

The key guarantee is the NONE tier emitting ZERO ANSI (so piped / CI / NO_COLOR output stays
clean), plus that each colour tier uses the right escape family. Pure functions, no I/O.
"""
from __future__ import annotations

import unittest

from stayawake.cli._banner import SAW_LOGO, render_intro, render_welcome
from stayawake.core.terminal import ColorLevel

ESC = "\033"


class TestBanner(unittest.TestCase):
    def test_none_level_has_no_ansi(self):
        for render in (render_welcome, render_intro):
            self.assertNotIn(ESC, render(ColorLevel.NONE, "1.2.3"))

    def test_welcome_carries_the_essentials(self):
        out = render_welcome(ColorLevel.NONE, "9.9.9")
        for needle in ("saw scan", "saw intro", "supply-chain worm hunter",
                       "zero code runs at install", "v9.9.9",
                       "github.com/Ndevu12/stayAwakeBot"):
            self.assertIn(needle, out)

    def test_intro_covers_the_tour(self):
        out = render_intro(ColorLevel.NONE, "1.0.0")
        for needle in ("What it is", "Three verbs", "Why it's safe", "Gate CI",
                       "saw fix", "--pr", "the exit code IS the verdict"):
            self.assertIn(needle, out)

    def test_truecolor_uses_24bit_sequences(self):
        out = render_welcome(ColorLevel.TRUECOLOR, "1.0.0")
        self.assertIn(f"{ESC}[", out)
        self.assertIn("38;2;", out)          # 24-bit RGB foreground
        self.assertNotIn("38;5;", out)

    def test_ansi256_uses_256_sequences(self):
        out = render_welcome(ColorLevel.ANSI256, "1.0.0")
        self.assertIn("38;5;", out)
        self.assertNotIn("38;2;", out)

    def test_ansi16_uses_no_extended_sequences(self):
        out = render_welcome(ColorLevel.ANSI16, "1.0.0")
        self.assertIn(ESC, out)              # still coloured…
        self.assertNotIn("38;5;", out)       # …but only base 16-colour SGR codes
        self.assertNotIn("38;2;", out)

    def test_logo_rows_are_equal_width(self):
        rows = SAW_LOGO.split("\n")
        self.assertEqual(len(rows), 5)
        self.assertEqual(len({len(r) for r in rows}), 1, "wordmark columns must align")

    def test_colour_is_reset_after_every_span(self):
        # Every opened SGR must be closed with a reset, or colour bleeds into later output.
        out = render_intro(ColorLevel.TRUECOLOR, "1.0.0")
        resets = out.count(f"{ESC}[0m")
        opens = out.count(f"{ESC}[") - resets
        self.assertEqual(opens, resets)


if __name__ == "__main__":
    unittest.main()
