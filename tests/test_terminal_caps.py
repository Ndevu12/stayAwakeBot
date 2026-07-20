#!/usr/bin/env python3
"""Tests for `core.terminal.color_level` — the single colour-capability decision.

Each precedence branch (NO_COLOR, CLICOLOR_FORCE, TTY, CI, dumb, the COLORTERM/TERM tiers) is
exercised in isolation. Env is patched with `clear=True` so no ambient variable leaks in.
"""
from __future__ import annotations

import os
import unittest
from unittest import mock

from stayawake.utils.terminal import ColorLevel, color_level, supports_color


class _Stream:
    """Minimal stand-in for stdout with a settable isatty()."""
    def __init__(self, tty: bool) -> None:
        self._tty = tty

    def isatty(self) -> bool:
        return self._tty


def _level(tty: bool, **env) -> ColorLevel:
    with mock.patch.dict(os.environ, env, clear=True):
        return color_level(_Stream(tty))


class TestColorLevel(unittest.TestCase):
    # ── NO_COLOR: the hard override ───────────────────────────────────────────────
    def test_no_color_disables_even_on_truecolor_tty(self):
        self.assertIs(_level(True, COLORTERM="truecolor", NO_COLOR="1"), ColorLevel.NONE)

    def test_no_color_beats_clicolor_force(self):
        self.assertIs(_level(False, NO_COLOR="1", CLICOLOR_FORCE="1", COLORTERM="truecolor"),
                      ColorLevel.NONE)

    def test_empty_no_color_is_not_set(self):
        # env.get treats a blank value as unset, per the NO_COLOR spec (present *and non-empty*).
        self.assertIs(_level(True, NO_COLOR="", COLORTERM="truecolor"), ColorLevel.TRUECOLOR)

    # ── TTY gate ──────────────────────────────────────────────────────────────────
    def test_not_a_tty_is_none(self):
        self.assertIs(_level(False, COLORTERM="truecolor"), ColorLevel.NONE)

    def test_clicolor_force_colours_a_non_tty(self):
        self.assertIs(_level(False, CLICOLOR_FORCE="1", COLORTERM="truecolor"),
                      ColorLevel.TRUECOLOR)

    def test_clicolor_force_zero_is_not_forced(self):
        self.assertIs(_level(False, CLICOLOR_FORCE="0", COLORTERM="truecolor"), ColorLevel.NONE)

    # ── CI / dumb suppression ─────────────────────────────────────────────────────
    def test_ci_suppresses_on_a_tty(self):
        self.assertIs(_level(True, CI="true", COLORTERM="truecolor"), ColorLevel.NONE)

    def test_clicolor_force_overrides_ci(self):
        self.assertIs(_level(True, CI="true", CLICOLOR_FORCE="1", COLORTERM="truecolor"),
                      ColorLevel.TRUECOLOR)

    def test_dumb_terminal_is_none(self):
        self.assertIs(_level(True, TERM="dumb", COLORTERM="truecolor"), ColorLevel.NONE)

    # ── capability tiers ──────────────────────────────────────────────────────────
    def test_truecolor_from_colorterm(self):
        self.assertIs(_level(True, COLORTERM="24bit"), ColorLevel.TRUECOLOR)

    def test_ansi256_from_term(self):
        self.assertIs(_level(True, TERM="xterm-256color"), ColorLevel.ANSI256)

    def test_ansi16_default_tty(self):
        self.assertIs(_level(True, TERM="xterm"), ColorLevel.ANSI16)

    def test_ansi16_when_no_term_hints(self):
        self.assertIs(_level(True), ColorLevel.ANSI16)

    # ── supports_color convenience ────────────────────────────────────────────────
    def test_supports_color_boolean(self):
        with mock.patch.dict(os.environ, {"COLORTERM": "truecolor"}, clear=True):
            self.assertTrue(supports_color(_Stream(True)))
            self.assertFalse(supports_color(_Stream(False)))


if __name__ == "__main__":
    unittest.main()
