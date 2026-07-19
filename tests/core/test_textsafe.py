#!/usr/bin/env python3
"""Unit tests for core.textsafe — the shared output-encoding for untrusted strings.

These previously lived only implicitly under test_pr.py (the fix PR/issue bodies). Extracting the
helpers into a shared module means they get tested directly, so every caller (saw fix, saw guard
setup, …) inherits proven behavior. The escaping contract originates in #1183/#1184 and the
GitHub Actions log-injection work.
"""
from __future__ import annotations

import unittest

from stayawake.core import textsafe


class TestSanitize(unittest.TestCase):
    def test_neutralizes_backtick_so_span_cannot_break_out(self):
        # A value rendered INSIDE a code span must not close it early.
        self.assertNotIn("`", textsafe.sanitize("evil`.js"))

    def test_control_and_separators_become_space(self):
        # Newlines / bidi overrides can't break the list item or spoof direction. Built via chr()
        # so no raw control/bidi literal sits in the source (line/para sep, RLO override, NUL).
        for ch in ("\n", "\r", chr(0x2028), chr(0x202E), "\x00"):
            self.assertNotIn(ch, textsafe.sanitize("a" + ch + "b"))

    def test_bounded(self):
        self.assertLessEqual(len(textsafe.sanitize("x" * 5000, limit=100)), 100)

    def test_keeps_ordinary_text(self):
        self.assertEqual(textsafe.sanitize("src/index.js"), "src/index.js")


class TestCode(unittest.TestCase):
    def test_wraps_in_a_balanced_code_span(self):
        self.assertEqual(textsafe.code("plain"), "`plain`")

    def test_injection_stays_inside_the_span(self):
        # Markdown link + interior backtick + newline: the dangerous bits are neutralized and the
        # result is a single balanced span, so nothing renders as active markup.
        out = textsafe.code("[CLICK](https://evil.example)/x`.js\n## PWNED")
        self.assertTrue(out.startswith("`") and out.endswith("`"))
        self.assertEqual(out.count("`"), 2)          # exactly the two delimiters — no early close
        self.assertNotIn("\n", out)


class TestPlain(unittest.TestCase):
    def test_defangs_both_actions_command_introducers(self):
        # `::cmd::` (line-start) AND legacy `##[cmd]` (matched anywhere) must both be broken.
        out = textsafe.plain("path ::error:: and ##[warning] here")
        self.assertNotIn("::", out)
        self.assertNotIn("##[", out)

    def test_control_and_separators_become_space_and_stripped(self):
        out = textsafe.plain("\na b\n")
        self.assertNotIn("\n", out)
        self.assertEqual(out, "a b")                 # leading/trailing space stripped

    def test_bounded(self):
        self.assertLessEqual(len(textsafe.plain("y" * 5000, limit=40)), 40)


if __name__ == "__main__":
    unittest.main()
