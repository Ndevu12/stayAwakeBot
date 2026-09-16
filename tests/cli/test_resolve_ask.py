#!/usr/bin/env python3
"""Tests for `cli.resolve.ask` — the one-item keep/remove prompt.

Driven with StringIO stand-ins: `remove` and its short forms remove; blank, unknown, and end of
input keep; an unclear answer is re-asked before keeping.
"""
from __future__ import annotations

import io
import unittest

from stayawake.bots.security.pr.resolve import UncertainItem
from stayawake.cli.resolve.ask import ask_decision


def _item():
    return UncertainItem("x.js", "code-loader", "sig", "why", b"const a = 1;\n", "", ())


def _ask(typed):
    return ask_decision(_item(), stdin=io.StringIO(typed), stderr=io.StringIO())


class TestAskDecision(unittest.TestCase):
    def test_remove_removes(self):
        self.assertTrue(_ask("remove\n").remove)

    def test_short_and_yes_forms_remove(self):
        self.assertTrue(_ask("r\n").remove)
        self.assertTrue(_ask("  YES \n").remove)
        self.assertTrue(_ask("y\n").remove)

    def test_keep_and_no_keep(self):
        self.assertFalse(_ask("keep\n").remove)
        self.assertFalse(_ask("no\n").remove)

    def test_a_blank_line_keeps(self):
        self.assertFalse(_ask("\n").remove)

    def test_end_of_input_keeps(self):
        self.assertFalse(_ask("").remove)

    def test_an_unclear_answer_is_re_asked_then_honoured(self):
        self.assertTrue(_ask("what?\nremove\n").remove)

    def test_unclear_answers_exhaust_to_keep(self):
        self.assertFalse(_ask("a\nb\nc\nremove\n").remove)

    def test_the_safe_block_is_shown_to_the_operator(self):
        err = io.StringIO()
        ask_decision(_item(), stdin=io.StringIO("keep\n"), stderr=err)
        self.assertIn("do NOT trust", err.getvalue())


if __name__ == "__main__":
    unittest.main()
