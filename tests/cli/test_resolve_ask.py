#!/usr/bin/env python3
"""Tests for `cli.resolve.ask` — the one-item keep/remove/restore prompt.

Driven with StringIO stand-ins: `remove` and its short forms remove; `restore` restores when the item
carries a clean version; blank, unknown, and end of input keep; an unclear answer is re-asked before
keeping.
"""
from __future__ import annotations

import io
import unittest

from stayawake.bots.security.pr.resolve import KEEP, REMOVE, RESTORE, SUPPLY, UncertainItem
from stayawake.cli.resolve.ask import ask_resolution


def _item(restore_candidate=None, restore_source="", keep_content=False):
    return UncertainItem("x.js", "code-loader", "sig", "why", b"const a = 1;\n",
                         restore_candidate=restore_candidate, restore_source=restore_source,
                         keep_content=keep_content)


def _ask(typed, **kw):
    return ask_resolution(_item(**kw), stdin=io.StringIO(typed), stderr=io.StringIO())


class TestAskResolution(unittest.TestCase):
    def test_remove_removes(self):
        self.assertEqual(_ask("remove\n").action, REMOVE)

    def test_short_and_yes_forms_remove(self):
        self.assertEqual(_ask("r\n").action, REMOVE)
        self.assertEqual(_ask("  YES \n").action, REMOVE)
        self.assertEqual(_ask("y\n").action, REMOVE)

    def test_keep_and_no_keep(self):
        self.assertEqual(_ask("keep\n").action, KEEP)
        self.assertEqual(_ask("no\n").action, KEEP)

    def test_a_blank_line_keeps(self):
        self.assertEqual(_ask("\n").action, KEEP)

    def test_end_of_input_keeps(self):
        self.assertEqual(_ask("").action, KEEP)

    def test_an_unclear_answer_is_re_asked_then_honoured(self):
        self.assertEqual(_ask("what?\nremove\n").action, REMOVE)

    def test_unclear_answers_exhaust_to_keep(self):
        self.assertEqual(_ask("a\nb\nc\nremove\n").action, KEEP)

    def test_the_safe_block_is_shown_to_the_operator(self):
        err = io.StringIO()
        ask_resolution(_item(), stdin=io.StringIO("keep\n"), stderr=err)
        self.assertIn("do NOT trust", err.getvalue())

    def test_restore_is_offered_and_returns_the_candidate_when_present(self):
        entry = ("100644", "a" * 40)
        answer = _ask("restore\n", restore_candidate=entry, restore_source="dead00beef01")
        self.assertEqual(answer.action, RESTORE)
        self.assertEqual(answer.restore, entry)

    def test_restore_is_ignored_when_no_candidate(self):
        # With no clean version to put back, "restore" is unknown and is re-asked, then kept.
        self.assertEqual(_ask("restore\nrestore\nrestore\n").action, KEEP)

    def test_the_restore_prompt_is_shown_only_when_a_candidate_exists(self):
        err = io.StringIO()
        ask_resolution(_item(restore_candidate=("100644", "b" * 40), restore_source="c0ffee00"),
                       stdin=io.StringIO("keep\n"), stderr=err)
        self.assertIn("restore", err.getvalue().lower())

    def test_supply_reads_the_bytes_of_a_file_the_operator_names(self):
        import os
        import tempfile
        fd, path = tempfile.mkstemp()
        os.write(fd, b"export const ok = true;\n")
        os.close(fd)
        try:
            answer = ask_resolution(_item(keep_content=True),
                                    stdin=io.StringIO(f"supply\n{path}\n"), stderr=io.StringIO())
        finally:
            os.unlink(path)
        self.assertEqual(answer.action, SUPPLY)
        self.assertEqual(answer.supply, b"export const ok = true;\n")

    def test_supply_is_not_offered_without_keep_content(self):
        self.assertEqual(_ask("supply\nsupply\nsupply\n").action, KEEP)

    def test_an_unreadable_supplied_path_falls_through_to_keep(self):
        answer = ask_resolution(_item(keep_content=True),
                                stdin=io.StringIO("supply\n/no/such/file/here\n"),
                                stderr=io.StringIO())
        self.assertEqual(answer.action, KEEP)


if __name__ == "__main__":
    unittest.main()
