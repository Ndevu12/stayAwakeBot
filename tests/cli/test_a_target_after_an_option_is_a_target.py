#!/usr/bin/env python3
"""A target named after an option is one more target; anything else a command does not know is refused."""
from __future__ import annotations

import contextlib
import io
import unittest

from stayawake.cli import dispatch


def _parse(*argv: str):
    return dispatch._parsed(dispatch.build_parser(), list(argv))


def _refused(*argv: str) -> tuple[int, str]:
    said = io.StringIO()
    with contextlib.redirect_stderr(said), unittest.TestCase().assertRaises(SystemExit) as stop:
        _parse(*argv)
    return stop.exception.code, said.getvalue()


class TestATargetAfterAnOptionIsATarget(unittest.TestCase):
    def test_amend_takes_its_repository_after_the_config(self):
        args = _parse("fix", "amend", "-c", "config/security.yml", ".")
        self.assertEqual(args.paths, ["amend", "."])
        self.assertEqual(args.config, "config/security.yml")

    def test_targets_on_both_sides_of_an_option_are_kept_in_order(self):
        self.assertEqual(_parse("scan", "a", "-c", "f.yml", "b").paths, ["a", "b"])

    def test_a_guard_target_after_an_option_is_kept(self):
        self.assertEqual(_parse("guard", "check", "a", "-c", "f.yml", "b").targets, ["a", "b"])

    def test_an_unknown_option_is_still_refused(self):
        code, said = _refused("scan", ".", "--no-such-option")
        self.assertEqual(code, 2)
        self.assertIn("unrecognized arguments: --no-such-option", said)

    def test_a_word_for_a_command_that_takes_no_targets_is_still_refused(self):
        code, said = _refused("audit", "stray")
        self.assertEqual(code, 2)
        self.assertIn("unrecognized arguments: stray", said)


if __name__ == "__main__":
    unittest.main()
