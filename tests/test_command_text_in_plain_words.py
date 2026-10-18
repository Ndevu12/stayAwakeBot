#!/usr/bin/env python3
"""`saw --version` and the help of each command say what saw is and does, in plain words."""
from __future__ import annotations

import contextlib
import io
import unittest

from stayawake.cli._meta import __version__
from stayawake.cli import main

_INTERNAL_TERMS = ("capabilities:", "host denials", "SAW Guard", "Read-only", "read-back",
                   "intent/capability", "entry points")


def _printed(argv) -> str:
    out = io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(io.StringIO()):
        try:
            main(argv)
        except SystemExit:
            pass
    return out.getvalue()


class TestTheVersionIsOneLine(unittest.TestCase):
    def test_it_prints_the_version_and_nothing_else(self):
        self.assertEqual(_printed(["--version"]).strip(), f"saw (stayawakebot) {__version__}")


class TestHelpSaysWhatEachCommandDoes(unittest.TestCase):
    def test_no_help_uses_saws_internal_terms(self):
        for argv in (["--help"], ["harden", "-h"], ["guard", "-h"], ["hook", "install", "-h"],
                     ["doctor", "-h"]):
            text = _printed(argv)
            self.assertTrue(text, argv)
            for term in _INTERNAL_TERMS:
                self.assertNotIn(term, text, (argv, term))


if __name__ == "__main__":
    unittest.main()
