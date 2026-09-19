#!/usr/bin/env python3
"""Tests for `cli.resolve.build` — the environment gate deciding whether to ask the operator.

A resolver is built only when both streams are real terminals and the run is not CI; otherwise the
result is None so the core behaves exactly as it does with no operator present.
"""
from __future__ import annotations

import os
import unittest
from unittest import mock

from stayawake.bots.security.pr.resolve import REMOVE, UncertainItem
from stayawake.cli.resolve.build import build_resolver


class _TTY:
    """A stream stand-in with a settable isatty(), a readline() queue, and a write() sink."""
    def __init__(self, tty=True, lines=()) -> None:
        self._tty = tty
        self._lines = list(lines)

    def isatty(self) -> bool:
        return self._tty

    def readline(self) -> str:
        return self._lines.pop(0) if self._lines else ""

    def write(self, s: str) -> None:
        pass

    def flush(self) -> None:
        pass


def _item():
    return UncertainItem("x.js", "code-loader", "sig", "why", b"a\n", "", ())


class TestBuildResolver(unittest.TestCase):
    def test_interactive_and_not_ci_builds_a_working_resolver(self):
        with mock.patch.dict(os.environ, {}, clear=True):
            resolver = build_resolver(_TTY(lines=["remove\n"]), _TTY())
        self.assertIsNotNone(resolver)
        self.assertEqual(resolver(_item()).action, REMOVE)

    def test_a_non_tty_input_gives_no_resolver(self):
        with mock.patch.dict(os.environ, {}, clear=True):
            self.assertIsNone(build_resolver(_TTY(tty=False), _TTY()))

    def test_a_non_tty_prompt_stream_gives_no_resolver(self):
        with mock.patch.dict(os.environ, {}, clear=True):
            self.assertIsNone(build_resolver(_TTY(), _TTY(tty=False)))

    def test_ci_gives_no_resolver_even_on_a_tty(self):
        with mock.patch.dict(os.environ, {"CI": "true"}, clear=True):
            self.assertIsNone(build_resolver(_TTY(), _TTY()))


if __name__ == "__main__":
    unittest.main()
