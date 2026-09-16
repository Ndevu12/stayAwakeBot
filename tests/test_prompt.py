#!/usr/bin/env python3
"""Tests for `utils.prompt` — the terminal primitives behind an interactive operator question.

`interactive` gates on both streams being real terminals; `ask_line` writes the prompt to the error
stream, reads one line, and returns None (never crashes) at end of input or on a broken stream.
"""
from __future__ import annotations

import unittest
from unittest import mock

from stayawake.utils import prompt


class _In:
    """Input stand-in with a settable isatty() and a queue of readline() results."""
    def __init__(self, lines=(), tty=True, raises=None) -> None:
        self._lines = list(lines)
        self._tty = tty
        self._raises = raises

    def isatty(self) -> bool:
        return self._tty

    def readline(self) -> str:
        if self._raises is not None:
            raise self._raises
        return self._lines.pop(0) if self._lines else ""


class _Out:
    """Output stand-in that records what was written and reports a settable isatty()."""
    def __init__(self, tty=True) -> None:
        self._tty = tty
        self.written: list[str] = []

    def isatty(self) -> bool:
        return self._tty

    def write(self, s: str) -> None:
        self.written.append(s)

    def flush(self) -> None:
        pass


class TestInteractive(unittest.TestCase):
    def test_both_terminals_is_interactive(self):
        self.assertTrue(prompt.interactive(_In(tty=True), _Out(tty=True)))

    def test_a_non_tty_input_is_not_interactive(self):
        self.assertFalse(prompt.interactive(_In(tty=False), _Out(tty=True)))

    def test_a_non_tty_prompt_stream_is_not_interactive(self):
        self.assertFalse(prompt.interactive(_In(tty=True), _Out(tty=False)))

    def test_defaults_to_the_process_streams(self):
        with mock.patch("sys.stdin", _In(tty=True)), mock.patch("sys.stderr", _Out(tty=True)):
            self.assertTrue(prompt.interactive())


class TestAskLine(unittest.TestCase):
    def test_writes_the_prompt_and_returns_the_typed_line(self):
        out = _Out()
        answer = prompt.ask_line("remove suspect.bin? [y/N] ",
                                 stdin=_In(["yes\n"]), stderr=out)
        self.assertEqual(answer, "yes")
        self.assertEqual("".join(out.written), "remove suspect.bin? [y/N] ")

    def test_strips_a_crlf_ending(self):
        self.assertEqual(prompt.ask_line("? ", stdin=_In(["keep\r\n"]), stderr=_Out()), "keep")

    def test_a_blank_line_is_an_empty_answer_not_eof(self):
        self.assertEqual(prompt.ask_line("? ", stdin=_In(["\n"]), stderr=_Out()), "")

    def test_end_of_input_returns_none(self):
        self.assertIsNone(prompt.ask_line("? ", stdin=_In([]), stderr=_Out()))

    def test_a_broken_stream_returns_none(self):
        self.assertIsNone(
            prompt.ask_line("? ", stdin=_In(raises=ValueError("closed")), stderr=_Out()))
        self.assertIsNone(
            prompt.ask_line("? ", stdin=_In(raises=OSError("detached")), stderr=_Out()))

    def test_keyboard_interrupt_propagates(self):
        with self.assertRaises(KeyboardInterrupt):
            prompt.ask_line("? ", stdin=_In(raises=KeyboardInterrupt()), stderr=_Out())


if __name__ == "__main__":
    unittest.main()
