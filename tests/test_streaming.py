#!/usr/bin/env python3
"""core/streaming.py — the typewriter writer + spinner must be byte-for-byte plain when
disabled (piped / CI / --no-stream / env), so report artifacts and stdout consumers are
unaffected; only the cadence is animated on a TTY."""
from __future__ import annotations

import io
import os
import unittest
from unittest import mock

from stayawake.core import streaming
from stayawake.core.streaming import Streamer, status, stream_enabled


class TestStreamerDisabled(unittest.TestCase):
    def test_disabled_writes_text_verbatim(self):
        buf = io.StringIO()
        sw = Streamer(out=buf, enabled=False)
        sw.write("hello world")
        sw.line("  [1/2] [INFECTED] ~/a (3 findings)")
        self.assertEqual(buf.getvalue(),
                         "hello world  [1/2] [INFECTED] ~/a (3 findings)\n")

    def test_disabled_has_no_escape_codes_or_cr(self):
        buf = io.StringIO()
        Streamer(out=buf, enabled=False).line("x")
        self.assertNotIn("\r", buf.getvalue())
        self.assertNotIn("\033", buf.getvalue())

    def test_enabled_writes_identical_bytes_just_slower(self):
        # Even animated, the FULL text emitted is identical — cadence only.
        buf = io.StringIO()
        sw = Streamer(out=buf, enabled=True, cps=1e9, max_seconds=0.0, by="word")
        text = "  [2/9] [clean   ] ~/Dev/web/x  (0 findings)\n"
        sw.write(text)
        self.assertEqual(buf.getvalue(), text)

    def test_char_and_word_modes_emit_same_text(self):
        for by in ("word", "char"):
            buf = io.StringIO()
            Streamer(out=buf, enabled=True, cps=1e9, max_seconds=0.0, by=by).write("a b\nc")
            self.assertEqual(buf.getvalue(), "a b\nc", by)


class TestAutoEnable(unittest.TestCase):
    def test_non_tty_is_disabled(self):
        self.assertFalse(Streamer(out=io.StringIO()).enabled)        # StringIO isn't a TTY

    def test_stream_enabled_force_off(self):
        self.assertFalse(stream_enabled(io.StringIO(), force_off=True))

    def test_env_disables_even_on_tty(self):
        fake_tty = mock.Mock()
        fake_tty.isatty.return_value = True
        with mock.patch.dict(os.environ, {"STAYAWAKE_NO_STREAM": "1"}):
            self.assertFalse(stream_enabled(fake_tty))
        with mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop("STAYAWAKE_NO_STREAM", None)
            self.assertTrue(stream_enabled(fake_tty))


class TestStatusSpinner(unittest.TestCase):
    def test_disabled_is_silent(self):
        buf = io.StringIO()
        with status("Discovering…", out=buf, enabled=False):
            pass
        self.assertEqual(buf.getvalue(), "")     # silent — the result line conveys progress

    def test_disabled_yields_and_runs_body(self):
        ran = []
        with status("x", out=io.StringIO(), enabled=False):
            ran.append(True)
        self.assertEqual(ran, [True])


if __name__ == "__main__":
    unittest.main()
