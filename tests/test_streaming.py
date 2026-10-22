#!/usr/bin/env python3
"""core/streaming.py — the typewriter writer + spinner must be byte-for-byte plain when
disabled (piped / CI / --no-stream / env), so report artifacts and stdout consumers are
unaffected; only the cadence is animated on a TTY."""
from __future__ import annotations

import io
import os
import time
import unittest
from unittest import mock

from stayawake.utils import streaming
from stayawake.utils.render import term_width
from stayawake.utils.streaming import Streamer, say, status, stream_enabled


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

    def test_say_force_off_writes_instantly(self):
        buf = io.StringIO()
        with mock.patch.object(streaming, "stream_enabled", return_value=False) as enabled:
            say("hello", no_stream=True, out=buf)
        self.assertTrue(enabled.call_args.kwargs.get("force_off"))
        self.assertEqual(buf.getvalue(), "hello\n")

    def test_env_disables_even_on_tty(self):
        fake_tty = mock.Mock()
        fake_tty.isatty.return_value = True
        with mock.patch.dict(os.environ, {"STAYAWAKE_NO_STREAM": "1"}):
            self.assertFalse(stream_enabled(fake_tty))
        with mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop("STAYAWAKE_NO_STREAM", None)
            self.assertTrue(stream_enabled(fake_tty))


class TestLiveOutputWhenItIsAskedFor(unittest.TestCase):
    def tearDown(self):
        streaming.ask_for_live_output(False)

    def test_a_pipe_stays_plain_until_asked(self):
        pipe = io.StringIO()
        self.assertFalse(stream_enabled(pipe))
        with mock.patch.dict(os.environ, {"STAYAWAKE_STREAM": "1"}):
            self.assertTrue(stream_enabled(pipe))
        streaming.ask_for_live_output(True)
        self.assertTrue(stream_enabled(pipe))

    def test_asking_off_wins(self):
        pipe = io.StringIO()
        with mock.patch.dict(os.environ, {"STAYAWAKE_STREAM": "1", "STAYAWAKE_NO_STREAM": "1"}):
            self.assertFalse(stream_enabled(pipe, force_on=True))
        streaming.ask_for_live_output(True)
        self.assertFalse(stream_enabled(pipe, force_off=True))

    def test_an_off_word_does_not_ask(self):
        pipe = io.StringIO()
        with mock.patch.dict(os.environ, {"STAYAWAKE_STREAM": "0"}):
            self.assertFalse(stream_enabled(pipe))

    def test_the_step_is_shown_when_the_output_is_not_a_terminal(self):
        err = io.StringIO()
        out = io.StringIO()

        def check():
            time.sleep(0.25)
            return []

        from stayawake.cli.dispatch import main
        with mock.patch("stayawake.bots.security.hygiene.audit_checks",
                        return_value=[("running processes", check)]), \
             mock.patch("stayawake.lib.auth.resolve_token", return_value=(None, None)), \
             mock.patch("sys.stderr", err), mock.patch("sys.stdout", out):
            main(["audit", "--stream"])
        shown = err.getvalue()
        self.assertIn("checking running processes", shown)
        self.assertIn("\r", shown)
        self.assertIn("\033[K", shown)
        self.assertNotIn("\r", out.getvalue())
        self.assertFalse(stream_enabled(io.StringIO()))

    def test_json_stays_the_document_and_the_steps_are_separate(self):
        err = io.StringIO()
        out = io.StringIO()

        def check():
            time.sleep(0.25)
            return []

        from stayawake.cli.dispatch import main
        with mock.patch("stayawake.bots.security.hygiene.audit_checks",
                        return_value=[("running processes", check)]), \
             mock.patch("stayawake.lib.auth.resolve_token", return_value=(None, None)), \
             mock.patch("sys.stderr", err), mock.patch("sys.stdout", out):
            main(["audit", "--json", "--stream"])
        import json
        report = json.loads(out.getvalue())
        self.assertIn("schema_version", report)
        self.assertNotIn("checking running processes", out.getvalue())
        self.assertIn("checking running processes", err.getvalue())

    def test_no_stream_wins_over_stream_for_the_json_commands(self):
        from stayawake.cli.argtypes import no_stream_requested, stream_requested
        from stayawake.cli.dispatch import build_parser
        parser = build_parser()
        asked = parser.parse_args(["fix", "--json", "--stream"])
        streaming.ask_for_live_output(stream_requested(asked))
        self.assertTrue(stream_enabled(io.StringIO(), force_off=no_stream_requested(asked)))
        both = parser.parse_args(["audit", "--json", "--stream", "--no-stream"])
        self.assertFalse(stream_enabled(io.StringIO(), force_off=no_stream_requested(both)))

    def test_the_width_follows_columns(self):
        with mock.patch.dict(os.environ, {"COLUMNS": "60"}):
            self.assertEqual(term_width(), 60)


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
