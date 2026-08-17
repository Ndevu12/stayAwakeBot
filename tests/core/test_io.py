#!/usr/bin/env python3
"""resolve_writable_dir: report writing must degrade gracefully on an unwritable dir,
never crash a completed run."""
from __future__ import annotations

import contextlib
import io as _io
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from stayawake.utils.io import (resolve_writable_dir, resolve_reports_dir,
                                reports_dir_choice, write_json)


class TestResolveWritableDir(unittest.TestCase):
    def test_writable_preferred_is_used_silently(self):
        with tempfile.TemporaryDirectory() as d:
            target = Path(d) / "reports" / "security"
            err = _io.StringIO()
            with contextlib.redirect_stderr(err):
                got = resolve_writable_dir(target, label="security reports")
            self.assertEqual(got, target)
            self.assertTrue(got.is_dir())
            self.assertEqual(err.getvalue(), "")            # no warning on the happy path

    def test_unwritable_preferred_falls_back_and_warns(self):
        # Force an unwritable preferred path in a uid-independent way: make its parent a
        # regular FILE so mkdir raises NotADirectoryError for any user — unlike chmod, which
        # root ignores (and CI/test runners are often root).
        with tempfile.TemporaryDirectory() as d:
            blocker = Path(d) / "blocker"
            blocker.write_text("not a dir\n")
            target = blocker / "security"               # parent is a file -> mkdir fails
            err = _io.StringIO()
            with contextlib.redirect_stderr(err):
                got = resolve_writable_dir(target, label="security reports")
            self.assertNotEqual(got, target)
            self.assertTrue(got.is_dir())
            warning = err.getvalue()
            self.assertIn("not writable", warning)          # warned…
            self.assertIn(str(target), warning)             # …naming the path we couldn't use
            # and the fallback is genuinely writable
            write_json(got / "latest.json", {"ok": True})
            self.assertTrue((got / "latest.json").exists())


class TestResolveReportsDir(unittest.TestCase):
    """Shared precedence: explicit → STAYAWAKE_REPORTS_DIR env → settings → default
    (then made writable via resolve_writable_dir). One place so the report writers
    don't each re-implement it."""

    def _resolve(self, *, explicit=None, env=None, settings_value=None, default="def"):
        # Every candidate lives under one writable temp dir, so the result equals whichever
        # candidate won the precedence (no fallback) — we're asserting precedence, not
        # writability. STAYAWAKE_REPORTS_DIR is forced to exactly `env` (or absent).
        with tempfile.TemporaryDirectory() as d:
            under = lambda name: str(Path(d) / name) if name else None
            environ = {"STAYAWAKE_REPORTS_DIR": under(env)} if env else {}
            with mock.patch.dict("os.environ", environ, clear=True):
                got = resolve_reports_dir(explicit=under(explicit),
                                          settings_value=under(settings_value),
                                          default=under(default))
            return Path(d), got

    def test_explicit_wins(self):
        base, got = self._resolve(explicit="cli", env="envd", settings_value="cfg")
        self.assertEqual(got, base / "cli")

    def test_env_beats_settings_and_default(self):
        base, got = self._resolve(env="envd", settings_value="cfg")
        self.assertEqual(got, base / "envd")

    def test_settings_beats_default(self):
        base, got = self._resolve(settings_value="cfg")
        self.assertEqual(got, base / "cfg")

    def test_default_when_nothing_set(self):
        base, got = self._resolve()
        self.assertEqual(got, base / "def")


class TestReportsDirChoice(unittest.TestCase):
    """`reports_dir_choice`: WAS a bundle asked for, and by whom. Split out of `resolve_reports_dir`
    so a caller can distinguish "nobody asked" from "asked, here is where" (#1454) — gating on the
    CLI value alone made the env and settings rungs unreachable."""

    def _choice(self, *, explicit=None, env=None, settings_value=None):
        environ = {"STAYAWAKE_REPORTS_DIR": env} if env else {}
        with mock.patch.dict("os.environ", environ, clear=True):
            return reports_dir_choice(explicit, settings_value=settings_value)

    def test_none_when_nobody_asked(self):
        # The whole point: no source asked, so the caller must write nothing rather than fall back
        # to a default path the user never named.
        self.assertIsNone(self._choice())

    def test_settings_alone_is_enough_to_ask(self):
        self.assertEqual(self._choice(settings_value="cfg"), "cfg")

    def test_env_alone_is_enough_to_ask(self):
        # The container image sets this so a scan in the image writes somewhere container-owned.
        self.assertEqual(self._choice(env="/tmp/stayawake"), "/tmp/stayawake")

    def test_precedence_matches_resolve(self):
        self.assertEqual(self._choice(explicit="cli", env="envd", settings_value="cfg"), "cli")
        self.assertEqual(self._choice(env="envd", settings_value="cfg"), "envd")


if __name__ == "__main__":
    unittest.main()
