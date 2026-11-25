#!/usr/bin/env python3
"""Which reports folder was asked for, and in which order the sources are read."""
from __future__ import annotations

import contextlib
import io as _io
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from stayawake.utils.io import resolve_reports_dir, reports_dir_choice, write_json


class TestResolveReportsDir(unittest.TestCase):
    """Shared precedence: explicit → STAYAWAKE_REPORTS_DIR env → settings → default
    (then readied by scratch.destination_dir). One place so the report writers
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
