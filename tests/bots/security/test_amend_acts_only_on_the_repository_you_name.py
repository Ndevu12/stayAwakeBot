#!/usr/bin/env python3
"""`saw fix amend` acts only on the repository you are in or the ones you name."""
from __future__ import annotations

import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from stayawake.bots.security import remediator
from stayawake.bots.security.targets import ScanOptions


class _Lines:
    enabled = False

    def __init__(self):
        self.said: list[str] = []

    def line(self, text=""):
        self.said.append(str(text))


class TestAmendActsOnlyOnTheRepositoryYouName(unittest.TestCase):
    def setUp(self):
        here = os.getcwd()
        self.addCleanup(os.chdir, here)
        self.home = Path(tempfile.mkdtemp()).resolve()
        self.repos = {}
        for name in ("one", "two", "three"):
            path = self.home / "code" / name
            subprocess.run(["git", "init", "-q", str(path)], check=True)
            self.repos[name] = path
        (self.repos["one"] / "src").mkdir()

    def _amend(self, *, stand_in, paths=None, cfg=None):
        os.chdir(stand_in)
        rewritten: list = []
        lines = _Lines()
        with mock.patch.dict(os.environ, {"HOME": str(self.home)}), \
                mock.patch.object(remediator.auth, "resolve_token", return_value=(None, None)), \
                mock.patch.object(remediator, "_preflight", return_value=None), \
                mock.patch.object(remediator, "_run_fix_sweep",
                                  side_effect=lambda repos, *a, **k: rewritten.extend(repos) or []):
            remediator._amend_local(cfg or {}, ScanOptions(), [], [], paths, lines)
        return rewritten, "\n".join(lines.said)

    def test_with_nothing_named_it_amends_only_the_repository_it_is_run_in(self):
        rewritten, _ = self._amend(stand_in=self.repos["one"])
        self.assertEqual(rewritten, [self.repos["one"]])

    def test_from_a_folder_inside_a_repository_it_amends_that_repository(self):
        rewritten, _ = self._amend(stand_in=self.repos["one"] / "src")
        self.assertEqual(rewritten, [self.repos["one"]])

    def test_outside_a_repository_it_amends_nothing_and_says_how_to_name_one(self):
        rewritten, said = self._amend(stand_in=self.home)
        self.assertEqual(rewritten, [])
        self.assertIn("nothing was changed", said)
        self.assertIn("saw fix amend <folder>", said)

    def test_a_named_folder_holding_repositories_is_refused(self):
        rewritten, said = self._amend(stand_in=self.repos["one"], paths=[str(self.home / "code")])
        self.assertEqual(rewritten, [])
        self.assertIn("nothing was changed", said)

    def test_configured_targets_are_not_amended(self):
        cfg = {"targets": {"local": [str(self.home / "code" / "*")]}}
        rewritten, _ = self._amend(stand_in=self.repos["three"], cfg=cfg)
        self.assertEqual(rewritten, [self.repos["three"]])

    def test_repositories_named_one_by_one_are_amended(self):
        named = [str(self.repos["one"]), str(self.repos["two"])]
        rewritten, _ = self._amend(stand_in=self.home, paths=named)
        self.assertEqual(rewritten, [self.repos["one"], self.repos["two"]])


class TestARemoteAmendNeedsANamedRepository(unittest.TestCase):
    def test_remote_with_no_repository_named_changes_nothing(self):
        lines = _Lines()
        with mock.patch.object(remediator, "_resolve_remote",
                               side_effect=AssertionError("must not look for repositories")):
            outcomes = remediator._amend_remote({}, ScanOptions(), [], [], lines, slugs=None)
        self.assertEqual(outcomes, [])
        self.assertIn("Nothing was changed.", "\n".join(lines.said))


class TestScanAndFixStillSweep(unittest.TestCase):
    def test_a_bare_fix_still_looks_under_the_home_folder(self):
        home = tempfile.mkdtemp()
        with mock.patch.dict(os.environ, {"HOME": home}):
            self.assertEqual(remediator._local_patterns({}, []), [str(Path(home))])


if __name__ == "__main__":
    unittest.main()
