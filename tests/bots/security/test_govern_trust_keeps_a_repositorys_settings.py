#!/usr/bin/env python3
"""`saw govern trust` keeps the programs a repository's own git settings start, only on a person's
answer at a terminal, until they change. `--forget` stops keeping them. A checked update saw writes
keeps them kept. A change made another way is not kept."""
from __future__ import annotations

import argparse
import io
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from stayawake.bots.security import kept_settings
from stayawake.cli.commands import govern as govern_cli
from stayawake.lib.git import settings_fingerprint
from stayawake.lib.git.run import real_git
from stayawake.utils import exitcodes


class _Terminal(io.StringIO):
    def isatty(self) -> bool:
        return True


@unittest.skipIf(os.name == "nt", "the git stand-in runs on Linux and macOS")
class TrustKeepsARepositorysSettings(unittest.TestCase):
    def setUp(self):
        self.root = Path(os.path.realpath(tempfile.mkdtemp(prefix="saw-trust-")))
        self.addCleanup(shutil.rmtree, self.root, True)
        (self.root / ".gitconfig").write_text("[user]\n\tname = Operator\n", encoding="utf-8")
        environment = {"HOME": str(self.root), "XDG_CACHE_HOME": str(self.root / "cache"),
                       "GIT_CONFIG_GLOBAL": str(self.root / ".gitconfig"), "GIT_CONFIG_NOSYSTEM": "1"}
        patched = mock.patch.dict(os.environ, environment)
        patched.start()
        self.addCleanup(patched.stop)
        os.environ.pop("SAW_GOVERN_DECISION", None)
        self.repo = self.root / "repo"
        subprocess.run([real_git(), "init", "-q", str(self.repo)], check=True, stdin=subprocess.DEVNULL)
        self.hook = self.repo / ".git" / "hooks" / "pre-commit"
        self.hook.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")

    def trust(self, answer: str | None, forget: bool = False) -> int:
        stdin = _Terminal(answer) if answer is not None else io.StringIO("y\n")
        stderr = _Terminal() if answer is not None else io.StringIO()
        with mock.patch("sys.stdin", stdin), mock.patch("sys.stderr", stderr):
            return govern_cli.run_trust(argparse.Namespace(repo=str(self.repo), forget=forget))

    def kept(self) -> bool:
        return kept_settings.is_kept(settings_fingerprint.fingerprint(self.repo))

    def test_a_person_who_answers_yes_keeps_them(self):
        self.assertEqual(self.trust("y\n"), exitcodes.CLEAN)
        self.assertTrue(self.kept())
        self.assertTrue(kept_settings.record_path().is_relative_to(self.root / "cache" / "saw"))

    def test_any_other_answer_keeps_nothing(self):
        self.assertEqual(self.trust("\n"), exitcodes.DID_NOT_RUN)
        self.assertFalse(self.kept())

    def test_with_no_one_at_a_terminal_nothing_is_kept_whatever_was_decided_ahead(self):
        for decision in ("run-as-typed", "yes", "let-in"):
            with mock.patch.dict(os.environ, {"SAW_GOVERN_DECISION": decision}):
                self.assertEqual(self.trust(None), exitcodes.DID_NOT_RUN)
            self.assertFalse(self.kept(), decision)

    def test_changed_settings_are_no_longer_kept(self):
        self.trust("y\n")
        self.hook.write_text("#!/bin/sh\necho changed\n", encoding="utf-8")
        self.assertFalse(self.kept())

    def test_forget_stops_keeping_them(self):
        self.trust("y\n")
        self.assertEqual(self.trust(None, forget=True), exitcodes.CLEAN)
        self.assertFalse(self.kept())

    def test_the_record_is_never_kept_inside_a_repository(self):
        with mock.patch.dict(os.environ, {"XDG_CACHE_HOME": str(self.repo / "cache")}):
            self.assertEqual(self.trust("y\n"), exitcodes.DID_NOT_RUN)
            self.assertFalse(kept_settings.record_path().exists())

    def test_a_checked_update_saw_writes_keeps_them_kept(self):
        self.trust("y\n")
        before = kept_settings.kept_before(self.repo)
        self.hook.write_text("#!/bin/sh\necho updated\n", encoding="utf-8")
        self.assertTrue(kept_settings.keep_after_a_governed_change(self.repo, before))
        self.assertTrue(self.kept())

    def test_a_change_made_before_the_update_is_not_kept(self):
        self.trust("y\n")
        self.hook.write_text("#!/bin/sh\necho planted\n", encoding="utf-8")
        before = kept_settings.kept_before(self.repo)
        self.assertIsNone(before)
        self.assertFalse(kept_settings.keep_after_a_governed_change(self.repo, before))
        self.assertFalse(self.kept())


if __name__ == "__main__":
    unittest.main()
