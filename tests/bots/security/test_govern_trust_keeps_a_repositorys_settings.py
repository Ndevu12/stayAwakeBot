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

    def test_any_other_answer_keeps_nothing_and_is_recorded_as_a_no(self):
        self.assertEqual(self.trust("\n"), exitcodes.DID_NOT_RUN)
        self.assertFalse(self.kept())
        self.assertTrue(kept_settings.is_declined(settings_fingerprint.fingerprint(self.repo)))

    def test_a_no_holds_only_for_the_settings_it_answered(self):
        self.trust("n\n")
        self.hook.write_text("#!/bin/sh\necho changed\n", encoding="utf-8")
        self.assertFalse(kept_settings.is_declined(settings_fingerprint.fingerprint(self.repo)))

    def test_keeping_them_later_replaces_the_no(self):
        self.trust("n\n")
        self.assertEqual(self.trust("y\n"), exitcodes.CLEAN)
        self.assertTrue(self.kept())
        self.assertFalse(kept_settings.is_declined(settings_fingerprint.fingerprint(self.repo)))

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


STANDIN = (Path(__file__).resolve().parents[3] / "src" / "stayawake" / "bots" / "mcp" / "session" / "target"
           / "release" / "saw-git-standin")


@unittest.skipUnless(os.name != "nt" and STANDIN.is_file(), "needs the git stand-in built from this checkout")
class AKeptRepositoryRunsItsOwnHookThroughTheStandIn(unittest.TestCase):
    def test_a_commit_after_saw_govern_trust_runs_the_hook_without_asking_saw(self):
        root = Path(os.path.realpath(tempfile.mkdtemp(prefix="saw-trust-end-")))
        self.addCleanup(shutil.rmtree, root, True)
        (root / ".gitconfig").write_text("[user]\n\tname = Operator\n\temail = operator@example.invalid\n",
                                         encoding="utf-8")
        environment = {key: value for key, value in os.environ.items()
                       if not key.startswith(("GIT_", "SAW_", "XDG_"))}
        environment.update({"HOME": str(root), "XDG_CACHE_HOME": str(root / "cache"),
                            "XDG_CONFIG_HOME": str(root / "config"), "XDG_STATE_HOME": str(root / "state")})
        patched = mock.patch.dict(os.environ, environment, clear=True)
        patched.start()
        self.addCleanup(patched.stop)
        repo, git = root / "repo", real_git()
        subprocess.run([git, "init", "-q", str(repo)], check=True, stdin=subprocess.DEVNULL)
        (repo / "notes.txt").write_text("one\n", encoding="utf-8")
        subprocess.run([git, "-C", str(repo), "add", "."], check=True, stdin=subprocess.DEVNULL)
        subprocess.run([git, "-C", str(repo), "commit", "-qm", "one"], check=True, stdin=subprocess.DEVNULL)
        hook = repo / ".git" / "hooks" / "pre-commit"
        hook.write_text(f"#!/bin/sh\necho hook >> '{root / 'hook.log'}'\n", encoding="utf-8")
        hook.chmod(0o755)
        saw = root / "fake-saw"
        saw.write_text(f"#!/bin/sh\necho \"$@\" >> '{root / 'saw.log'}'\n"
                       "printf '%s\\n' '{\"passthrough\":true}'\n", encoding="utf-8")
        saw.chmod(0o755)
        with mock.patch("sys.stdin", _Terminal("y\n")), mock.patch("sys.stderr", _Terminal()):
            self.assertEqual(govern_cli.run_trust(argparse.Namespace(repo=str(repo), forget=False)), exitcodes.CLEAN)
        (repo / "notes.txt").write_text("two\n", encoding="utf-8")
        done = subprocess.run([str(STANDIN), "commit", "-qam", "two"], cwd=repo, stdin=subprocess.DEVNULL,
                              capture_output=True, text=True,
                              env={**environment, "SAW_STANDIN_TOOL": "git", "SAW_REAL_GIT": git,
                                   "SAW_BIN": str(saw), "SAW_GOVERN_HOLDING": str(root / "holding")})
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertTrue((root / "hook.log").is_file(), "the kept pre-commit hook did not run")
        self.assertFalse((root / "saw.log").exists(), "saw was asked about a command in a kept repository")


if __name__ == "__main__":
    unittest.main()
