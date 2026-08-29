#!/usr/bin/env python3
"""`saw fix amend` force-updates branches that still carry the payload; it does not run on heuristic-only or `--pr`."""
from __future__ import annotations

import io
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock
from contextlib import redirect_stderr

from stayawake import cli
from stayawake.bots.security.pr.amend import amend_repo
from stayawake.bots.security.targets import ScanOptions
from stayawake.lib.git.write.push import PushResult
from tests.bots.security.test_evil_merge import EVIL_SIG, _git


def _sigs():
    by: dict[str, list] = {}
    for s in EVIL_SIG:
        by.setdefault(s["matcher"], []).append(s)
    return by


def _ok_push(branch, dest, lease):
    return PushResult(True)


class TestFixAmendCli(unittest.TestCase):
    @mock.patch("stayawake.bots.security.remediator.amend", return_value=0)
    def test_amend_routes_and_strips_the_word(self, m):
        rc = cli.main(["fix", "amend", "."])
        self.assertEqual(rc, 0)
        m.assert_called_once()
        self.assertEqual(m.call_args.kwargs["paths"], ["."])
        self.assertFalse(m.call_args.kwargs["remote"])

    @mock.patch("stayawake.bots.security.remediator.amend", return_value=0)
    def test_amend_remote_routes(self, m):
        rc = cli.main(["fix", "amend", "--remote"])
        self.assertEqual(rc, 0)
        self.assertTrue(m.call_args.kwargs["remote"])

    @mock.patch("stayawake.bots.security.remediator.amend")
    def test_amend_refuses_a_pull_request(self, m):
        with redirect_stderr(io.StringIO()) as err:
            rc = cli.main(["fix", "amend", "--pr"])
        self.assertEqual(rc, 2)
        m.assert_not_called()
        self.assertIn("does not open a pull request", err.getvalue())


class TestFixAmendRepo(unittest.TestCase):
    def setUp(self):
        self.d = Path(tempfile.mkdtemp(prefix="amend-"))
        _git(self.d, "init", "-q")
        _git(self.d, "config", "user.email", "t@t.test")
        _git(self.d, "config", "user.name", "Tester")
        (self.d / "a.txt").write_text("base\n")
        _git(self.d, "add", ".")
        _git(self.d, "commit", "-qm", "init")
        self.base = subprocess.run(
            ["git", "-C", str(self.d), "rev-parse", "--abbrev-ref", "HEAD"],
            capture_output=True, text=True, check=True).stdout.strip()
        _git(self.d, "checkout", "-qb", "feature")
        (self.d / "b.txt").write_text("feature\n")
        _git(self.d, "add", ".")
        _git(self.d, "commit", "-qm", "feature work")
        _git(self.d, "checkout", "-q", self.base)

    def tearDown(self):
        shutil.rmtree(self.d, ignore_errors=True)

    def _rev(self, ref="HEAD"):
        return subprocess.run(
            ["git", "-C", str(self.d), "rev-parse", ref],
            capture_output=True, text=True, check=True).stdout.strip()

    def _loader_merge(self):
        (self.d / "x.js").write_text("var ok = 1;\n")
        _git(self.d, "add", "x.js")
        _git(self.d, "commit", "-qm", "add x.js")
        _git(self.d, "merge", "--no-ff", "--no-commit", "feature")
        (self.d / "x.js").write_text("var ok = 1;\neval(String.fromCharCode(1, 2, 3));\n")
        _git(self.d, "add", "x.js")
        _git(self.d, "commit", "-qm", "merge (smuggled loader)")

    def _amend(self, pusher=_ok_push, **kw):
        with mock.patch("stayawake.bots.security.pr.amend.gitutil.origin_slug",
                        return_value="acme/app"):
            return amend_repo(self.d, ScanOptions(), _sigs(), [], token="t",
                              pusher=pusher, **kw)

    def test_no_remote_is_not_a_fix(self):
        self._loader_merge()
        before = self._rev()
        line = amend_repo(self.d, ScanOptions(), _sigs(), [])
        self.assertIn("nothing was force-updated", line)
        self.assertEqual(before, self._rev())

    def test_force_updates_the_branch_that_carries_the_commit(self):
        self._loader_merge()
        merge = self._rev()
        calls = []

        def pusher(branch, dest, lease):
            calls.append((branch, dest, lease))
            return PushResult(True)

        line = self._amend(pusher=pusher)
        self.assertTrue(calls)
        self.assertEqual(calls[0][0], calls[0][1])
        self.assertIn("force-updated", line)
        self.assertNotIn("was not force-updated", line)
        self.assertNotEqual(self._rev(), merge)
        text = subprocess.run(
            ["git", "-C", str(self.d), "show", "HEAD:x.js"],
            capture_output=True, text=True, check=True).stdout
        self.assertNotIn("fromCharCode", text)
        self.assertTrue((self.d / ".git" / "saw-amend" / merge[:12] / "capture.json").is_file())

    def test_replays_a_later_commit(self):
        self._loader_merge()
        merge = self._rev()
        (self.d / "later.txt").write_text("ok\n")
        _git(self.d, "add", "later.txt")
        _git(self.d, "commit", "-qm", "later work")
        line = self._amend()
        self.assertIn("force-updated", line)
        text = subprocess.run(
            ["git", "-C", str(self.d), "show", "HEAD:x.js"],
            capture_output=True, text=True, check=True).stdout
        self.assertNotIn("fromCharCode", text)
        self.assertTrue((self.d / "later.txt").exists())
        self.assertNotEqual(self._rev(), merge)

    def test_force_updates_every_branch_that_carries_the_commit(self):
        self._loader_merge()
        merge = self._rev()
        _git(self.d, "branch", "also")
        calls = []

        def pusher(branch, dest, lease):
            calls.append(branch)
            return PushResult(True)

        line = self._amend(pusher=pusher)
        self.assertIn("force-updated", line)
        self.assertEqual(set(calls), {self.base, "also"})
        self.assertEqual(self._rev(), self._rev("also"))
        self.assertNotEqual(self._rev("also"), merge)

    def test_a_failed_push_is_not_a_fix(self):
        self._loader_merge()
        line = self._amend(pusher=lambda *_a: PushResult(False, "denied"))
        self.assertIn("was not force-updated", line)
        self.assertNotIn("force-updated '", line)

    def test_heuristic_only_is_not_replaced(self):
        _git(self.d, "merge", "--no-ff", "--no-commit", "feature")
        (self.d / "evil.txt").write_text("injected only in the merge\n")
        _git(self.d, "add", "evil.txt")
        _git(self.d, "commit", "-qm", "merge with new file")
        before = self._rev()
        line = self._amend()
        self.assertIn("no confirmed payload in past commits to replace", line)
        self.assertEqual(before, self._rev())

    def test_dirty_tree_is_refused(self):
        self._loader_merge()
        (self.d / "dirty.txt").write_text("nope\n")
        before = self._rev()
        line = self._amend()
        self.assertIn("working tree is not clean", line)
        self.assertEqual(before, self._rev())


if __name__ == "__main__":
    unittest.main()
