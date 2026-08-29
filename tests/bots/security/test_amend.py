#!/usr/bin/env python3
"""`saw fix amend` replaces a confirmed merge; it does not run on heuristic-only or `--pr`."""
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
from tests.bots.security.test_evil_merge import EVIL_SIG, _git


def _sigs():
    by: dict[str, list] = {}
    for s in EVIL_SIG:
        by.setdefault(s["matcher"], []).append(s)
    return by


class TestFixAmendCli(unittest.TestCase):
    @mock.patch("stayawake.bots.security.remediator.amend", return_value=0)
    def test_amend_routes_and_strips_the_word(self, m):
        rc = cli.main(["fix", "amend", "."])
        self.assertEqual(rc, 0)
        m.assert_called_once()
        self.assertEqual(m.call_args.kwargs["paths"], ["."])

    @mock.patch("stayawake.bots.security.remediator.amend")
    def test_amend_refuses_publish(self, m):
        with redirect_stderr(io.StringIO()) as err:
            rc = cli.main(["fix", "amend", "--pr"])
        self.assertEqual(rc, 2)
        m.assert_not_called()
        self.assertIn("does not publish", err.getvalue())


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

    def _loader_merge(self):
        (self.d / "x.js").write_text("var ok = 1;\n")
        _git(self.d, "add", "x.js")
        _git(self.d, "commit", "-qm", "add x.js")
        _git(self.d, "merge", "--no-ff", "--no-commit", "feature")
        (self.d / "x.js").write_text("var ok = 1;\neval(String.fromCharCode(1, 2, 3));\n")
        _git(self.d, "add", "x.js")
        _git(self.d, "commit", "-qm", "merge (smuggled loader)")

    def test_replaces_a_confirmed_merge_at_head(self):
        self._loader_merge()
        merge = subprocess.run(
            ["git", "-C", str(self.d), "rev-parse", "HEAD"],
            capture_output=True, text=True, check=True).stdout.strip()
        line = amend_repo(self.d, ScanOptions(), _sigs(), [])
        self.assertIn("replaced merge", line)
        self.assertIn(merge[:12], line)
        head = subprocess.run(
            ["git", "-C", str(self.d), "rev-parse", "HEAD"],
            capture_output=True, text=True, check=True).stdout.strip()
        self.assertNotEqual(head, merge)
        text = subprocess.run(
            ["git", "-C", str(self.d), "show", "HEAD:x.js"],
            capture_output=True, text=True, check=True).stdout
        self.assertNotIn("fromCharCode", text)
        self.assertTrue((self.d / ".git" / "saw-amend" / merge[:12] / "capture.json").is_file())

    def test_replays_a_later_commit(self):
        self._loader_merge()
        merge = subprocess.run(
            ["git", "-C", str(self.d), "rev-parse", "HEAD"],
            capture_output=True, text=True, check=True).stdout.strip()
        (self.d / "later.txt").write_text("ok\n")
        _git(self.d, "add", "later.txt")
        _git(self.d, "commit", "-qm", "later work")
        line = amend_repo(self.d, ScanOptions(), _sigs(), [])
        self.assertIn("replaced merge", line)
        self.assertIn("1 later commit", line)
        text = subprocess.run(
            ["git", "-C", str(self.d), "show", "HEAD:x.js"],
            capture_output=True, text=True, check=True).stdout
        self.assertNotIn("fromCharCode", text)
        self.assertTrue((self.d / "later.txt").exists())
        self.assertNotEqual(
            subprocess.run(["git", "-C", str(self.d), "rev-parse", "HEAD"],
                           capture_output=True, text=True, check=True).stdout.strip(),
            merge)

    def test_heuristic_only_is_not_replaced(self):
        _git(self.d, "merge", "--no-ff", "--no-commit", "feature")
        (self.d / "evil.txt").write_text("injected only in the merge\n")
        _git(self.d, "add", "evil.txt")
        _git(self.d, "commit", "-qm", "merge with new file")
        before = subprocess.run(
            ["git", "-C", str(self.d), "rev-parse", "HEAD"],
            capture_output=True, text=True, check=True).stdout.strip()
        line = amend_repo(self.d, ScanOptions(), _sigs(), [])
        self.assertIn("no confirmed merge to replace", line)
        after = subprocess.run(
            ["git", "-C", str(self.d), "rev-parse", "HEAD"],
            capture_output=True, text=True, check=True).stdout.strip()
        self.assertEqual(before, after)

    def test_dirty_tree_is_refused(self):
        self._loader_merge()
        (self.d / "dirty.txt").write_text("nope\n")
        before = subprocess.run(
            ["git", "-C", str(self.d), "rev-parse", "HEAD"],
            capture_output=True, text=True, check=True).stdout.strip()
        line = amend_repo(self.d, ScanOptions(), _sigs(), [])
        self.assertIn("working tree is not clean", line)
        after = subprocess.run(
            ["git", "-C", str(self.d), "rev-parse", "HEAD"],
            capture_output=True, text=True, check=True).stdout.strip()
        self.assertEqual(before, after)


if __name__ == "__main__":
    unittest.main()
