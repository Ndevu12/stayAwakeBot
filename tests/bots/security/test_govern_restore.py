#!/usr/bin/env python3
"""`saw govern restore` puts the open folder back on the commit saw let in, keeping uncommitted work
and leaving HEAD attached — so an editor need not run git over a dirty tree."""
from __future__ import annotations

import os
import shutil
import tempfile

from stayawake.bots.security import govern
from tests.support.gitrepo import GitSandbox


class GovernRestore(GitSandbox):
    def setUp(self):
        super().setUp()
        base = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, base, ignore_errors=True)
        self._env = {k: os.environ.get(k) for k in ("XDG_CACHE_HOME", "XDG_CONFIG_HOME", "XDG_STATE_HOME")}
        for k in ("XDG_CACHE_HOME", "XDG_CONFIG_HOME", "XDG_STATE_HOME"):
            os.environ[k] = base
        self.repo = self.new_repo("open")
        self.write(self.repo, "keep.txt", "a\n")
        self.commit(self.repo, "start")
        self.git(self.repo, "checkout", "-q", "-b", "next")

    def tearDown(self):
        for k, v in self._env.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
        super().tearDown()

    def _default(self):
        return "main" if self.git(self.repo, "branch", "--list", "main").strip() else "master"

    def _rev(self):
        return self.git(self.repo, "rev-parse", "HEAD").strip()

    def test_restore_puts_the_branch_back_keeping_uncommitted_and_head_attached(self):
        # saw lets in next@C1
        self.write(self.repo, "arrived.txt", "clean\n")
        self.commit(self.repo, "arrive")
        c1 = self._rev()
        self.git(self.repo, "checkout", "-q", self._default())
        holding = tempfile.mkdtemp(); self.addCleanup(shutil.rmtree, holding, ignore_errors=True)
        govern.prepare(str(self.repo), holding, "git", ["checkout", "next"], None)
        govern.apply(str(self.repo), holding)
        self.assertEqual(self._rev(), c1)
        # an ungoverned commit on next, then the operator's own uncommitted work
        self.write(self.repo, "evil.txt", "x\n")
        self.commit(self.repo, "ungoverned")
        self.assertNotEqual(self._rev(), c1)
        self.write(self.repo, "scratch.txt", "my unsaved work\n")  # untracked, operator's
        v = govern.verdict(str(self.repo), None)[0]
        self.assertEqual(v["code"], "unknown-commit")
        self.assertEqual(v["let_in"], c1)
        # put it back
        payload, _ = govern.restore(str(self.repo), None)
        self.assertTrue(payload["restored"])
        self.assertEqual(payload["commit"], c1)
        self.assertEqual(self._rev(), c1, "the branch is back on the commit saw let in")
        self.assertEqual(self.git(self.repo, "symbolic-ref", "HEAD").strip(), "refs/heads/next",
                         "HEAD stays attached, not detached")
        self.assertTrue((self.repo / "scratch.txt").exists(), "uncommitted work is kept")
        self.assertFalse((self.repo / "evil.txt").exists(), "the ungoverned commit is undone")

    def test_restore_with_nothing_let_in_says_so(self):
        payload, _ = govern.restore(str(self.repo), None)
        self.assertFalse(payload["restored"])
        self.assertIn("nothing to put back", payload["reason"])


if __name__ == "__main__":
    import unittest
    unittest.main()
