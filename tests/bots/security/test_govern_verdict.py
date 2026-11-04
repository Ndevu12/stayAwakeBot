#!/usr/bin/env python3
"""`saw govern verdict` answers, for one open folder, whether its current tree is one saw let in —
scanned clean by a hook or applied by govern (clean or residue, with the tree still matching) — or a
change that came in another way, or one saw could not answer."""
from __future__ import annotations

import os
import shutil
import tempfile

from stayawake.bots.security import clean_ledger, govern
from tests.support.gitrepo import GitSandbox


class GovernVerdict(GitSandbox):
    def setUp(self):
        super().setUp()
        cache = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, cache, ignore_errors=True)
        self._env = {k: os.environ.get(k) for k in ("XDG_CACHE_HOME", "XDG_CONFIG_HOME")}
        os.environ["XDG_CACHE_HOME"] = cache
        os.environ["XDG_CONFIG_HOME"] = cache
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

    def _payload(self):
        return govern.verdict(str(self.repo), None)[0]

    def _govern_checkout_next(self):
        holding = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, holding, ignore_errors=True)
        govern.prepare(str(self.repo), holding, "git", ["checkout", "next"], None)
        govern.apply(str(self.repo), holding)

    def test_a_clean_governed_update_is_let_in(self):
        self.write(self.repo, "arrived.txt", "clean\n")
        self.commit(self.repo, "arrive")
        self.git(self.repo, "checkout", "-q", self._default())
        self._govern_checkout_next()
        p = self._payload()
        self.assertEqual(p["code"], "let-in")
        self.assertEqual(p["governed"], "let-in")
        self.assertEqual(p["head"], p["let_in"])  # the tree in place is the commit saw let in

    def test_an_ungoverned_checkout_is_not_let_in(self):
        self.write(self.repo, "arrived.txt", "clean\n")
        self.commit(self.repo, "arrive")
        self.assertEqual(self._payload()["code"], "unknown-commit")

    def test_a_dirty_tree_on_a_governed_commit_is_not_let_in(self):
        self.write(self.repo, "arrived.txt", "clean\n")
        self.commit(self.repo, "arrive")
        self.git(self.repo, "checkout", "-q", self._default())
        self._govern_checkout_next()
        self.write(self.repo, "arrived.txt", "tampered\n")  # changed outside govern
        p = self._payload()
        self.assertEqual(p["code"], "tree-changed")
        self.assertTrue(p.get("let_in"), "the commit saw let in is named so the editor can put it back")

    def test_a_residue_apply_is_let_in_without_widening_the_hook_skip(self):
        head = self.git(self.repo, "rev-parse", "HEAD").strip()
        key = clean_ledger.clean_key(head, None)
        clean_ledger.remember_applied(self.repo, key)  # the residue path: applied, not scanned clean
        self.assertFalse(clean_ledger.scanned_clean(self.repo, key),
                         "residue must not be remembered as a strictly-clean scan")
        self.assertEqual(self._payload()["code"], "let-in")


if __name__ == "__main__":
    import unittest
    unittest.main()
