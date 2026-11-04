#!/usr/bin/env python3
"""`saw govern` records a clean update it let into the open folder in saw's clean ledger, so a change
that reached the working tree outside the check is the one the ledger does not know."""
from __future__ import annotations

import os
import shutil
import tempfile

from stayawake.bots.security import clean_ledger, govern
from tests.support import samples
from tests.support.gitrepo import GitSandbox


class GovernLedger(GitSandbox):
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

    def _govern_checkout_next(self):
        holding = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, holding, ignore_errors=True)
        govern.prepare(str(self.repo), holding, "git", ["checkout", "next"], None)
        return govern.apply(str(self.repo), holding)

    def _head(self):
        return self.git(self.repo, "rev-parse", "HEAD").strip()

    def test_a_clean_governed_update_is_remembered(self):
        self.write(self.repo, "arrived.txt", "clean\n")
        self.commit(self.repo, "arrive")
        self.git(self.repo, "checkout", "-q", "main" if self._has_main() else "master")
        payload, _ = self._govern_checkout_next()
        self.assertTrue(payload.get("applied"), payload)
        key = clean_ledger.clean_key(self._head(), None)
        self.assertTrue(clean_ledger.scanned_clean(self.repo, key),
                        "a clean governed update should be in the ledger")

    def test_an_infected_update_is_not_remembered(self):
        self.write(self.repo, "loader.js", samples.loader_line())
        self.commit(self.repo, "worm")
        infected_commit = self._head()
        self.git(self.repo, "checkout", "-q", "main" if self._has_main() else "master")
        self._govern_checkout_next()  # held, not applied
        key = clean_ledger.clean_key(infected_commit, None)
        self.assertFalse(clean_ledger.scanned_clean(self.repo, key),
                         "an infected update must never be recorded clean")

    def test_an_ungoverned_checkout_is_not_in_the_ledger(self):
        self.write(self.repo, "arrived.txt", "clean\n")
        self.commit(self.repo, "arrive")
        # a plain checkout, no govern — the ledger must not know this HEAD
        key = clean_ledger.clean_key(self._head(), None)
        self.assertFalse(clean_ledger.scanned_clean(self.repo, key))

    def _has_main(self):
        return self.git(self.repo, "branch", "--list", "main").strip() != ""


if __name__ == "__main__":
    import unittest
    unittest.main()
