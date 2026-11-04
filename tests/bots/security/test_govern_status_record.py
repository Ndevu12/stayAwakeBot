#!/usr/bin/env python3
"""`saw govern` writes a durable per-folder record an editor reads: checking, held, applied, or
finished, with the verdict. It is keyed the way the editor keys it and outlives the holding dir."""
from __future__ import annotations

import hashlib
import os
import shutil
import tempfile

from stayawake.bots.security import govern, govern_status
from tests.support import samples
from tests.support.gitrepo import GitSandbox


class GovernStatusRecord(GitSandbox):
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

    def _govern(self):
        holding = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, holding, ignore_errors=True)
        govern.prepare(str(self.repo), holding, "git", ["checkout", "next"], None)
        return govern.apply(str(self.repo), holding)

    def test_the_key_matches_how_the_editor_keys_a_folder(self):
        key = govern_status.folder_key(str(self.repo))
        expected = hashlib.sha256(os.path.abspath(str(self.repo)).encode()).hexdigest()[:32]
        self.assertEqual(key, expected)
        self.assertEqual(len(key), 32)

    def test_a_clean_update_ends_applied_with_the_verdict(self):
        self.write(self.repo, "arrived.txt", "clean\n")
        self.commit(self.repo, "arrive")
        self.git(self.repo, "checkout", "-q", self._default())
        self._govern()
        rec = govern_status.read(str(self.repo))
        self.assertIsNotNone(rec)
        self.assertEqual(rec["phase"], "applied")
        self.assertEqual(rec["verdict"], "clean")
        self.assertEqual(rec["repo"], os.path.abspath(str(self.repo)))
        self.assertIsInstance(rec["at"], int)

    def test_an_infected_update_ends_held_with_the_verdict(self):
        self.write(self.repo, "loader.js", samples.loader_line())
        self.commit(self.repo, "worm")
        self.git(self.repo, "checkout", "-q", self._default())
        self._govern()
        rec = govern_status.read(str(self.repo))
        self.assertEqual(rec["phase"], "held")
        self.assertEqual(rec["verdict"], "infected")
        self.assertTrue(rec["reasons"])

    def test_the_record_outlives_the_holding_directory(self):
        self.write(self.repo, "arrived.txt", "clean\n")
        self.commit(self.repo, "arrive")
        self.git(self.repo, "checkout", "-q", self._default())
        holding = tempfile.mkdtemp()
        govern.prepare(str(self.repo), holding, "git", ["checkout", "next"], None)
        govern.apply(str(self.repo), holding)
        shutil.rmtree(holding, ignore_errors=True)  # system mode deletes its holding
        self.assertEqual(govern_status.read(str(self.repo))["phase"], "applied")


if __name__ == "__main__":
    import unittest
    unittest.main()
