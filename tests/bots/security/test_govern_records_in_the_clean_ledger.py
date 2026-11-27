#!/usr/bin/env python3
"""`saw govern` records a clean update it let into the open folder in saw's clean ledger, so a change
that reached the working tree outside the check is the one the ledger does not know."""
from __future__ import annotations

import json
import os
import shutil
import tempfile
from pathlib import Path

from stayawake.bots.security import clean_ledger, govern
from tests.support import samples
from tests.support.gitrepo import GitSandbox


class _Ledger(GitSandbox):
    def setUp(self):
        super().setUp()
        cache = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, cache, ignore_errors=True)
        self._env = {k: os.environ.get(k) for k in ("XDG_CACHE_HOME", "XDG_CONFIG_HOME")}
        os.environ["XDG_CACHE_HOME"] = cache
        os.environ["XDG_CONFIG_HOME"] = cache
        self.repo = self.new_repo("open")
        self.write(self.repo, "keep.txt", "a\n")
        self.start = self.commit(self.repo, "start")
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
        clean_ledger.remember(self.repo, clean_ledger.clean_key(self.start, None))
        govern.prepare(str(self.repo), holding, "git", ["checkout", "next"], None)
        return govern.apply(str(self.repo), holding)

    def _head(self):
        return self.git(self.repo, "rev-parse", "HEAD").strip()

    def _has_main(self):
        return self.git(self.repo, "branch", "--list", "main").strip() != ""


class GovernLedger(_Ledger):

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

    def test_an_update_bringing_a_new_submodule_link_is_not_recorded_as_judged(self):
        self.git(self.repo, "update-index", "--add", "--cacheinfo", f"160000,{self.start},sub")
        self.git(self.repo, "commit", "-qm", "submodule link")
        linked = self._head()
        self.git(self.repo, "checkout", "-q", "main" if self._has_main() else "master")
        payload, _ = self._govern_checkout_next()
        self.assertTrue(payload.get("applied"), payload)
        self.assertEqual(self._head(), linked)
        self.assertFalse(clean_ledger.governed(self.repo, clean_ledger.clean_key(linked, None)))
        self.assertEqual(clean_ledger.let_in_commit(self.repo, None), self.start)

    def test_a_submodule_link_the_tree_saw_let_in_holds_is_judged(self):
        self.git(self.repo, "checkout", "-q", "main" if self._has_main() else "master")
        self.git(self.repo, "update-index", "--add", "--cacheinfo", f"160000,{self.start},sub")
        self.git(self.repo, "commit", "-qm", "submodule link")
        linked = self._head()
        clean_ledger.remember(self.repo, clean_ledger.clean_key(linked, None))
        self.git(self.repo, "checkout", "-q", "-b", "more")
        self.write(self.repo, "arrived.txt", "clean\n")
        self.git(self.repo, "add", "arrived.txt")
        self.git(self.repo, "commit", "-qm", "arrive")
        arrived = self._head()
        self.git(self.repo, "checkout", "-q", "main" if self._has_main() else "master")
        holding = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, holding, ignore_errors=True)
        govern.prepare(str(self.repo), holding, "git", ["checkout", "more"], None)
        self.assertTrue(govern.apply(str(self.repo), holding)[0].get("applied"))
        self.assertTrue(clean_ledger.governed(self.repo, clean_ledger.clean_key(arrived, None)))

    def test_an_ungoverned_checkout_is_not_in_the_ledger(self):
        self.write(self.repo, "arrived.txt", "clean\n")
        self.commit(self.repo, "arrive")
        # a plain checkout, no govern — the ledger must not know this HEAD
        key = clean_ledger.clean_key(self._head(), None)
        self.assertFalse(clean_ledger.scanned_clean(self.repo, key))


class ARecordInsideAGitRepositoryCountsAsEmpty(_Ledger):

    def _record_inside(self, *parts: str) -> Path:
        cache = self.repo.joinpath(*parts)
        os.environ["XDG_CACHE_HOME"] = str(cache)
        return cache / "saw"

    def test_contents_a_record_inside_a_working_tree_names_are_judged_again(self):
        self.write(self.repo, "loader.js", samples.loader_line())
        infected_commit = self.commit(self.repo, "worm")
        blob = self.git(self.repo, "rev-parse", "HEAD:loader.js").strip()
        self.git(self.repo, "checkout", "-q", "main" if self._has_main() else "master")
        record = self._record_inside("cache")
        record.mkdir(parents=True)
        root = os.path.realpath(self.repo)
        (record / "govern-let-in-blobs.json").write_text(json.dumps(
            {root: {"policy": clean_ledger.policy_digest(None), "blobs": [["loader.js", "100644", blob]]}}))
        (record / "govern-applied.json").write_text(json.dumps({root: clean_ledger.clean_key(infected_commit, None)}))
        self.assertEqual(clean_ledger.blobs_let_in(self.repo, None), set())
        self.assertIsNone(clean_ledger.let_in_commit(self.repo, None))
        self.assertFalse(clean_ledger.governed(self.repo, clean_ledger.clean_key(infected_commit, None)))
        holding = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, holding, ignore_errors=True)
        answer, _code = govern.prepare(str(self.repo), holding, "git", ["checkout", "next"], None)
        self.assertEqual(answer["scan"]["results"][0]["verdict"], "infected", answer)
        self.assertFalse(govern.apply(str(self.repo), holding)[0]["applied"])

    def test_nothing_is_written_to_a_record_inside_a_repository(self):
        key = clean_ledger.clean_key(self.start, None)
        for parts in (("cache",), (".git", "cache"), ("missing", "cache")):
            with self.subTest(parts=parts):
                record = self._record_inside(*parts)
                clean_ledger.remember(self.repo, key)
                clean_ledger.remember_applied(self.repo, key)
                clean_ledger.remember_accepted(self.repo, self.start, "infected")
                clean_ledger.remember_settings_scan(self.repo, key)
                clean_ledger.remember_blobs(self.repo, [["keep.txt", "100644", "0" * 40]],
                                            clean_ledger.policy_digest(None))
                self.assertFalse(record.exists())
                self.assertFalse(clean_ledger.governed(self.repo, key))


if __name__ == "__main__":
    import unittest
    unittest.main()
