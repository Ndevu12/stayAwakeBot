#!/usr/bin/env python3
"""What git could not read is reported as not read: by the scan's merge check, by the gate's setup
and by the recovery advice."""
from __future__ import annotations

import subprocess
import unittest
from types import SimpleNamespace
from unittest import mock

from stayawake.bots.security import remediation
from stayawake.bots.security.guard import detect as guard_detect, provision
from stayawake.bots.security.matchers.git_history import GitHistoryMatcher
from stayawake.lib import git as gitutil
from stayawake.lib.git import query
from stayawake.lib.git.merge import candidates, corroborate, detect as mergedetect
from tests.bots.security.test_evil_merge import EVIL_SIG
from tests.bots.security.test_recovery import CLEAN, SIG, _commit, _finding, _infected_newlines, _repo


class TestTheMergeCheck(unittest.TestCase):
    def setUp(self):
        self.d = _repo()
        _commit(self.d, "a.js", "one\n", "first")
        self.target = SimpleNamespace(repo_root=self.d, merge_scope=None, read_errors=[])

    def _scan(self):
        return GitHistoryMatcher().scan(self.target, EVIL_SIG)

    def test_merges_it_could_not_list_are_a_read_error(self):
        with mock.patch.object(gitutil, "merge_commits", return_value=None):
            self.assertEqual(self._scan(), [])
        self.assertEqual(self.target.read_errors, ["the merge commits could not be listed"])

    def test_a_merge_it_could_not_read_is_a_read_error(self):
        with mock.patch.object(gitutil, "merge_commits", return_value=["a" * 40]), \
                mock.patch.object(gitutil, "evil_merge_paths", side_effect=query.Unread("x.js")):
            self.assertEqual(self._scan(), [])
        self.assertEqual(self.target.read_errors, [f"merge {'a' * 12}: x.js could not be read"])

    def test_a_lookup_git_could_not_answer_is_not_an_answer(self):
        missing = "0" * 40
        with self.assertRaises(query.Unread):
            query.stores_path(self.d, missing, "a.js")
        with self.assertRaises(query.Unread):
            mergedetect.evil_merge_paths(self.d, missing)
        with self.assertRaises(query.Unread):
            corroborate.corroborated(self.d, "HEAD", "HEAD", "a.js", [missing])
        with mock.patch.object(candidates, "run", return_value=None):
            self.assertIsNone(candidates.merge_commits(self.d))
        with self.assertRaises(query.Unread):
            query.introduced_added_text(self.d, missing, "HEAD", "a.js")
        with self.assertRaises(query.Unread):
            query.changed_paths(self.d, missing, "HEAD")

    def test_a_baseline_it_could_not_read_is_not_an_answer(self):
        base = subprocess.run(["git", "-C", str(self.d), "rev-parse", "HEAD"], capture_output=True,
                              text=True, check=True).stdout.strip()
        _commit(self.d, "a.js", "one\ntwo\n", "second")
        later = subprocess.run(["git", "-C", str(self.d), "rev-parse", "HEAD"], capture_output=True,
                               text=True, check=True).stdout.strip()
        with mock.patch.object(corroborate, "file_text_at", return_value=None):
            with self.assertRaises(query.Unread):
                corroborate.corroborated(self.d, base, later, "a.js", [base],
                                         obfuscation_reason=lambda *a: None)


class TestASubmoduleIsNotFileContent(unittest.TestCase):
    def setUp(self):
        self.d = _repo()
        _commit(self.d, "a.js", "one\n", "first")
        head = subprocess.run(["git", "-C", str(self.d), "rev-parse", "HEAD"], capture_output=True,
                              text=True, check=True).stdout.strip()
        subprocess.run(["git", "-C", str(self.d), "update-index", "--add", "--cacheinfo",
                        f"160000,{head},vendor"], check=True)
        subprocess.run(["git", "-C", str(self.d), "-c", "user.email=t@t", "-c", "user.name=t",
                        "commit", "-qm", "submodule"], check=True)
        self.parent = subprocess.run(["git", "-C", str(self.d), "rev-parse", "HEAD"],
                                     capture_output=True, text=True, check=True).stdout.strip()

    def test_a_parent_holding_a_submodule_there_does_not_store_the_file(self):
        self.assertIs(query.stores_path(self.d, self.parent, "vendor"), False)
        self.assertIs(query.stores_path(self.d, self.parent, "vendor/x.js"), False)
        self.assertEqual(corroborate.corroborated(self.d, self.parent, self.parent, "vendor/x.js",
                                                  [self.parent]),
                         (True, "introduced file absent from every parent (review-evading)"))

    def test_recovery_passes_over_a_version_a_submodule_holds(self):
        with mock.patch.object(gitutil, "stores_path", return_value=False), \
                mock.patch.object(gitutil, "file_text_at") as read:
            remediation.classify_recovery(self.d, _finding("vendor"), SIG)
        read.assert_not_called()


class TestTheScanReadsWhatAnyRefNames(unittest.TestCase):
    def test_file_content_a_ref_names_directly_is_read(self):
        d = _repo()
        _commit(d, "a.js", "one\n", "first")
        blob = subprocess.run(["git", "-C", str(d), "hash-object", "-w", "--stdin"], input=b"held\n",
                              capture_output=True, check=True).stdout.decode().strip()
        subprocess.run(["git", "-C", str(d), "update-ref", "refs/tags/content", blob], check=True)
        entries, complete = query.stored_entries(d)
        self.assertTrue(complete)
        self.assertIn((blob, query._FILE_TYPE), entries["/refs/tags/content"])


class TestTheGateSetup(unittest.TestCase):
    def setUp(self):
        self.d = _repo()
        _commit(self.d, ".github/workflows/ci.yml", "on: push\n", "ci")

    def test_workflows_it_could_not_read_stop_the_setup(self):
        with mock.patch.object(gitutil, "list_tree", return_value=None):
            with self.assertRaises(query.Unread):
                guard_detect._ref_workflows(self.d, "HEAD")
        with mock.patch.object(gitutil, "file_text_at", return_value=None):
            with self.assertRaises(query.Unread):
                guard_detect._ref_workflows(self.d, "HEAD")
            with self.assertRaises(query.Unread):
                guard_detect._ref_action_reader(self.d, "HEAD")("./action")

    def test_a_root_action_is_read_and_a_path_outside_is_not_an_action(self):
        _commit(self.d, "action.yml", "name: root\n", "action")
        reader = guard_detect._ref_action_reader(self.d, "HEAD")
        self.assertEqual(reader("./"), "name: root\n")
        self.assertIsNone(reader("./../elsewhere"))

    def test_the_setup_says_what_it_could_not_read(self):
        with mock.patch.object(provision, "_ref_workflows", side_effect=query.Unread("the workflows on main")), \
                mock.patch.object(provision.gitutil, "fetch"), \
                mock.patch.object(provision.gitutil, "ref_exists", return_value=False):
            result = provision.setup(self.d, pr=True, branch="main", pin=provision.Pin("a" * 40),
                                     scanner="v1.0.0")
        self.assertIn("couldn't read the workflows on main", result.error)
        self.assertIsNone(result.plan)


class TestTheRecoveryAdvice(unittest.TestCase):
    def test_a_history_it_could_not_read_is_left_for_inspection(self):
        d = _repo()
        _commit(d, "postcss.config.mjs", CLEAN, "add config")
        _commit(d, "postcss.config.mjs", _infected_newlines(), "feat: landing page")
        for patch in (mock.patch.object(gitutil, "file_text_at", return_value=None),
                      mock.patch.object(gitutil, "file_commits", return_value=None)):
            with self.subTest(patch=patch.attribute), patch:
                disp = remediation.classify_recovery(d, _finding("postcss.config.mjs"), SIG)
            self.assertIsInstance(disp, remediation.Manual)
            self.assertIn("Could not read this file's git history", disp.action)


if __name__ == "__main__":
    unittest.main()
