#!/usr/bin/env python3
"""`saw fix amend` takes everything an evil merge brought out of history, and holds the run back only
for copies of what is confirmed malicious."""
from __future__ import annotations

import unittest
from unittest import mock

from stayawake.bots.security.pr import amend as amendmod
from stayawake.bots.security.pr.amend import amend_outcome
from stayawake.bots.security.pr.outcome import Cause
from stayawake.bots.security.scanner import scan_target
from stayawake.bots.security.signatures import load_signatures
from stayawake.bots.security.targets import LocalRepoTarget, ScanOptions
from stayawake.lib import git as gitutil
from stayawake.lib.git.write.push import PushResult
from tests.bots.security.test_amend import _AmendFixture

LOADER = "global['_V']=function(x){return x};require('child_process').exec('id');\n"
STAGE2 = "global['_V']=function(x){return x};require('child_process').exec('whoami');\n"


class _EvilMerge(_AmendFixture):

    def setUp(self):
        super().setUp()
        self.base = self.git(self.d, "rev-parse", "--abbrev-ref", "HEAD").strip()

    def branch_with(self, name, path, text):
        self.git(self.d, "checkout", "-q", "-b", name)
        self.write(self.d, path, text)
        self.commit(self.d, f"{name} adds {path}")
        self.git(self.d, "checkout", "-q", self.base)

    def evil_merge(self, extra):
        self.write(self.d, "docs/guide.md", "# guide\n")
        self.commit(self.d, "add docs")
        self.git(self.d, "merge", "--no-commit", "--no-ff", "feature")
        self.write(self.d, "vendor/x/loader.js", LOADER)
        for path, text in extra.items():
            self.write(self.d, path, text)
        return self.commit(self.d, "Merge pull request #7 from feature")

    def run_amend(self):
        scan = scan_target(LocalRepoTarget(self.d, str(self.d), ScanOptions()), load_signatures())
        with self._remote(), \
                mock.patch("stayawake.bots.security.pr.amend.scan_target", return_value=scan):
            return amend_outcome(self.d, "acme/app", ScanOptions(), load_signatures(), [], "t",
                                 pusher=lambda *a: PushResult(True), resolver=None)

    def holds(self, ref, path):
        return self.git_may_fail(self.d, "cat-file", "-e", f"{ref}:{path}").returncode == 0


class TestGenuineFilesBesideThePayload(_EvilMerge):

    def test_an_empty_file_beside_the_payload_does_not_hold_the_run_back(self):
        self.write(self.d, "src/__init__.py", "")
        self.commit(self.d, "an empty module")
        self.evil_merge({"vendor/x/.keep": ""})
        outcome = self.run_amend()
        self.assertTrue(outcome.completed, self._causes(outcome))
        self.assertFalse(self.holds(self.base, "vendor/x/loader.js"))
        self.assertFalse(self.holds(self.base, "vendor/x/.keep"))
        self.assertNotIn(Cause.ARRIVED_COPIES_REMAIN, self._causes(outcome))

    def test_a_genuine_file_whose_copy_is_on_another_branch_goes_and_the_copy_stays(self):
        self.branch_with("other", "LICENSE.txt", "MIT\n")
        self.evil_merge({"vendor/x/LICENSE": "MIT\n"})
        outcome = self.run_amend()
        self.assertTrue(outcome.completed, self._causes(outcome))
        self.assertFalse(self.holds(self.base, "vendor/x/LICENSE"))
        self.assertTrue(self.holds("other", "LICENSE.txt"))
        self.assertIn(Cause.ARRIVED_COPIES_REMAIN, self._causes(outcome))
        self.assertTrue(outcome.needs_review)


class TestConfirmedCopiesStillHoldTheRunBack(_EvilMerge):

    def test_a_confirmed_file_deleted_later_with_a_copy_elsewhere_is_still_reachable(self):
        self.branch_with("other", "tools/stage2.js", STAGE2)
        self.evil_merge({"vendor/x/stage2.js": STAGE2})
        self.git(self.d, "rm", "-q", "vendor/x/stage2.js")
        self.commit(self.d, "tidy")
        outcome = self.run_amend()
        self.assertFalse(outcome.completed)
        self.assertIn(Cause.PAYLOAD_STILL_REACHABLE, self._causes(outcome))

    def test_history_too_long_to_walk_is_named_for_review(self):
        self.evil_merge({})
        with mock.patch.object(amendmod.gitutil, "path_versions", return_value=None):
            outcome = self.run_amend()
        self.assertIn(Cause.REMOVAL_NOT_CONFIRMED, self._causes(outcome))
        self.assertTrue(outcome.needs_review)
        self.assertFalse(self.holds(self.base, "vendor/x/loader.js"))

    def test_history_git_cannot_walk_is_named_and_the_merge_versions_count(self):
        self.branch_with("other", "LICENSE.txt", "MIT\n")
        self.evil_merge({"vendor/x/LICENSE": "MIT\n"})
        with mock.patch.object(amendmod.gitutil, "path_versions",
                               side_effect=gitutil.Unread("every copy of vendor/x/LICENSE")):
            outcome = self.run_amend()
        self.assertFalse(outcome.completed)
        self.assertIn(Cause.PAYLOAD_STILL_REACHABLE, self._causes(outcome))


if __name__ == "__main__":
    unittest.main()
