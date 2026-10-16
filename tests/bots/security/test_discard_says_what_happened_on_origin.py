#!/usr/bin/env python3
"""`saw discard --branch` says what happened to origin's copy: a branch that was never pushed is said to be so, one on
origin is deleted there, origin it could not check is named as unchecked, and only a delete that fails reads FAILED."""
from __future__ import annotations

import subprocess
import unittest
from unittest import mock

from stayawake.bots.security.pr import discard as discardmod
from stayawake.bots.security.pr.constants import FIX_BRANCH
from stayawake.lib import git as gitutil
from tests.support.gitrepo import GitSandbox
from tests.support.local_remotes import allow_local_remotes

_FIX = f"{FIX_BRANCH}-main"


class _WithOrigin(GitSandbox):
    def clone_with_a_fix_branch(self, *, pushed: bool):
        origin = self.owned(self.root / "origin.git")
        subprocess.run(["git", "init", "-q", "--bare", "-b", "main", str(origin)], check=True, capture_output=True)
        work = self.new_repo("work")
        self.write(work, "a", "1\n")
        self.commit(work, "init")
        self.git(work, "remote", "add", "origin", str(origin))
        self.git(work, "push", "-q", "origin", "HEAD:main")
        self.git(work, "branch", _FIX)
        if pushed:
            self.git(work, "push", "-q", "origin", _FIX)
        return work


class TestOriginThatCanBeChecked(_WithOrigin):
    def setUp(self):
        super().setUp()
        allow_local_remotes(self)

    def test_a_branch_that_was_never_pushed_is_said_to_be_so(self):
        work = self.clone_with_a_fix_branch(pushed=False)
        out = discardmod.discard_branch(work)
        self.assertNotIn("FAILED", out)
        self.assertIn(f"discarded local {_FIX} (it was never pushed)", out)
        self.assertFalse(gitutil.ref_exists(work, f"refs/heads/{_FIX}"))

    def test_a_branch_on_origin_is_deleted_there(self):
        work = self.clone_with_a_fix_branch(pushed=True)
        out = discardmod.discard_branch(work)
        self.assertNotIn("FAILED", out)
        self.assertIn(f"remote {_FIX}", out)
        self.assertFalse(gitutil.remote_has_branch("origin", _FIX, repo=work))

    def test_a_delete_on_origin_that_fails_reads_failed(self):
        work = self.clone_with_a_fix_branch(pushed=True)
        with mock.patch.object(discardmod.gitutil, "delete_remote_branch", return_value=False):
            out = discardmod.discard_branch(work)
        self.assertIn(f"FAILED to delete remote {_FIX}", out)


class TestOriginThatCannotBeChecked(_WithOrigin):
    def test_it_is_named_as_unchecked_not_as_a_failure(self):
        work = self.clone_with_a_fix_branch(pushed=False)
        out = discardmod.discard_branch(work)
        self.assertNotIn("FAILED", out)
        self.assertIn(f"discarded local {_FIX}", out)
        self.assertIn("could not check origin for a copy", out)
        self.assertFalse(gitutil.ref_exists(work, f"refs/heads/{_FIX}"))

    def test_with_no_local_branch_it_still_says_it_could_not_check_origin(self):
        work = self.clone_with_a_fix_branch(pushed=False)
        self.git(work, "branch", "-D", _FIX)
        out = discardmod.discard_branch(work)
        self.assertNotIn("nothing to discard", out)
        self.assertIn("could not check origin for one", out)


if __name__ == "__main__":
    unittest.main()
