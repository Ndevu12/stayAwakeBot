#!/usr/bin/env python3
"""Creating a worktree on a branch a removed worktree was registered on."""
from __future__ import annotations

import subprocess
import unittest

from stayawake.lib.git.write.worktree import add_worktree, remove_worktree
from tests.support.gitrepo import GitSandbox


class TestABranchIsFreedWhenItsWorktreeIsGone(GitSandbox):
    """Check that a stale registration does not block the next worktree."""

    def setUp(self):
        super().setUp()
        self.repo = self.new_repo("origin", user__name="Tester")
        self.write(self.repo, "a.txt", "base\n")
        self.commit(self.repo, "init")
        self.base = self.git(self.repo, "rev-parse", "--abbrev-ref", "HEAD").strip()
        self.wt = self.owned(self.root / "wt")

    def _registrations(self):
        return self.git(self.repo, "worktree", "list")

    def test_a_second_worktree_on_the_same_branch_is_created(self):
        self.assertTrue(add_worktree(self.repo, self.wt, "fixbr", self.base))
        import shutil
        shutil.rmtree(self.wt)
        self.assertIn("prunable", self._registrations())
        self.assertTrue(add_worktree(self.repo, self.wt, "fixbr", self.base))

    def test_git_refuses_it_without_the_drop(self):
        """Check what git answers without the drop."""
        self.assertTrue(add_worktree(self.repo, self.wt, "fixbr", self.base))
        import shutil
        shutil.rmtree(self.wt)
        raw = subprocess.run(["git", "-C", str(self.repo), "worktree", "add", "-f", "-B",
                              "fixbr", str(self.wt), self.base], capture_output=True, text=True)
        self.assertNotEqual(0, raw.returncode)
        self.assertIn("cannot force update the branch", raw.stderr)

    def test_removing_a_worktree_leaves_no_registration(self):
        add_worktree(self.repo, self.wt, "fixbr", self.base)
        remove_worktree(self.repo, self.wt)
        self.assertNotIn("prunable", self._registrations())
        self.assertTrue(add_worktree(self.repo, self.wt, "fixbr", self.base))


if __name__ == "__main__":
    unittest.main()
