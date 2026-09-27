#!/usr/bin/env python3
"""A fix checkout lives in saw's own repository and leaves nothing registered in the operator's."""
from __future__ import annotations

import shutil
import unittest

from stayawake.lib.git.write.worktree import add_worktree, held_checkout, remove_worktree
from tests.support.gitrepo import GitSandbox


class TestAFixCheckoutRegistersNothing(GitSandbox):
    """The operator's `worktree list` is untouched."""

    def setUp(self):
        super().setUp()
        self.repo = self.new_repo("origin", user__name="Tester")
        self.write(self.repo, "a.txt", "base\n")
        self.base_sha = self.commit(self.repo, "init")
        self.base = self.git(self.repo, "rev-parse", "--abbrev-ref", "HEAD").strip()
        self.wt = self.owned(self.root / "wt")
        self.wt.mkdir()

    def _registrations(self):
        return self.git(self.repo, "worktree", "list").strip().splitlines()

    def test_the_checkout_is_not_a_worktree_of_the_repository(self):
        self.assertTrue(add_worktree(self.repo, self.wt, "fixbr", self.base))
        self.addCleanup(remove_worktree, self.repo, self.wt)
        self.assertEqual(1, len(self._registrations()))
        self.assertEqual("base\n", (self.wt / "a.txt").read_text())
        self.assertEqual(self.base_sha, self.rev(self.repo, "refs/heads/fixbr"))

    def test_a_second_checkout_on_the_same_branch_is_made_after_the_first_vanishes(self):
        self.assertTrue(add_worktree(self.repo, self.wt, "fixbr", self.base))
        shutil.rmtree(self.wt)
        self.wt.mkdir()
        self.assertTrue(add_worktree(self.repo, self.wt, "fixbr", self.base))
        self.addCleanup(remove_worktree, self.repo, self.wt)

    def test_removing_the_checkout_forgets_it(self):
        add_worktree(self.repo, self.wt, "fixbr", self.base)
        self.assertTrue(remove_worktree(self.repo, self.wt))
        self.assertIsNone(held_checkout(self.wt))
        self.assertEqual(1, len(self._registrations()))

    def test_a_branch_the_operator_has_checked_out_is_refused(self):
        self.assertFalse(add_worktree(self.repo, self.wt, self.base, self.base))


if __name__ == "__main__":
    unittest.main()
