#!/usr/bin/env python3
"""saw reads the options of a command it checks the way the git under test reads them: every option
git takes a value for is one saw skips the value of, and the hooks folder compares by its
filesystem's own rules."""
from __future__ import annotations

import subprocess
import unittest

from stayawake.lib.git import incoming, query
from tests.support.gitrepo import GitSandbox


class TheOptionsGitTakesAValueFor(GitSandbox):

    def test_every_one_the_git_under_test_lists_is_known(self):
        repo = self.new_repo()
        for sub, known in incoming._OPTIONS_TAKING_THE_NEXT_WORD.items():
            listed = subprocess.run(["git", "-C", str(repo), sub, "--git-completion-helper-all"],
                                    capture_output=True, text=True, stdin=subprocess.DEVNULL).stdout.split()
            taking = {word[:-1] for word in listed if word.endswith("=")}
            with self.subTest(sub=sub):
                self.assertTrue(listed, f"git {sub} listed no options")
                self.assertEqual(set(), taking - known)


class TheHooksFolderComparesByItsFilesystem(GitSandbox):

    def test_case_counts_only_where_the_filesystem_folds_it(self):
        repo = self.new_repo()
        self.git(repo, "config", "core.hooksPath", ".githooks")
        (repo / ".githooks").mkdir()
        changed = (".GitHooks/pre-commit", "src/app.js")
        self.assertEqual(query.hook_files(repo, changed, folds_case=lambda _folder: True), (".GitHooks/pre-commit",))
        self.assertEqual(query.hook_files(repo, changed, folds_case=lambda _folder: False), ())
        self.assertEqual(query.hook_files(repo, (".githooks/pre-commit",), folds_case=lambda _folder: False),
                         (".githooks/pre-commit",))


if __name__ == "__main__":
    unittest.main()
