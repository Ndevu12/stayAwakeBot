#!/usr/bin/env python3
"""The local branch your uncommitted work is saved on is committed under the name and email you set,
including the ones set for all your repositories, wherever git would refuse to guess one; with none set,
saw says how to set them, makes no branch, and never commits under a guessed identity."""
from __future__ import annotations

import os
import tempfile
from pathlib import Path
from unittest import mock

from stayawake.bots.security.remediation import preserve
from tests.support.gitrepo import GitSandbox


class _YourWork(GitSandbox):
    def setUp(self):
        super().setUp()
        self.operator = Path(tempfile.mkdtemp(prefix="saw-operator-")) / "gitconfig"
        self.operator.write_text("")
        patcher = mock.patch.dict(os.environ, {"GIT_CONFIG_GLOBAL": str(self.operator)})
        patcher.start()
        self.addCleanup(patcher.stop)
        self.repo = self.new_repo()
        self.write(self.repo, "kept.js", "module.exports = 1;\n")
        self.commit(self.repo, "a starting point")
        self.git(self.repo, "config", "--unset", "user.name")
        self.git(self.repo, "config", "--unset", "user.email")
        (self.repo / "notes.md").write_text("my own work\n")

    def _you_are(self, name: str, email: str):
        self.operator.write_text(f"[user]\n\tname = {name}\n\temail = {email}\n")

    def _saved(self) -> preserve.Preserved:
        return preserve.preserve(self.repo, preserve.uncommitted(self.repo))

    def _identities(self, branch: str) -> list[str]:
        return self.git(self.repo, "log", "-1", "--format=%an <%ae>|%cn <%ce>", branch).strip().split("|")

    def _saved_branches(self) -> str:
        return self.git(self.repo, "branch", "--list", f"{preserve.BRANCH_PREFIX}*").strip()


class TestYourWorkIsSavedAsYou(_YourWork):
    def test_your_name_and_email_for_every_repository_commit_it_where_git_will_not_guess_one(self):
        self._you_are("Ada Operator", "ada@example.com")
        self.git(self.repo, "config", "user.useConfigOnly", "true")
        done = self._saved()
        self.assertTrue(done.branch, done.reason)
        self.assertEqual(self._identities(done.branch), ["Ada Operator <ada@example.com>"] * 2)

    def test_the_repositorys_own_name_and_email_come_first(self):
        self._you_are("Ada Operator", "ada@example.com")
        self.git(self.repo, "config", "user.name", "Ada At Work")
        self.git(self.repo, "config", "user.email", "ada@work.example")
        done = self._saved()
        self.assertEqual(self._identities(done.branch), ["Ada At Work <ada@work.example>"] * 2)

    def test_a_name_and_email_in_the_environment_do_not_replace_yours(self):
        self._you_are("Ada Operator", "ada@example.com")
        replayed = {"GIT_AUTHOR_NAME": "Someone Else", "GIT_AUTHOR_EMAIL": "else@example.com",
                    "GIT_COMMITTER_NAME": "Someone Else", "GIT_COMMITTER_EMAIL": "else@example.com"}
        with mock.patch.dict(os.environ, replayed):
            done = self._saved()
        self.assertEqual(self._identities(done.branch), ["Ada Operator <ada@example.com>"] * 2)


class TestWithNoNameOrEmailSet(_YourWork):
    def test_it_says_how_to_set_them_and_makes_no_branch(self):
        self.git(self.repo, "config", "user.useConfigOnly", "true")
        done = self._saved()
        self.assertEqual(done.branch, "")
        self.assertTrue(done.blocked)
        self.assertIn('`git config --global user.name "Your Name"`', done.note())
        self.assertIn("`git config --global user.email you@example.com`", done.note())
        self.assertEqual(self._saved_branches(), "")

    def test_it_never_commits_under_a_guessed_identity(self):
        done = self._saved()
        self.assertEqual(done.branch, "")
        self.assertEqual(done.reason, preserve.NO_IDENTITY)
        self.assertEqual(self._saved_branches(), "")


if __name__ == "__main__":
    import unittest
    unittest.main()
