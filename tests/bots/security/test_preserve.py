#!/usr/bin/env python3
"""The operator's uncommitted work goes on a local branch before anything is removed."""
from __future__ import annotations

import unittest

import io
from contextlib import redirect_stderr, redirect_stdout

from stayawake.bots.security import remediator
from stayawake.bots.security.remediation import preserve
from tests.support.gitrepo import GitSandbox

LOADER = ("const _0x1a=['aHR0cHM6Ly9ldmlsLnRlc3Q='];\n"
          "(function(v){var f=String.fromCharCode;globalThis['v']=f(127);})(0);\n")


class TestTheBranchNeverCarriesThePayload(GitSandbox):
    """Check what the branch holds."""

    def setUp(self):
        super().setUp()
        self.repo = self.new_repo()
        self.write(self.repo, "app.js", "module.exports = 1;\n")
        self.commit(self.repo, "a starting point")
        (self.repo / "public" / "fonts").mkdir(parents=True)
        (self.repo / "public" / "fonts" / "text.woff").write_text(LOADER)   # uncommitted payload
        (self.repo / "notes.md").write_text("my own work\n")               # uncommitted, theirs

    def test_what_the_cleanup_removed_is_not_on_the_branch(self):
        theirs = preserve.uncommitted(self.repo)
        (self.repo / "public" / "fonts" / "text.woff").unlink()             # the cleanup removes it
        done = preserve.preserve(self.repo, theirs)
        listed = self.git(self.repo, "ls-tree", "-r", "--name-only", done.branch)
        self.assertNotIn("text.woff", listed)
        self.assertIn("notes.md", listed)

    def test_a_file_that_was_not_theirs_is_never_branched(self):
        theirs = preserve.uncommitted(self.repo)
        theirs = [p for p in theirs if "text.woff" not in p]                # never noted as theirs
        done = preserve.preserve(self.repo, theirs)
        listed = self.git(self.repo, "ls-tree", "-r", "--name-only", done.branch)
        self.assertNotIn("text.woff", listed)

    def test_nothing_of_theirs_left_means_no_branch(self):
        theirs = preserve.uncommitted(self.repo)
        (self.repo / "public" / "fonts" / "text.woff").unlink()
        (self.repo / "notes.md").unlink()
        self.assertEqual("", preserve.preserve(self.repo, theirs).branch)


class TestItPutsTheWorkAside(GitSandbox):
    def setUp(self):
        super().setUp()
        self.repo = self.new_repo()
        self.write(self.repo, "kept.js", "module.exports = 1;\n")
        self.head = self.commit(self.repo, "a starting point")

    def test_a_clean_tree_needs_no_branch(self):
        done = preserve.preserve(self.repo)
        self.assertEqual("", done.branch)
        self.assertEqual("", done.note())

    def test_an_uncommitted_edit_is_put_on_a_branch(self):
        self.write(self.repo, "kept.js", "module.exports = 2;\n")
        done = preserve.preserve(self.repo)
        self.assertTrue(done.branch.startswith(preserve.BRANCH_PREFIX))
        self.assertEqual(1, done.files)
        self.assertIn("never pushed", done.note())

    def test_an_untracked_file_is_put_on_the_branch(self):
        self.write(self.repo, "new.js", "console.log(1);\n")
        done = preserve.preserve(self.repo)
        listed = self.git(self.repo, "ls-tree", "-r", "--name-only", done.branch)
        self.assertIn("new.js", listed)

    def test_an_ignored_file_is_left_out(self):
        self.write(self.repo, ".gitignore", "secret.env\n")
        self.write(self.repo, "secret.env", "TOKEN=hunter2\n")
        done = preserve.preserve(self.repo)
        listed = self.git(self.repo, "ls-tree", "-r", "--name-only", done.branch)
        self.assertNotIn("secret.env", listed)
        self.assertIn(".gitignore", listed)


class TestItDoesNotDisturbTheOperator(GitSandbox):
    def setUp(self):
        super().setUp()
        self.repo = self.new_repo()
        self.write(self.repo, "kept.js", "module.exports = 1;\n")
        self.head = self.commit(self.repo, "a starting point")
        self.write(self.repo, "kept.js", "module.exports = 2;\n")
        self.write(self.repo, "new.js", "console.log(1);\n")

    def test_head_does_not_move(self):
        preserve.preserve(self.repo)
        self.assertEqual(self.head, self.rev(self.repo))

    def test_the_branch_they_are_on_does_not_change(self):
        before = self.git(self.repo, "rev-parse", "--abbrev-ref", "HEAD").strip()
        preserve.preserve(self.repo)
        self.assertEqual(before, self.git(self.repo, "rev-parse", "--abbrev-ref", "HEAD").strip())

    def test_the_files_are_left_exactly_as_they_were(self):
        preserve.preserve(self.repo)
        self.assertEqual("module.exports = 2;\n", (self.repo / "kept.js").read_text())
        self.assertEqual("console.log(1);\n", (self.repo / "new.js").read_text())

    def test_their_work_is_still_uncommitted_afterwards(self):
        preserve.preserve(self.repo)
        self.assertNotEqual([], preserve.uncommitted(self.repo))

    def test_the_index_is_not_staged_behind_them(self):
        preserve.preserve(self.repo)
        staged = self.git(self.repo, "diff", "--cached", "--name-only").strip()
        self.assertEqual("", staged)

    def test_the_branch_holds_the_work_even_so(self):
        done = preserve.preserve(self.repo)
        shown = self.git(self.repo, "show", f"{done.branch}:kept.js")
        self.assertEqual("module.exports = 2;\n", shown)


class TestTheRunActuallyPreservesFirst(GitSandbox):
    """Check what a run leaves behind."""

    def setUp(self):
        super().setUp()
        self.d = self.new_repo("project", user__name="Tester")
        (self.d / "public" / "fonts").mkdir(parents=True)
        (self.d / "public" / "fonts" / "text.woff").write_text(LOADER)
        self.commit(self.d, "project and payload")
        (self.d / "notes.txt").write_text("work in progress\n")     # uncommitted, untracked

    def _fix(self):
        with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            remediator.fix(None, paths=[str(self.d)], no_stream=True)

    def _preserved(self):
        refs = self.git(self.d, "for-each-ref", "--format=%(refname)", "refs/heads/saw/")
        return [r.strip() for r in refs.splitlines() if r.strip()]

    def test_a_run_leaves_their_work_on_a_branch(self):
        self._fix()
        self.assertTrue(self._preserved(), "no saw/uncommitted-* branch was created")

    def test_the_branch_holds_the_uncommitted_file(self):
        self._fix()
        branch = self._preserved()[0]
        listed = self.git(self.d, "ls-tree", "-r", "--name-only", branch)
        self.assertIn("notes.txt", listed)


if __name__ == "__main__":
    unittest.main()
