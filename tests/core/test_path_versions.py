#!/usr/bin/env python3
"""`path_versions` finds every version any ref's history wrote at a path."""
from __future__ import annotations

import unittest
from unittest import mock

from stayawake.lib import git as gitutil
from tests.support.gitrepo import GitSandbox


class TestPathVersions(GitSandbox):

    def setUp(self):
        super().setUp()
        self.d = self.new_repo("versions")
        self.base = None

    def blob(self, ref, path):
        return self.git(self.d, "rev-parse", f"{ref}:{path}").strip()

    def test_every_version_written_at_a_path_on_any_ref_is_found(self):
        self.write(self.d, "a.js", "one\n")
        first = self.commit(self.d, "one")
        self.write(self.d, "a.js", "two\n")
        self.commit(self.d, "two")
        self.git(self.d, "checkout", "-q", "-b", "side", first)
        self.write(self.d, "a.js", "three\n")
        self.commit(self.d, "three")
        self.git(self.d, "tag", "only-a-tag")
        self.git(self.d, "checkout", "-q", "-")
        self.git(self.d, "branch", "-D", "side")
        found = gitutil.path_versions(self.d, ["a.js", "b.js"])
        self.assertEqual({self.blob("HEAD~1", "a.js"), self.blob("HEAD", "a.js"),
                          self.blob("only-a-tag", "a.js")}, set(found["a.js"]))
        self.assertEqual({}, found["b.js"])

    def test_a_file_a_merge_created_is_found_whatever_the_merge_display_setting(self):
        self.write(self.d, "base.txt", "base\n")
        self.commit(self.d, "base")
        self.git(self.d, "checkout", "-q", "-b", "side")
        self.write(self.d, "side.txt", "side\n")
        self.commit(self.d, "side")
        self.git(self.d, "checkout", "-q", "-")
        self.git(self.d, "merge", "--no-commit", "--no-ff", "side")
        self.write(self.d, "v/new.js", "born at the merge\n")
        self.commit(self.d, "merge")
        for setting in ("combined", "dense-combined", "first-parent"):
            self.git(self.d, "config", "log.diffMerges", setting)
            found = gitutil.path_versions(self.d, ["v/new.js"])
            self.assertEqual({self.blob("HEAD", "v/new.js")}, set(found["v/new.js"]), setting)

    def test_output_it_cannot_read_is_named_not_guessed(self):
        self.write(self.d, "a.js", "one\n")
        self.commit(self.d, "one")
        odd = b"1" * 40 + b"\n::100644 100644 100644 " + b"0" * 40 + b" " + b"2" * 40 + b" " + \
            b"3" * 40 + b" AM\0a.js\0"
        from stayawake.lib.git import query
        with mock.patch.object(query, "own_view_fed", return_value=odd):
            with self.assertRaises(gitutil.Unread):
                gitutil.path_versions(self.d, ["a.js"])

    def test_a_version_only_an_older_stash_entry_holds_is_found(self):
        self.write(self.d, "a.js", "one\n")
        self.commit(self.d, "one")
        self.write(self.d, "a.js", "older stash\n")
        self.git(self.d, "stash", "push", "-q", "-m", "older")
        self.write(self.d, "a.js", "newer stash\n")
        self.git(self.d, "stash", "push", "-q", "-m", "newer")
        older = self.git(self.d, "rev-parse", "stash@{1}:a.js").strip()
        self.assertIn(older, gitutil.path_versions(self.d, ["a.js"])["a.js"])

    def test_a_history_past_the_bound_is_not_listed(self):
        self.write(self.d, "a.js", "one\n")
        self.commit(self.d, "one")
        self.write(self.d, "a.js", "two\n")
        self.commit(self.d, "two")
        self.assertIsNone(gitutil.path_versions(self.d, ["a.js"], limit=1))


if __name__ == "__main__":
    unittest.main()
