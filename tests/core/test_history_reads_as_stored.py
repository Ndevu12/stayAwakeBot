#!/usr/bin/env python3
"""History is read as the repository stores it, and a lookup git could not answer is never an
answer."""
from __future__ import annotations

import os
import subprocess
import unittest
from unittest import mock

from stayawake.lib.git import contexts, query
from stayawake.lib.git.merge import detect as mergedetect
from stayawake.lib.git.write import amend as gitamend, rebuild, replace
from tests.support.gitrepo import GitSandbox


def _unanswered(real, treeish_failing):
    """An `entry_at` that git does not answer for one commit or tree."""
    def entry_at(repo, treeish, path):
        return (False, None) if treeish == treeish_failing else real(repo, treeish, path)
    return entry_at


class TestEntries(GitSandbox):
    def setUp(self):
        super().setUp()
        self.d = self.new_repo()
        self.write(self.d, "dir/a.js", "one\n")
        self.commit(self.d, "first")

    def test_a_deep_absent_path_is_answered_as_absent(self):
        self.assertEqual(query.entry_at(self.d, "HEAD", "a/" * 1100 + "f.js"), (True, None))

    def test_a_path_is_matched_exactly(self):
        self.assertEqual(query.entry_at(self.d, "HEAD", "dir/")[1], None)
        self.assertEqual(query.entry_at(self.d, "HEAD", "dir")[1][0], query.TREE_MODE)
        self.assertEqual(query.file_text_at(self.d, "HEAD", "dir"), ("", ""))
        self.assertEqual(query.file_text_at(self.d, "HEAD", "dir/a.js")[1], "one\n")

    def test_a_path_a_submodule_holds_is_not_read_as_absent(self):
        sub = self.new_repo("sub")
        self.write(sub, "x.js", "x\n")
        self.commit(sub, "sub")
        self.git(self.d, "-c", "protocol.file.allow=always", "submodule", "add", "-q", str(sub), "lib/sub")
        self.commit(self.d, "add the submodule")
        answered, entry = query.entry_at(self.d, "HEAD", "lib/sub/x.js")
        self.assertTrue(answered)
        self.assertEqual(entry[0], query.GITLINK_MODE)
        self.assertIsNone(query.file_text_at(self.d, "HEAD", "lib/sub/x.js"))

    def test_a_replaced_object_is_read_as_stored(self):
        stored = self.rev(self.d)
        self.write(self.d, "dir/a.js", "decoy\n")
        decoy = self.commit(self.d, "decoy")
        self.git(self.d, "replace", stored, decoy)
        self.assertEqual(query.file_text_at(self.d, stored, "dir/a.js")[1], "one\n")

    def test_a_replaced_ancestry_is_read_as_stored(self):
        first = self.rev(self.d)
        self.write(self.d, "dir/a.js", "two\n")
        second = self.commit(self.d, "second")
        orphan = self.git(self.d, "commit-tree", f"{second}^{{tree}}", "-m", "no parent").strip()
        self.git(self.d, "replace", second, orphan)
        self.assertIs(query.ancestry(self.d, first, second), True)

    def test_a_lookup_git_could_not_answer_is_not_an_answer(self):
        missing = "0" * 40
        self.assertEqual(query.entry_at(self.d, missing, "dir/a.js"), (False, None))
        self.assertIsNone(query.file_text_at(self.d, missing, "dir/a.js"))
        self.assertIsNone(query.ancestry(self.d, missing, "HEAD"))
        self.assertIsNone(query.parents(self.d, missing))
        self.assertIsNone(query.branches_carrying(self.d, missing))
        self.assertIsNone(gitamend.discarded_delta(self.d, missing, missing))
        with self.assertRaises(query.Unread):
            mergedetect.born_at_merge(self.d, missing, ["dir/a.js"])
        self.assertIsNone(query.list_tree(self.d, missing, "dir"))
        with mock.patch.object(query, "own_view_fed", return_value=None):
            with self.assertRaises(query.Unread):
                query.blob_paths(self.d, "1" * 40)
        self.assertEqual(query.list_tree(self.d, "HEAD", "nowhere"), [])
        self.write(self.d, "dir/b.js", "two\n")
        head = self.commit(self.d, "second")
        with mock.patch.object(query, "_entries", return_value=None):
            with self.assertRaises(query.Unread):
                mergedetect.born_at_merge(self.d, head, ["dir/a.js"])


class TestARewriteFollowsWhatIsStored(GitSandbox):
    """A commit replaced by another object is rewritten from what the repository stores."""

    def setUp(self):
        super().setUp()
        self.d = self.new_repo()
        self.write(self.d, "file.js", "clean\n")
        self.clean = self.commit(self.d, "clean")
        self.write(self.d, "file.js", "payload\n")
        self.carrier = self.commit(self.d, "carrier")
        self.write(self.d, "file.js", "decoy\n")
        decoy_parent = self.commit(self.d, "decoy parent")
        swapped = subprocess.run(
            ["git", "-C", str(self.d), "commit-tree", f"{self.carrier}^{{tree}}", "-p", decoy_parent,
             "-m", "swapped"], capture_output=True, text=True, check=True,
            env={**os.environ, "GIT_AUTHOR_NAME": "Decoy", "GIT_AUTHOR_EMAIL": "decoy@example.com"},
        ).stdout.strip()
        self.git(self.d, "replace", self.carrier, swapped)

    def test_every_command_reads_the_stored_view(self):
        for context in (contexts.UNTRUSTED, contexts.SAW_OWNED, contexts.OPERATOR_CONFIG,
                        contexts.OPERATOR_PUSH):
            env = contexts.child_env(context, None)
            self.assertEqual(env["GIT_NO_REPLACE_OBJECTS"], "1")
            self.assertEqual(env["GIT_NO_LAZY_FETCH"], "1")
            self.assertFalse(os.path.exists(env["GIT_GRAFT_FILE"]))

    def test_a_restore_takes_the_parent_the_repository_stores(self):
        self.assertEqual(query.parents(self.d, self.carrier), [self.clean])
        got = replace.replacement_tree(self.d, self.carrier, ["file.js"])
        clean_blob = self.git(self.d, "rev-parse", f"{self.clean}:file.js").strip()
        self.assertEqual(dict(got.plan)["file.js"][1], clean_blob)

    def test_a_rewritten_commit_keeps_the_author_the_repository_stores(self):
        tree = self.git(self.d, "rev-parse", f"{self.clean}^{{tree}}").strip()
        sha, _kind, _refusal = gitamend.rewrite_commit(self.d, self.carrier, tree, [self.clean])
        author = self.git(self.d, "--no-replace-objects", "log", "-1", "--format=%an", sha).strip()
        self.assertNotEqual(author, "Decoy")


class TestHistoryWalk(GitSandbox):
    def setUp(self):
        super().setUp()
        self.d = self.new_repo()
        self.write(self.d, "a.js", "one\n")
        self.first = self.commit(self.d, "first")

    def test_a_branch_naming_no_commit_is_reported_and_never_empties_the_walk(self):
        (self.d / ".git" / "refs" / "heads" / "ghost").write_text("1" * 40 + "\n")
        self.assertEqual(query.unreadable_branch_refs(self.d), ["refs/heads/ghost"])
        self.assertIsNone(query.file_commits(self.d, "a.js", all_branches=True))
        with self.assertRaises(query.Unread):
            query.blob_paths(self.d, self.git(self.d, "rev-parse", "HEAD:a.js").strip())

    def test_a_walk_git_could_not_finish_is_not_an_empty_history(self):
        with mock.patch.object(query, "own_view", return_value=None):
            self.assertIsNone(query.file_commits(self.d, "a.js", all_branches=True))
        self.assertIsNone(rebuild.ordered_graph(self.d, ["0" * 40]))

    def test_a_clone_without_its_whole_history_is_told_apart(self):
        self.write(self.d, "a.js", "two\n")
        self.commit(self.d, "second")
        self.assertTrue(query.holds_its_history(self.d))
        shallow = self.owned(self.d.parent / "shallow")
        subprocess.run(["git", "-c", "protocol.file.allow=always", "clone", "-q", "--depth", "1",
                        f"file://{self.d}", str(shallow)], check=True)
        self.assertFalse(query.holds_its_history(shallow))


class TestNoReadReachesTheNetwork(GitSandbox):
    def test_only_a_push_may_use_a_transport(self):
        with mock.patch.dict(os.environ, {"GIT_ALLOW_PROTOCOL": "ftp"}):
            for context in (contexts.UNTRUSTED, contexts.SAW_OWNED, contexts.OPERATOR_CONFIG):
                self.assertEqual(contexts.child_env(context, None)["GIT_ALLOW_PROTOCOL"], "")
            self.assertEqual(contexts.child_env(contexts.OPERATOR_PUSH, None)["GIT_ALLOW_PROTOCOL"],
                             "https:ssh")

    def test_a_read_never_fetches_what_the_clone_lacks(self):
        origin = self.new_repo("origin", uploadpack__allowFilter="true")
        self.write(origin, "f.txt", "held elsewhere\n")
        self.commit(origin, "c")
        partial = self.owned(origin.parent / "partial")
        subprocess.run(["git", "-c", "protocol.file.allow=always", "clone", "-q", "--filter=blob:none",
                        "--no-checkout", f"file://{origin}", str(partial)], check=True)
        self.git(partial, "config", "protocol.file.allow", "always")
        res = query.run(partial, ["cat-file", "-p", "HEAD:f.txt"])
        self.assertNotEqual(res.returncode, 0)
        self.assertIsNone(query.file_text_at(partial, "HEAD", "f.txt"))
        self.assertFalse(query.holds_its_history(partial))


class TestTheRewriteStopsWhereItCannotRead(GitSandbox):
    def setUp(self):
        super().setUp()
        self.d = self.new_repo()
        self.write(self.d, "a.js", "payload\n")
        self.carrier = self.commit(self.d, "carrier")
        self.write(self.d, "b.js", "later\n")
        self.after = self.commit(self.d, "after")

    def test_a_replacement_it_cannot_read_is_refused(self):
        with mock.patch.object(replace, "entry_at", _unanswered(query.entry_at, self.carrier)):
            got = replace.replacement_tree(self.d, self.carrier, ["a.js"])
        self.assertFalse(got.ok)
        self.assertEqual(got.kind, "unreadable")

    def test_a_commit_it_cannot_read_is_blocked_not_carried(self):
        oid = self.git(self.d, "rev-parse", f"{self.carrier}:a.js").strip()
        with mock.patch.object(replace, "entry_at", _unanswered(query.entry_at, self.after)):
            tree, refusal = replace.carried_forward(self.d, self.after, {}, remove={"a.js": oid})
        self.assertIsNone(tree)
        self.assertEqual(refusal, ("unreadable", "a.js"))

    def test_a_written_tree_it_cannot_read_back_is_not_applied(self):
        tree = self.git(self.d, "rev-parse", f"{self.after}^{{tree}}").strip()
        with mock.patch.object(replace, "entry_at", _unanswered(query.entry_at, tree)):
            self.assertEqual(replace._not_applied(self.d, tree, [("a.js", None)]), ["a.js"])

    def test_a_replaced_commit_it_cannot_read_is_blocked_with_its_descendants(self):
        replacement = replace.Replacement(tree="t", plan=(("a.js", None),))
        graph = [(self.carrier, []), (self.after, [self.carrier])]
        with mock.patch.object(rebuild, "entry_at", _unanswered(query.entry_at, self.carrier)):
            got = rebuild.rebuild_without_payload(self.d, graph, {self.carrier: replacement},
                                                  lambda *a: ("x", "", ""))
        self.assertEqual(got.blocked[self.carrier][0], "unreadable")
        self.assertIn(self.after, got.blocked)
        self.assertEqual(got.mapping, {})


if __name__ == "__main__":
    unittest.main()
