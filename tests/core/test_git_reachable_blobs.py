#!/usr/bin/env python3
"""What history still carries — every blob reachable from any ref, not just the checked-out tree.

The scan reads the working tree, so a payload one commit back, on another branch, or under a tag is
never examined and the repository reports `clean`. Measured on the reference account: 0 artefacts at
any branch tip and 59 payload blobs still reachable from live refs across all 24 remediated
repositories. This is the enumeration those three axes share.
"""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from support.gitrepo import GitSandbox                       # noqa: E402
from stayawake.lib.git import query                          # noqa: E402


class TestEveryRefIsReached(GitSandbox):
    def _repo_with_history(self):
        repo = self.new_repo()
        self.write(repo, "kept.txt", "on every ref\n")
        self.commit(repo, "first")
        return repo

    def _paths(self, repo):
        blobs, complete = query.reachable_blobs(repo)
        self.assertTrue(complete)
        return {path for _sha, path in blobs}

    def test_a_blob_only_in_an_earlier_commit_is_reached(self):
        """The `saw fix` shape: the payload lands, a removal commit cleans the tip. One command
        puts it back — `git show HEAD~1:<path>` — and the tree scan never sees it."""
        repo = self._repo_with_history()
        self.write(repo, "payload.js", "the payload\n")
        self.commit(repo, "payload lands")
        (repo / "payload.js").unlink()
        self.commit(repo, "removal commit cleans the tip")
        self.assertFalse((repo / "payload.js").exists(), "the tree really is clean")
        self.assertIn("payload.js", self._paths(repo))

    def test_a_blob_only_on_another_branch_is_reached(self):
        """`#183` measured 329 of 380 branches still infected after a single-branch remediation."""
        repo = self._repo_with_history()
        self.git(repo, "checkout", "-q", "-b", "side")
        self.write(repo, "only-on-side.js", "elsewhere\n")
        self.commit(repo, "side only")
        self.git(repo, "checkout", "-q", "main")
        self.assertIn("only-on-side.js", self._paths(repo))

    def test_a_blob_only_under_a_tag_is_reached(self):
        """A tag is a one-command entry point: `git clone --branch <tag>` puts it on disk."""
        repo = self._repo_with_history()
        self.write(repo, "tagged.js", "under a tag\n")
        self.commit(repo, "tagged content")
        self.git(repo, "tag", "v1")
        self.git(repo, "reset", "-q", "--hard", "HEAD~1")
        self.assertFalse((repo / "tagged.js").exists())
        self.assertIn("tagged.js", self._paths(repo))

    def test_one_content_on_many_branches_is_one_object(self):
        """Deduplicated by blob sha. Counting per branch overstates the work by the branch count,
        and a real repository carries the same file on most of them."""
        repo = self._repo_with_history()
        for name in ("a", "b", "c", "d"):
            self.git(repo, "checkout", "-q", "-b", name, "main")
        blobs, _ = query.reachable_blobs(repo)
        shas = [sha for sha, path in blobs if path == "kept.txt"]
        self.assertEqual(len(shas), 1, "the same content reached five ways is one object")

    def test_a_commit_is_not_returned_as_content(self):
        """`rev-list --objects` emits commits and tag objects with no path at all — 5600 of 20400
        on this project's own repository. Returning them would hand a caller shas that are not
        content to read."""
        repo = self._repo_with_history()
        self.git(repo, "tag", "-a", "v1", "-m", "annotated")
        blobs, _ = query.reachable_blobs(repo)
        shas = {sha for sha, _p in blobs}
        self.assertNotIn(self.rev(repo), shas, "a commit sha came back as content")
        self.assertNotIn(self.git(repo, "rev-parse", "v1").strip(), shas,
                         "a tag object sha came back as content")
        self.assertTrue(all(path for _s, path in blobs), "every entry names something")

    def test_a_bound_that_was_hit_is_reported(self):
        """A bound that is not reported reads as coverage of what it cut."""
        repo = self._repo_with_history()
        for n in range(6):
            self.write(repo, f"f{n}.txt", f"{n}\n")
            self.commit(repo, f"c{n}")
        blobs, complete = query.reachable_blobs(repo, limit=3)
        self.assertFalse(complete)
        self.assertEqual(len(blobs), 3)

    def test_a_repository_with_nothing_in_it_answers_empty(self):
        blobs, complete = query.reachable_blobs(self.new_repo("bare"))
        self.assertEqual(blobs, [])
        self.assertTrue(complete)


if __name__ == "__main__":
    unittest.main()
