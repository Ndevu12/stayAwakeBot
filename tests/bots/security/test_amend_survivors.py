#!/usr/bin/env python3
"""`saw fix amend` accounts for a removed file beyond the branches it rewrites.

A ref outside the rewrite that still reaches a removed file is named for review, and a file amend
removes does not survive the history it rewrites.
"""
from __future__ import annotations

import subprocess
import unittest
from unittest import mock

from stayawake.bots.security.models import CONFIRMED, Finding, ScanResult, Severity
from stayawake.bots.security.signatures import load_signatures
from stayawake.bots.security.pr.amend import amend_outcome
from stayawake.bots.security.pr.outcome import Cause, render_amend_line
from stayawake.bots.security.remediation.footprint import REMOVE_FILE
from stayawake.bots.security.targets import ScanOptions
from stayawake.lib.git.write.push import PushResult
from tests.bots.security.test_amend import _AmendFixture

_FILE = "src/fonts/BlockchainFont.woff2"


def _foreign_finding(path=_FILE):
    return Finding("fake-font-blockchain", "fake-font", Severity.HIGH, path,
                   "wholly foreign", remediation=REMOVE_FILE, confidence=CONFIRMED)


class _Survivors(_AmendFixture):
    """A repository whose main branch carries a wholly foreign file amend removes."""

    def _act_removing_foreign(self):
        scan = ScanResult(target=str(self.d), source="local", findings=[_foreign_finding()])
        with self._remote():
            with mock.patch("stayawake.bots.security.pr.amend.scan_target", return_value=scan):
                return amend_outcome(self.d, "acme/app", ScanOptions(), load_signatures(), [], "t",
                                     pusher=lambda *a: PushResult(True))

    def _foreign_on_main(self):
        """The foreign file committed early and carried to the tip, with unrelated commits after it."""
        self.write(self.d, _FILE, "wOF2\x00camouflage\n")
        self.commit(self.d, "add the foreign font")
        self.write(self.d, "app.js", "ok\n")
        self.commit(self.d, "unrelated work")
        self.write(self.d, "app.js", "ok2\n")
        self.commit(self.d, "more unrelated work")

    def _reachable(self, ref, path=_FILE):
        return subprocess.run(["git", "-C", str(self.d), "cat-file", "-e", f"{ref}:{path}"],
                              capture_output=True).returncode == 0

    def _reasons(self, outcome):
        return [r.cause for r in outcome.reasons]


class TestAmendNamesSurvivorsOnOtherRefs(_Survivors):

    def test_a_tag_holding_the_removed_file_is_named(self):
        self._foreign_on_main()
        self.git(self.d, "tag", "v1.0")
        outcome = self._act_removing_foreign()
        self.assertIn(_FILE, outcome.removed)
        self.assertTrue(self._reachable("refs/tags/v1.0"))
        self.assertIn(Cause.PAYLOAD_REACHABLE_FROM_OTHER_REFS, self._reasons(outcome))
        self.assertTrue(outcome.needs_review)
        self.assertIn("refs/tags/v1.0", render_amend_line(outcome))

    def test_a_stash_holding_the_removed_file_is_named(self):
        self._foreign_on_main()
        (self.d / "app.js").write_text("dirty\n")
        self.git(self.d, "stash", "push", "-u", "-m", "wip")
        outcome = self._act_removing_foreign()
        self.assertTrue(self._reachable("refs/stash"))
        self.assertIn(Cause.PAYLOAD_REACHABLE_FROM_OTHER_REFS, self._reasons(outcome))
        self.assertTrue(outcome.needs_review)
        self.assertIn("stash@{", render_amend_line(outcome))

    def test_a_non_origin_remote_ref_holding_it_is_named(self):
        self._foreign_on_main()
        tip = self.git(self.d, "rev-parse", "HEAD").strip()
        self.git(self.d, "update-ref", "refs/remotes/upstream/main", tip)
        outcome = self._act_removing_foreign()
        self.assertTrue(self._reachable("refs/remotes/upstream/main"))
        self.assertIn(Cause.PAYLOAD_REACHABLE_FROM_OTHER_REFS, self._reasons(outcome))
        self.assertIn("refs/remotes/upstream/main", render_amend_line(outcome))

    def test_an_arbitrary_ref_holding_it_is_named(self):
        self._foreign_on_main()
        tip = self.git(self.d, "rev-parse", "HEAD").strip()
        self.git(self.d, "update-ref", "refs/backup/main", tip)
        outcome = self._act_removing_foreign()
        self.assertTrue(self._reachable("refs/backup/main"))
        self.assertIn(Cause.PAYLOAD_REACHABLE_FROM_OTHER_REFS, self._reasons(outcome))
        self.assertIn("refs/backup/main", render_amend_line(outcome))

    def test_a_clean_amend_names_no_other_ref(self):
        """With no ref outside the branches holding the file, nothing is left for review."""
        self._foreign_on_main()
        outcome = self._act_removing_foreign()
        self.assertIn(_FILE, outcome.removed)
        self.assertNotIn(Cause.PAYLOAD_REACHABLE_FROM_OTHER_REFS, self._reasons(outcome))
        self.assertNotIn(Cause.REMOVAL_NOT_CONFIRMED, self._reasons(outcome))
        self.assertFalse(outcome.needs_review)

    def test_a_stash_without_its_log_is_named(self):
        self._foreign_on_main()
        (self.d / "app.js").write_text("dirty\n")
        self.git(self.d, "stash", "push", "-u", "-m", "wip")
        (self.d / ".git" / "logs" / "refs" / "stash").unlink()
        outcome = self._act_removing_foreign()
        self.assertIn(Cause.PAYLOAD_REACHABLE_FROM_OTHER_REFS, self._reasons(outcome))
        self.assertIn("refs/stash", render_amend_line(outcome))

    def test_a_remote_ref_that_is_not_a_branch_is_named(self):
        self._foreign_on_main()
        tip = self.git(self.d, "rev-parse", "HEAD").strip()
        self.git(self.d, "update-ref", "refs/remotes/origin/notes/x", tip)
        outcome = self._act_removing_foreign()
        self.assertIn(Cause.PAYLOAD_REACHABLE_FROM_OTHER_REFS, self._reasons(outcome))
        self.assertIn("refs/remotes/origin/notes/x", render_amend_line(outcome))

    def test_a_ref_private_to_another_checkout_is_named(self):
        self._foreign_on_main()
        tip = self.git(self.d, "rev-parse", "HEAD").strip()
        other = self.d.parent / "other-checkout"
        self.git(self.d, "worktree", "add", "-q", "--detach", str(other), "HEAD~3")
        self.git(other, "update-ref", "refs/bisect/bad", tip)
        outcome = self._act_removing_foreign()
        self.assertIn(Cause.PAYLOAD_REACHABLE_FROM_OTHER_REFS, self._reasons(outcome))
        self.assertIn("worktrees/other-checkout/refs/bisect/bad", render_amend_line(outcome))

    def test_a_remote_branch_the_push_left_behind_is_named(self):
        self._foreign_on_main()
        tip = self.git(self.d, "rev-parse", "HEAD").strip()
        self.git(self.d, "update-ref", f"refs/remotes/origin/{self.base}", tip)
        outcome = self._act_removing_foreign()
        self.assertIn(Cause.PAYLOAD_REACHABLE_FROM_OTHER_REFS, self._reasons(outcome))
        self.assertIn(f"refs/remotes/origin/{self.base}", render_amend_line(outcome))

    def test_a_checkout_whose_directory_is_a_link_is_never_passed_over(self):
        self._foreign_on_main()
        tip = self.git(self.d, "rev-parse", "HEAD").strip()
        other = self.d.parent / "other-checkout"
        self.git(self.d, "worktree", "add", "-q", "--detach", str(other), "HEAD~3")
        self.git(other, "update-ref", "refs/bisect/bad", tip)
        admin = self.d / ".git" / "worktrees" / "other-checkout"
        moved = self.d.parent / "moved-admin"
        admin.rename(moved)
        admin.symlink_to(moved)
        outcome = self._act_removing_foreign()
        self.assertTrue(outcome.needs_review)
        self.assertIn("worktrees/other-checkout", render_amend_line(outcome))

    def test_a_symbolic_ref_to_something_unlisted_is_walked_itself(self):
        self._foreign_on_main()
        tip = self.git(self.d, "rev-parse", "HEAD").strip()
        (self.d / ".git" / "KEEP_HEAD").write_text(tip + "\n")
        (self.d / ".git" / "refs" / "keep").write_text("ref: KEEP_HEAD\n")
        outcome = self._act_removing_foreign()
        self.assertIn(Cause.PAYLOAD_REACHABLE_FROM_OTHER_REFS, self._reasons(outcome))
        self.assertIn("refs/keep", render_amend_line(outcome))

    def test_a_pseudo_ref_left_on_a_replaced_commit_is_named(self):
        self._foreign_on_main()
        tip = self.git(self.d, "rev-parse", "HEAD").strip()
        (self.d / ".git" / "ORIG_HEAD").write_text(tip + "\n")
        outcome = self._act_removing_foreign()
        self.assertIn(Cause.PAYLOAD_REACHABLE_FROM_OTHER_REFS, self._reasons(outcome))
        self.assertIn("main-worktree/ORIG_HEAD", render_amend_line(outcome))

    def test_a_symbolic_ref_is_not_counted_as_a_second_holder(self):
        self._foreign_on_main()
        tip = self.git(self.d, "rev-parse", "HEAD").strip()
        self.git(self.d, "update-ref", f"refs/remotes/origin/{self.base}", tip)
        self.git(self.d, "symbolic-ref", "refs/remotes/origin/HEAD",
                 f"refs/remotes/origin/{self.base}")
        line = render_amend_line(self._act_removing_foreign())
        self.assertIn(f"refs/remotes/origin/{self.base}", line)
        self.assertNotIn("refs/remotes/origin/HEAD", line)

    def test_the_remote_branches_are_refreshed_after_the_push(self):
        self._foreign_on_main()
        tip = self.git(self.d, "rev-parse", "HEAD").strip()
        self.git(self.d, "update-ref", f"refs/remotes/origin/{self.base}", tip)
        from stayawake.bots.security.pr import amend as amendmod
        refreshes = []

        def refresh(repo, token=None):
            refreshes.append(repo)
            if len(refreshes) > 1:
                pushed = self.git(self.d, "rev-parse", f"refs/heads/{self.base}").strip()
                self.git(self.d, "update-ref", f"refs/remotes/origin/{self.base}", pushed)
            return mock.Mock(ok=True, reason="")

        scan = ScanResult(target=str(self.d), source="local", findings=[_foreign_finding()])
        with self._remote():
            with mock.patch("stayawake.bots.security.pr.amend.scan_target", return_value=scan), \
                    mock.patch.object(amendmod.gitutil, "fetch_refs", refresh):
                outcome = amend_outcome(self.d, "acme/app", ScanOptions(), load_signatures(), [],
                                        "t", pusher=lambda *a: PushResult(True))
        self.assertEqual(2, len(refreshes))
        self.assertNotIn(Cause.PAYLOAD_REACHABLE_FROM_OTHER_REFS, self._reasons(outcome))
        self.assertFalse(self._reachable(f"refs/remotes/origin/{self.base}"))

    def test_a_tag_at_the_cleaned_tip_is_not_named(self):
        """A tag pointing at the rewritten, clean tip holds no payload and is not a survivor."""
        self._foreign_on_main()
        outcome = self._act_removing_foreign()
        head = self.git(self.d, "rev-parse", "HEAD").strip()
        self.git(self.d, "tag", "release", head)
        self.assertFalse(self._reachable("refs/tags/release"))
        self.assertNotIn(Cause.PAYLOAD_REACHABLE_FROM_OTHER_REFS, self._reasons(outcome))

    def test_every_stash_reflog_entry_is_enumerated_not_just_the_top(self):
        """Every stash reflog entry is checked, not only `refs/stash`."""
        from stayawake.bots.security.pr import amend as amendmod
        (self.d / "wip.txt").write_text("a\n")
        self.git(self.d, "stash", "push", "-u", "-m", "one")
        (self.d / "wip.txt").write_text("b\n")
        self.git(self.d, "stash", "push", "-u", "-m", "two")
        names = {r for r, _ in amendmod._candidate_refs(self.d)[0]}
        self.assertIn("stash@{0}", names)
        self.assertIn("stash@{1}", names)

    def test_scope_lists_every_ref_the_repository_keeps(self):
        """Every ref is listed, branches and remote branches included; each is judged by what it
        points at."""
        from stayawake.bots.security.pr import amend as amendmod
        tip = self.git(self.d, "rev-parse", "HEAD").strip()
        self.git(self.d, "update-ref", "refs/remotes/origin/main", tip)
        self.git(self.d, "tag", "v9")
        self.git(self.d, "update-ref", "refs/backup/x", tip)
        names = {r for r, _ in amendmod._candidate_refs(self.d)[0]}
        self.assertLessEqual({"refs/tags/v9", "refs/backup/x", f"refs/heads/{self.base}",
                              "refs/remotes/origin/main"}, names)


class TestAmendNeverCallsAnUnansweredCheckClean(_Survivors):
    """A check git could not answer is named for review. It never reads as nothing holding the
    removed file, and it never stops the rest of the run."""

    def _completes_and_names(self, outcome, subject):
        self.assertTrue(outcome.completed)
        self.assertTrue(outcome.needs_review)
        self.assertIn(Cause.REMOVAL_NOT_CONFIRMED, self._reasons(outcome))
        self.assertIn(subject, render_amend_line(outcome))
        self.assertIn(_FILE, outcome.removed)
        self.assertFalse(self._reachable("refs/heads/main"))

    def test_other_refs_git_could_not_walk_are_named_for_review(self):
        self._foreign_on_main()
        self.git(self.d, "tag", "v1.0")
        from stayawake.bots.security.pr import amend as amendmod
        real = amendmod.gitutil.reachable_objects

        def after_the_push(repo, tips, exclude=None):
            return None if exclude else real(repo, tips, exclude)

        with mock.patch.object(amendmod.gitutil, "reachable_objects", after_the_push):
            outcome = self._act_removing_foreign()
        self._completes_and_names(outcome, "refs/tags/v1.0")

    def test_other_refs_git_could_not_list_are_named_for_review(self):
        self._foreign_on_main()
        from stayawake.bots.security.pr import amend as amendmod
        real = amendmod._answer

        def unlisted(repo, args):
            return None if args[:1] == ["worktree"] else real(repo, args)

        with mock.patch.object(amendmod, "_answer", unlisted):
            outcome = self._act_removing_foreign()
        self._completes_and_names(outcome, "the other checkouts")

    def test_stash_entries_git_could_not_list_are_named_for_review(self):
        self._foreign_on_main()
        self.write(self.d, "wip.js", "work in progress\n")
        self.git(self.d, "add", "wip.js")
        self.git(self.d, "stash")
        from stayawake.bots.security.pr import amend as amendmod
        real = amendmod._answer

        def unlisted(repo, args):
            return None if args[:2] == ["rev-list", "-g"] else real(repo, args)

        with mock.patch.object(amendmod, "_answer", unlisted):
            outcome = self._act_removing_foreign()
        self._completes_and_names(outcome, "the stash entries")

    def test_a_rebuilt_history_git_could_not_walk_is_still_rewritten(self):
        self._foreign_on_main()
        from stayawake.bots.security.pr import amend as amendmod
        with mock.patch.object(amendmod.gitutil, "reachable_objects", return_value=None):
            outcome = self._act_removing_foreign()
        self._completes_and_names(outcome, "every branch")

    def test_refs_git_could_not_list_are_named_for_review(self):
        self._foreign_on_main()
        from stayawake.bots.security.pr import amend as amendmod
        real = amendmod._answer

        def unlisted(repo, args):
            return None if args[-1:] == ["refs/"] else real(repo, args)

        with mock.patch.object(amendmod, "_answer", unlisted):
            outcome = self._act_removing_foreign()
        self._completes_and_names(outcome, "the tags, stashes and other refs")

    def test_checkouts_git_could_not_locate_are_named_for_review(self):
        self._foreign_on_main()
        from stayawake.bots.security.pr import amend as amendmod
        real = amendmod._answer

        def unlocated(repo, args):
            return None if "--git-common-dir" in args else real(repo, args)

        with mock.patch.object(amendmod, "_answer", unlocated):
            outcome = self._act_removing_foreign()
        self._completes_and_names(outcome, "the other checkouts' own refs")

    def test_a_checkout_whose_own_refs_git_could_not_list_is_named_for_review(self):
        self._foreign_on_main()
        from stayawake.bots.security.pr import amend as amendmod
        real = amendmod._answer

        def unlisted(repo, args):
            return None if "refs/bisect/" in args else real(repo, args)

        with mock.patch.object(amendmod, "_answer", unlisted):
            outcome = self._act_removing_foreign()
        self._completes_and_names(outcome, "the refs of main-worktree")

    def test_pseudo_refs_git_could_not_read_are_named_for_review(self):
        self._foreign_on_main()
        from stayawake.bots.security.pr import amend as amendmod
        with mock.patch.object(amendmod, "_pseudo_refs_in", return_value=None):
            outcome = self._act_removing_foreign()
        self._completes_and_names(outcome, "the refs of main-worktree")

    def test_a_known_holder_is_named_when_another_source_cannot_be_listed(self):
        self._foreign_on_main()
        self.git(self.d, "tag", "v1.0")
        from stayawake.bots.security.pr import amend as amendmod
        real = amendmod._answer

        def unlisted(repo, args):
            return None if args[:1] == ["worktree"] else real(repo, args)

        with mock.patch.object(amendmod, "_answer", unlisted):
            outcome = self._act_removing_foreign()
        self.assertIn(Cause.PAYLOAD_REACHABLE_FROM_OTHER_REFS, self._reasons(outcome))
        self.assertIn("refs/tags/v1.0", render_amend_line(outcome))
        self._completes_and_names(outcome, "the other checkouts")

    def test_a_known_holder_is_named_when_the_combined_walk_fails(self):
        self._foreign_on_main()
        self.git(self.d, "tag", "v1.0")
        from stayawake.bots.security.pr import amend as amendmod
        real = amendmod.gitutil.reachable_objects

        def combined_fails(repo, tips, exclude=None):
            return None if exclude and len(tips) > 1 else real(repo, tips, exclude)

        with mock.patch.object(amendmod.gitutil, "reachable_objects", combined_fails):
            outcome = self._act_removing_foreign()
        self.assertIn(Cause.PAYLOAD_REACHABLE_FROM_OTHER_REFS, self._reasons(outcome))
        self.assertIn("refs/tags/v1.0", render_amend_line(outcome))

    def test_a_checkout_directory_git_does_not_recognise_is_named_not_mislabelled(self):
        self._foreign_on_main()
        tip = self.git(self.d, "rev-parse", "HEAD").strip()
        self.git(self.d, "update-ref", "refs/bisect/bad", tip)
        (self.d / ".git" / "worktrees" / "junk").mkdir(parents=True)
        outcome = self._act_removing_foreign()
        line = render_amend_line(outcome)
        self.assertIn("main-worktree/refs/bisect/bad", line)
        self.assertNotIn("worktrees/junk/refs/bisect/bad", line)
        self.assertIn("the refs of worktrees/junk", line)

    def test_a_remote_copy_that_could_not_be_refreshed_is_said(self):
        self._foreign_on_main()
        from stayawake.bots.security.pr import amend as amendmod
        refreshes = []

        def refresh(repo, token=None):
            refreshes.append(repo)
            if len(refreshes) > 1:
                return mock.Mock(ok=False, reason="network is unreachable")
            return mock.Mock(ok=True, reason="")

        scan = ScanResult(target=str(self.d), source="local", findings=[_foreign_finding()])
        with self._remote():
            with mock.patch("stayawake.bots.security.pr.amend.scan_target", return_value=scan), \
                    mock.patch.object(amendmod.gitutil, "fetch_refs", refresh):
                outcome = amend_outcome(self.d, "acme/app", ScanOptions(), load_signatures(), [],
                                        "t", pusher=lambda *a: PushResult(True))
        self.assertIn(Cause.REMOTE_COPY_NOT_REFRESHED, self._reasons(outcome))
        self.assertIn("network is unreachable", render_amend_line(outcome))
        self.assertTrue(outcome.needs_review)

    def test_a_branch_tip_git_could_not_resolve_is_named_for_review(self):
        self.git(self.d, "branch", "other")
        self._foreign_on_main()
        from stayawake.bots.security.pr import amend as amendmod
        real = amendmod._answer

        def failing(repo, args):
            return None if args[:1] == ["rev-parse"] else real(repo, args)

        with mock.patch.object(amendmod, "_answer", failing):
            outcome = self._act_removing_foreign()
        self._completes_and_names(outcome, "branch other")

    def test_branches_git_could_not_list_after_the_rewrite_are_named_for_review(self):
        self._foreign_on_main()
        from stayawake.bots.security.pr import amend as amendmod
        real = amendmod.gitutil.listed_branch_refs
        calls = []

        def listed_once(repo):
            calls.append(repo)
            return real(repo) if len(calls) == 1 else None

        with mock.patch.object(amendmod.gitutil, "listed_branch_refs", listed_once):
            outcome = self._act_removing_foreign()
        self._completes_and_names(outcome, "the other branches")

    def test_a_removed_version_it_could_not_read_is_named_for_review(self):
        self._foreign_on_main()
        from stayawake.bots.security.pr import amend as amendmod
        real = amendmod._payload_blobs

        def one_unread(*args):
            oids, unsure = real(*args)
            return oids, [*unsure, "every copy of lib/unread.js"]

        with mock.patch.object(amendmod, "_payload_blobs", one_unread):
            outcome = self._act_removing_foreign()
        self._completes_and_names(outcome, "every copy of lib/unread.js")

    def test_a_branch_left_behind_git_could_not_read_is_named_for_review(self):
        self.git(self.d, "branch", "other")
        self._foreign_on_main()
        from stayawake.bots.security.pr import amend as amendmod
        real = amendmod.gitutil.entry_at

        def unreadable_other(repo, treeish, path):
            return (False, None) if treeish == "refs/heads/other" else real(repo, treeish, path)

        with mock.patch.object(amendmod.gitutil, "entry_at", unreadable_other):
            outcome = self._act_removing_foreign()
        self._completes_and_names(outcome, "branch other")

    def test_a_rewritten_history_git_could_not_relate_is_named_for_review(self):
        self._foreign_on_main()
        from stayawake.bots.security.pr import amend as amendmod
        before = set(self.git(self.d, "rev-list", "--all").split())
        real = amendmod.gitutil.ancestry

        def rewritten_unrelated(repo, ancestor, descendant):
            return real(repo, ancestor, descendant) if descendant in before else None

        with mock.patch.object(amendmod.gitutil, "ancestry", rewritten_unrelated):
            outcome = self._act_removing_foreign()
        self._completes_and_names(outcome, f"the rewritten branch {self.base}")

    def test_a_tag_whose_commit_is_replaced_is_still_named(self):
        self._foreign_on_main()
        tree = self.git(self.d, "rev-parse", "HEAD^{tree}").strip()
        side = subprocess.run(["git", "-C", str(self.d), "commit-tree", tree, "-p", "HEAD", "-m",
                               "only the tag reaches this"], capture_output=True, text=True,
                              env={**__import__("os").environ, "GIT_AUTHOR_NAME": "t",
                                   "GIT_AUTHOR_EMAIL": "t@t", "GIT_COMMITTER_NAME": "t",
                                   "GIT_COMMITTER_EMAIL": "t@t"}).stdout.strip()
        self.git(self.d, "tag", "v1.0", side)
        self.git(self.d, "replace", side, self.git(self.d, "rev-parse", "HEAD~3").strip())
        outcome = self._act_removing_foreign()
        self.assertIn(Cause.PAYLOAD_REACHABLE_FROM_OTHER_REFS, self._reasons(outcome))


class TestAReplacedMergeIsFollowedOnEveryRef(_AmendFixture):
    """A ref that still reaches a merge the run replaced is named, whatever kind of ref it is."""

    def test_a_clean_run_names_no_ref(self):
        self._loader_merge()
        outcome = self._act()
        self.assertNotIn(Cause.PAYLOAD_REACHABLE_FROM_OTHER_REFS, [r.cause for r in outcome.reasons])
        self.assertFalse(outcome.needs_review)

    def test_a_ref_left_at_the_merge_is_named(self):
        self._loader_merge()
        self.git(self.d, "update-ref", "refs/backup/main", self._rev())
        outcome = self._act()
        self.assertIn(Cause.PAYLOAD_REACHABLE_FROM_OTHER_REFS, [r.cause for r in outcome.reasons])
        self.assertIn("refs/backup/main", render_amend_line(outcome))

    def test_a_ref_left_at_the_merge_is_named_by_the_commit_itself(self):
        self._loader_merge()
        self.git(self.d, "update-ref", "refs/backup/main", self._rev())
        from stayawake.bots.security.pr import amend as amendmod
        with mock.patch.object(amendmod, "_payload_blobs", return_value=(set(), [])):
            outcome = self._act()
        self.assertIn("refs/backup/main", render_amend_line(outcome))

    def test_a_ref_that_carries_the_merged_file_elsewhere_is_named(self):
        self._loader_merge()
        tree = self.git(self.d, "rev-parse", "HEAD^{tree}").strip()
        root = subprocess.run(["git", "-C", str(self.d), "commit-tree", tree, "-m", "elsewhere"],
                              capture_output=True, text=True,
                              env={**__import__("os").environ, "GIT_AUTHOR_NAME": "t",
                                   "GIT_AUTHOR_EMAIL": "t@t", "GIT_COMMITTER_NAME": "t",
                                   "GIT_COMMITTER_EMAIL": "t@t"}).stdout.strip()
        self.git(self.d, "update-ref", "refs/backup/elsewhere", root)
        outcome = self._act()
        self.assertIn("refs/backup/elsewhere", render_amend_line(outcome))


class TestEachGateCheckAnswersYesNoOrUnknown(_AmendFixture):
    """Each check the run makes before and after it moves a branch tells a payload it found from one
    it could not look for."""

    def _amend(self):
        from stayawake.bots.security.pr import amend as amendmod
        return amendmod

    def test_a_branch_left_behind_that_carries_it_is_refused_by_name(self):
        self.git(self.d, "branch", "left")
        found, unsure = self._amend()._branches_left(
            self.d, [("a.js", lambda tr, p: tr.endswith("/left"))], {self.base})
        self.assertEqual(["left"], found)
        self.assertEqual([], unsure)

    def test_a_branch_left_behind_it_could_not_read_is_named_not_refused(self):
        self.git(self.d, "branch", "left")
        found, unsure = self._amend()._branches_left(
            self.d, [("a.js", lambda tr, p: None if tr.endswith("/left") else False)], {self.base})
        self.assertEqual([], found)
        self.assertEqual(["branch left"], unsure)

    def test_branches_it_could_not_list_are_named_not_refused(self):
        amendmod = self._amend()
        with mock.patch.object(amendmod.gitutil, "listed_branch_refs", return_value=None):
            found, unsure = amendmod._branches_left(self.d, [("a.js", lambda tr, p: True)], set())
        self.assertEqual(([], ["the other branches"]), (found, unsure))

    def test_a_rewritten_version_it_could_not_read_is_named_not_refused(self):
        amendmod = self._amend()
        head = self.git(self.d, "rev-parse", "HEAD").strip()
        rebuilt = mock.Mock(mapping={"old": head})
        left, unsure = amendmod._payload_left(self.d, [], rebuilt, [], {"a.js": lambda tr, p: None})
        self.assertEqual([], left)
        self.assertEqual(["the rewritten a.js"], unsure)

    def test_a_rewritten_version_that_still_carries_it_is_refused(self):
        amendmod = self._amend()
        head = self.git(self.d, "rev-parse", "HEAD").strip()
        rebuilt = mock.Mock(mapping={"old": head})
        left, _unsure = amendmod._payload_left(self.d, [], rebuilt, [],
                                               {"a.js": lambda tr, p: True})
        self.assertEqual([f"{head[:12]} still carries a.js"], left)

    def test_a_rewritten_tree_it_could_not_read_is_named_not_refused(self):
        amendmod = self._amend()
        head = self.git(self.d, "rev-parse", "HEAD").strip()
        rebuilt = mock.Mock(mapping={"old": head})
        with mock.patch.object(amendmod.gitutil, "entry_at", return_value=(False, None)):
            left, unsure = amendmod._payload_left(self.d, [], rebuilt, [], {}, {"a.js": "f" * 40})
        self.assertEqual(([], ["the rewritten a.js"]), (left, unsure))

    def test_a_version_git_could_not_read_is_unknown(self):
        amendmod = self._amend()
        self.write(self.d, "a.js", "x\n")
        self.commit(self.d, "a")
        from stayawake.lib.git import query
        with mock.patch.object(query, "entry_at", return_value=(False, None)):
            self.assertIsNone(amendmod._carries_in(self.d, "HEAD", "a.js", lambda text: False))
        with mock.patch.object(query, "blob_text", return_value=None):
            self.assertIsNone(amendmod._carries_in(self.d, "HEAD", "a.js", lambda text: False))

    def test_a_footprint_version_it_could_not_read_is_named(self):
        amendmod = self._amend()
        self.write(self.d, "a.js", "marked\n")
        self.commit(self.d, "a")
        head = self.git(self.d, "rev-parse", "HEAD").strip()
        clean = {"a.js": (lambda text: "marked" in text, None)}
        oids, unsure = amendmod._payload_blobs(self.d, {}, {}, {}, clean, {head}, (set(), []))
        self.assertEqual({self.git(self.d, "rev-parse", "HEAD:a.js").strip()}, oids)
        self.assertEqual([], unsure)
        from stayawake.lib.git import query
        for broken in ({"entry_at": (False, None)}, {"blob_text": None}):
            (name, value), = broken.items()
            with mock.patch.object(query, name, return_value=value):
                oids, unsure = amendmod._payload_blobs(self.d, {}, {}, {}, clean, {head},
                                                       (set(), []))
            self.assertEqual((set(), ["every copy of a.js"]), (oids, unsure))

    def test_a_removed_version_it_could_not_read_is_named(self):
        amendmod = self._amend()
        self.write(self.d, "a.js", "x\n")
        self.commit(self.d, "a")
        head = self.git(self.d, "rev-parse", "HEAD").strip()
        with mock.patch.object(amendmod.gitutil, "entry_at", return_value=(False, None)):
            oids, unsure = amendmod._payload_blobs(self.d, {}, {}, {"a.js": [head]}, {}, set(),
                                                   (set(), []))
        self.assertEqual(set(), oids)
        self.assertEqual(["every copy of a.js"], unsure)
        with mock.patch.object(amendmod.gitutil, "entry_at", return_value=(False, None)):
            oids, unsure = amendmod._merge_payload(self.d, {head: ("a.js",)}, {head: ("a.js",)},
                                                   lambda commit, path: None)
        self.assertEqual((set(), ["every copy of a.js"]), (oids, unsure))

    def test_a_directory_where_the_file_was_carries_nothing(self):
        self.write(self.d, "a.js/inner.js", "x\n")
        self.commit(self.d, "a directory")
        self.assertIs(False, self._amend()._carries_in(self.d, "HEAD", "a.js", lambda text: True))

    def test_a_footprint_is_read_across_windows_line_endings(self):
        import re
        self.write(self.d, "a.js", "x\r\ny\r\n")
        self.commit(self.d, "crlf")
        ends_x = re.compile(r"^x$", re.MULTILINE)
        self.assertIs(True, self._amend()._carries_in(self.d, "HEAD", "a.js",
                                                      lambda text: bool(ends_x.search(text))))

    def test_a_walk_that_keeps_failing_stops_at_its_budget_and_counts_the_rest(self):
        amendmod = self._amend()
        refs = [("refs/tags/a", "1" * 40), ("refs/tags/b", "2" * 40), ("refs/tags/c", "3" * 40)]
        with mock.patch.object(amendmod, "_candidate_refs", return_value=(refs, [])), \
                mock.patch.object(amendmod.gitutil, "reachable_objects", return_value=None), \
                mock.patch.object(amendmod.time, "monotonic", side_effect=[0.0] + [1e9] * 5):
            holding, unsure = amendmod._refs_still_reaching(self.d, {"f" * 40}, [])
        self.assertEqual(([], ["3 more refs"]), (holding, unsure))

    def test_a_path_is_held_absent_or_unknown(self):
        amendmod = self._amend()
        self.write(self.d, "held.js", "x\n")
        self.commit(self.d, "held")
        self.assertIs(True, amendmod._path_at(self.d, "HEAD", "held.js"))
        self.assertIs(False, amendmod._path_at(self.d, "HEAD", "no-such-file"))
        with mock.patch.object(amendmod.gitutil, "entry_at", return_value=(False, None)):
            self.assertIsNone(amendmod._path_at(self.d, "HEAD", "held.js"))

    def test_a_list_too_long_for_its_line_says_how_many_it_left_out(self):
        from stayawake.bots.security.pr.outcome import names_that_fit
        names = [f"refs/tags/release-candidate-{i}" for i in range(8)]
        shown = names_that_fit(names)
        self.assertLessEqual(len(shown), 120)
        self.assertTrue(shown.endswith(" and 5 more"), shown)
        self.assertEqual("a, b", names_that_fit(["a", "b", "a"]))
        self.assertTrue(names_that_fit(["x" * 200, "b"]).endswith("…, b"))

    def test_the_commits_a_branch_reaches_are_read_from_the_graph(self):
        graph = [("a", []), ("b", ["a"]), ("c", ["a"]), ("d", ["b", "c"]), ("e", ["a"])]
        self.assertEqual({"a", "b", "c", "d"}, self._amend()._reached_from(graph, ["d"]))
        self.assertEqual(set(), self._amend()._reached_from(graph, ["unknown"]))

    def test_an_unjudged_version_is_unknown_not_clean_or_carrying(self):
        from stayawake.bots.security.remediation import oracle
        judged = self._amend()._judged
        for token in (oracle.READ_ERROR, oracle.MATERIALIZE_ERROR, oracle.SCAN_ERROR):
            self.assertIsNone(judged(token))
        self.assertIs(True, judged("some-signature"))
        self.assertIs(False, judged(None))


class TestAStoredVersionIsReadAsTheRepositoryHoldsIt(_AmendFixture):
    """The check of whether a stored version carries a payload fails closed and judges the content
    the repository stores."""

    def _survives(self):
        from stayawake.bots.security.remediation import oracle
        return oracle.survives(self.d, load_signatures(), [], ScanOptions())

    def test_a_tree_git_could_not_read_counts_as_unclean(self):
        from stayawake.bots.security.remediation import oracle
        with mock.patch.object(oracle.gitutil, "entry_at", return_value=(False, None)):
            self.assertTrue(self._survives()("HEAD", "app.js"))

    def test_a_replaced_blob_is_still_judged_by_what_is_stored(self):
        self.write(self.d, ".gitignore", "node_modules\ntemp_auto_push.bat\nbranch_structure.json\n")
        self.commit(self.d, "payload")
        payload = self.git(self.d, "rev-parse", "HEAD:.gitignore").strip()
        benign = subprocess.run(["git", "-C", str(self.d), "hash-object", "-w", "--stdin"],
                                input=b"dist/\n", capture_output=True).stdout.decode().strip()
        self.git(self.d, "replace", "-f", payload, benign)
        self.assertTrue(self._survives()("HEAD", ".gitignore"))


class TestAmendRemovesEveryCopy(_AmendFixture):
    """A file amend removes does not survive the history it rewrites."""

    OLD, NEW = "src/fonts/loader.woff", "assets/fonts/renamed.woff"
    PAYLOAD = 'var _0x=String.fromCharCode(118,97,114);eval(_0x+" x=1");\n'

    def _act_removing(self, path):
        scan = ScanResult(target=str(self.d), source="local", findings=[_foreign_finding(path)])
        with self._remote():
            with mock.patch("stayawake.bots.security.pr.amend.scan_target", return_value=scan):
                return amend_outcome(self.d, "acme/app", ScanOptions(), load_signatures(), [], "t",
                                     pusher=lambda *a: PushResult(True))

    def _renamed_payload(self):
        self.write(self.d, self.OLD, self.PAYLOAD)
        self.commit(self.d, "add the foreign font")
        oid = self.git(self.d, "rev-parse", f"HEAD:{self.OLD}").strip()
        self.write(self.d, self.NEW, self.PAYLOAD)
        (self.d / self.OLD).unlink()
        self.commit(self.d, "rename it")
        self.write(self.d, "app.js", "ok\n")
        self.commit(self.d, "unrelated work")
        return oid

    def _on_branch(self, oid):
        objs = subprocess.run(["git", "-C", str(self.d), "rev-list", "--objects", "HEAD"],
                              capture_output=True, text=True).stdout
        return oid in {ln.split()[0] for ln in objs.splitlines() if ln.split()}

    def _reasons(self, outcome):
        return [r.cause for r in outcome.reasons]

    def test_a_renamed_payload_is_removed_at_its_former_path_too(self):
        oid = self._renamed_payload()
        self.git(self.d, "tag", "v-pre", "HEAD~2")
        outcome = self._act_removing(self.NEW)
        self.assertTrue(outcome.completed)
        self.assertIn(self.NEW, outcome.removed)
        self.assertIn(self.OLD, outcome.removed)
        self.assertFalse(self._on_branch(oid))
        self.assertIn(Cause.PAYLOAD_REACHABLE_FROM_OTHER_REFS, self._reasons(outcome))
        self.assertIn("refs/tags/v-pre", render_amend_line(outcome))

    def test_a_former_path_reused_by_a_legitimate_file_keeps_it(self):
        oid = self._renamed_payload()
        self.write(self.d, self.OLD, "legitimate font data\n")
        self.commit(self.d, "a new legitimate file at the old name")
        outcome = self._act_removing(self.NEW)
        self.assertTrue(outcome.completed)
        self.assertFalse(self._on_branch(oid))
        kept = self.git(self.d, "show", f"HEAD:{self.OLD}")
        self.assertEqual("legitimate font data\n", kept)

    def test_a_walk_that_cannot_complete_refuses(self):
        self._renamed_payload()
        from stayawake.bots.security.pr import amend as amendmod
        with mock.patch.object(amendmod.gitutil, "blob_paths", return_value=None):
            outcome = self._act_removing(self.NEW)
        self.assertFalse(outcome.completed)
        self.assertIn(Cause.HISTORY_TOO_LARGE_TO_ENUMERATE, self._reasons(outcome))

    def _anywhere(self, oid):
        objs = subprocess.run(["git", "-C", str(self.d), "rev-list", "--objects",
                               "--branches", "--glob=refs/remotes/origin/*"],
                              capture_output=True, text=True).stdout
        return oid in {ln.split()[0] for ln in objs.splitlines() if ln.split()}

    def test_a_copy_on_a_side_branch_under_a_non_ascii_name_is_removed(self):
        self.git(self.d, "checkout", "-qb", "side")
        self.write(self.d, "src/évil.woff", self.PAYLOAD)
        self.commit(self.d, "a copy on the side")
        self.git(self.d, "checkout", "-q", self.base)
        oid = self._renamed_payload()
        outcome = self._act_removing(self.NEW)
        self.assertTrue(outcome.completed)
        self.assertFalse(self._anywhere(oid))

    def test_a_copy_only_a_side_branch_reaches_is_refused_not_reported_removed(self):
        self.git(self.d, "checkout", "-qb", "side")
        self.write(self.d, "src/copy.woff", self.PAYLOAD)
        self.commit(self.d, "a copy on the side")
        self.git(self.d, "checkout", "-q", self.base)
        self.write(self.d, self.NEW, self.PAYLOAD)
        self.commit(self.d, "the scanned copy")
        from stayawake.bots.security.pr import amend as amendmod
        with mock.patch.object(amendmod.gitutil, "blob_paths", return_value=[]):
            outcome = self._act_removing(self.NEW)
        self.assertFalse(outcome.completed)
        self.assertIn(Cause.PAYLOAD_STILL_REACHABLE, self._reasons(outcome))
        self.assertIn("side", render_amend_line(outcome))

    def test_an_unreadable_location_is_refused_by_name(self):
        self._renamed_payload()
        from stayawake.bots.security.pr import amend as amendmod
        with mock.patch.object(amendmod.gitutil, "blob_paths", return_value=["no/such.woff"]):
            outcome = self._act_removing(self.NEW)
        self.assertFalse(outcome.completed)
        self.assertIn(Cause.PAYLOAD_STILL_REACHABLE, self._reasons(outcome))
        self.assertIn("no/such.woff", render_amend_line(outcome))

    def test_a_copy_the_run_cannot_take_out_makes_it_refuse(self):
        self._renamed_payload()
        from stayawake.bots.security.pr import amend as amendmod
        with mock.patch.object(amendmod.gitutil, "blob_paths", return_value=[]):
            outcome = self._act_removing(self.NEW)
        self.assertFalse(outcome.completed)
        self.assertIn(Cause.PAYLOAD_STILL_REACHABLE, self._reasons(outcome))


if __name__ == "__main__":
    unittest.main()
