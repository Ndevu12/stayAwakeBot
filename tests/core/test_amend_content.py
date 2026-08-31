#!/usr/bin/env python3
"""lib.git.write.amend — what replacing a confirmed evil merge does to content that is NOT the
payload, against REAL local git repos (no network, no mocks).

Three rules are pinned here. The reconstruction is the plain auto-merge of the two parents, so
every other byte the merge contributed is destroyed silently: `discarded_delta` has to name all
of it. `--rebase-merges` rebuilds a suffix merge by merging again, so a clean-but-different
re-resolution lands in a commit nobody flagged: `replay_is_faithful` has to catch it. And
`point_branch_at` runs `reset --hard` on the checked-out branch, so the uncommitted-work guard
belongs in that function rather than three call layers above it.
"""
from __future__ import annotations

import subprocess
import tempfile
import unittest
from pathlib import Path

from stayawake.lib.git.write import amend

_ABSENT = "0" * 40


def _git(repo: Path, *args: str) -> str:
    res = subprocess.run(["git", "-C", str(repo), *args],
                         check=True, capture_output=True, text=True)
    return res.stdout


def _rev(repo: Path, ref: str) -> str:
    return _git(repo, "rev-parse", ref).strip()


def _write(repo: Path, rel: str, text: str) -> None:
    path = repo / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def _commit(repo: Path, message: str) -> str:
    _git(repo, "add", "-A")
    _git(repo, "commit", "-qm", message)
    return _rev(repo, "HEAD")


def _new_repo() -> Path:
    repo = Path(tempfile.mkdtemp(prefix="saw-amend-content-"))
    subprocess.run(["git", "init", "-q", "-b", "main", str(repo)],
                   check=True, capture_output=True)
    for setting in (("user.email", "t@t"), ("user.name", "t"),
                    ("commit.gpgsign", "false"), ("tag.gpgsign", "false")):
        _git(repo, "config", *setting)
    return repo


def _repo_with_evil_merge() -> tuple[Path, str]:
    """`main` at a two-parent merge whose parents auto-merge CLEANLY, and whose recorded tree
    holds two things that auto-merge does not: `payload.js` (in neither parent) and a hand edit
    to `README.md` made while the merge was open. Only the first is the reason to replace it."""
    repo = _new_repo()
    _write(repo, "README.md", "readme\n")
    _write(repo, "app.js", "base\n")
    _commit(repo, "init")
    _git(repo, "checkout", "-q", "-b", "side")
    _write(repo, "side.js", "side\n")
    _commit(repo, "side work")
    _git(repo, "checkout", "-q", "main")
    _write(repo, "main.js", "main\n")
    _commit(repo, "main work")
    _git(repo, "merge", "--no-ff", "--no-commit", "-q", "side")
    _write(repo, "payload.js", "PAYLOAD\n")
    _write(repo, "README.md", "readme\nnote added while merging\n")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-qm", "Merge branch 'side'")
    return repo, _rev(repo, "HEAD")


def _repo_with_handmade_suffix_merge() -> tuple[Path, str, str]:
    """`(repo, evil_merge, head)` where the suffix after the evil merge ends in a SECOND merge
    that also carries content from neither parent. Its parents re-merge cleanly, so the rebase
    that replays the suffix will not conflict — it will just quietly drop `notes.txt`."""
    repo, evil = _repo_with_evil_merge()
    _git(repo, "checkout", "-q", "-b", "feature")
    _write(repo, "feat.txt", "feature\n")
    _commit(repo, "feature work")
    _git(repo, "checkout", "-q", "main")
    _write(repo, "app.js", "base\nmainline\n")
    _commit(repo, "mainline work")
    _git(repo, "merge", "--no-ff", "--no-commit", "-q", "feature")
    _write(repo, "notes.txt", "resolved by hand\n")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-qm", "Merge branch 'feature'")
    return repo, evil, _rev(repo, "HEAD")


class TestDiscardedDelta(unittest.TestCase):
    """A — the replacement discards the merge's whole contribution, not just the payload."""

    def test_names_the_hand_edit_the_reconstruction_destroys(self):
        repo, evil = _repo_with_evil_merge()
        new = amend.reconstruct_merge(repo, evil)
        self.assertIsNotNone(new, "the fixture's parents must auto-merge cleanly")

        dropped = amend.discarded_delta(repo, evil, new)

        self.assertIn("payload.js", dropped)
        self.assertIn("README.md", dropped,
                      "the merge-time edit is destroyed too — the caller must be told")
        for carried_by_a_parent in ("side.js", "main.js", "app.js"):
            self.assertNotIn(carried_by_a_parent, dropped)

    def test_names_a_deletion_the_merge_made_and_the_reconstruction_undoes(self):
        repo = _new_repo()
        _write(repo, "app.js", "base\n")
        _write(repo, "vendor.js", "vendored\n")
        _commit(repo, "init")
        _git(repo, "checkout", "-q", "-b", "side")
        _write(repo, "side.js", "side\n")
        _commit(repo, "side work")
        _git(repo, "checkout", "-q", "main")
        _write(repo, "main.js", "main\n")
        _commit(repo, "main work")
        _git(repo, "merge", "--no-ff", "--no-commit", "-q", "side")
        _git(repo, "rm", "-q", "vendor.js")
        _write(repo, "payload.js", "PAYLOAD\n")
        _git(repo, "add", "-A")
        _git(repo, "commit", "-qm", "Merge branch 'side'")
        evil = _rev(repo, "HEAD")
        new = amend.reconstruct_merge(repo, evil)

        dropped = amend.discarded_delta(repo, evil, new)

        self.assertIn("vendor.js", dropped,
                      "the reconstruction resurrects a file the merge deleted")
        self.assertIn("payload.js", dropped)

    def test_an_unanswerable_comparison_reports_everything_not_nothing(self):
        repo, evil = _repo_with_evil_merge()

        dropped = amend.discarded_delta(repo, evil, _ABSENT)

        self.assertIn("payload.js", dropped)
        self.assertIn("app.js", dropped,
                      "with no comparison, no path can be shown to survive")


class TestReplayIsFaithful(unittest.TestCase):
    """B — `--rebase-merges` re-resolves later merges instead of preserving them."""

    def test_reports_a_suffix_merge_that_git_re_resolved(self):
        repo, evil, old_head = _repo_with_handmade_suffix_merge()
        new_merge = amend.reconstruct_merge(repo, evil)
        replaced = amend.discarded_delta(repo, evil, new_merge)
        new_head = amend.replayed_head(repo, evil, new_merge, old_head)
        self.assertIsNotNone(new_head, "the fixture's suffix must replay without conflicting")

        faithful, report = amend.replay_is_faithful(
            repo, old_head, new_head, evil, new_merge, replaced)

        self.assertFalse(faithful, report)
        self.assertTrue(any("notes.txt" in line for line in report), report)

    def test_a_suffix_with_nothing_hand_made_replays_faithfully(self):
        repo, evil = _repo_with_evil_merge()
        _write(repo, "app.js", "base\nlater\n")
        _commit(repo, "later work")
        old_head = _rev(repo, "HEAD")
        new_merge = amend.reconstruct_merge(repo, evil)
        replaced = amend.discarded_delta(repo, evil, new_merge)
        new_head = amend.replayed_head(repo, evil, new_merge, old_head)

        faithful, report = amend.replay_is_faithful(
            repo, old_head, new_head, evil, new_merge, replaced)

        self.assertTrue(faithful, report)
        self.assertEqual(report, [])

    def test_the_paths_the_replacement_changed_are_not_reported_again(self):
        repo, evil = _repo_with_evil_merge()
        _write(repo, "app.js", "base\nlater\n")
        _commit(repo, "later work")
        old_head = _rev(repo, "HEAD")
        new_merge = amend.reconstruct_merge(repo, evil)
        new_head = amend.replayed_head(repo, evil, new_merge, old_head)

        faithful, report = amend.replay_is_faithful(
            repo, old_head, new_head, evil, new_merge, ())

        self.assertFalse(faithful, "with nothing allowed, the removed payload IS a difference")
        self.assertTrue(any("payload.js" in line for line in report), report)

    def test_sequences_that_cannot_be_walked_pairwise_are_not_assumed_clean(self):
        repo, evil, old_head = _repo_with_handmade_suffix_merge()
        new_merge = amend.reconstruct_merge(repo, evil)
        new_head = amend.replayed_head(repo, evil, new_merge, old_head)

        faithful, report = amend.replay_is_faithful(
            repo, old_head, new_head, evil, new_head, ())

        self.assertFalse(faithful, "no replayed commits to compare is not evidence of fidelity")
        self.assertTrue(report)


class TestPointBranchAtGuard(unittest.TestCase):
    """J — the `reset --hard` guard belongs in the function that runs `reset --hard`."""

    def test_refuses_the_checked_out_branch_while_the_tree_is_dirty(self):
        repo, evil = _repo_with_evil_merge()
        before = _rev(repo, "refs/heads/main")
        target = _rev(repo, f"{evil}^1")
        _write(repo, "app.js", "base\nuncommitted work\n")

        moved = amend.point_branch_at(repo, "main", target, before)

        self.assertFalse(moved)
        self.assertEqual(_rev(repo, "refs/heads/main"), before,
                         "refusing must happen BEFORE the ref moves")
        self.assertEqual((repo / "app.js").read_text(encoding="utf-8"),
                         "base\nuncommitted work\n")

    def test_refuses_while_an_untracked_file_would_be_overwritten(self):
        repo, evil = _repo_with_evil_merge()
        before = _rev(repo, "refs/heads/main")
        target = _rev(repo, f"{evil}^1")
        (repo / "side.js").write_text("untracked, and present in the target tree\n",
                                      encoding="utf-8")
        _git(repo, "rm", "-q", "--cached", "side.js")
        _git(repo, "commit", "-qm", "untrack side.js")
        head_after_untracking = _rev(repo, "refs/heads/main")

        moved = amend.point_branch_at(repo, "main", target, head_after_untracking)

        self.assertFalse(moved)
        self.assertEqual((repo / "side.js").read_text(encoding="utf-8"),
                         "untracked, and present in the target tree\n")

    def test_moves_the_checked_out_branch_when_the_tree_is_clean(self):
        repo, evil = _repo_with_evil_merge()
        before = _rev(repo, "refs/heads/main")
        target = _rev(repo, f"{evil}^1")

        moved = amend.point_branch_at(repo, "main", target, before)

        self.assertTrue(moved)
        self.assertEqual(_rev(repo, "refs/heads/main"), target)
        self.assertFalse((repo / "payload.js").exists(),
                         "the worktree follows the checked-out branch")

    def test_moves_a_branch_that_is_not_checked_out_even_with_a_dirty_tree(self):
        repo, evil = _repo_with_evil_merge()
        side_before = _rev(repo, "refs/heads/side")
        target = _rev(repo, f"{evil}^1")
        _write(repo, "app.js", "base\nuncommitted work\n")

        moved = amend.point_branch_at(repo, "side", target, side_before)

        self.assertTrue(moved, "no reset happens on a branch that is not checked out")
        self.assertEqual(_rev(repo, "refs/heads/side"), target)
        self.assertEqual((repo / "app.js").read_text(encoding="utf-8"),
                         "base\nuncommitted work\n")


if __name__ == "__main__":
    unittest.main()
