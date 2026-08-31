#!/usr/bin/env python3
"""lib.git.write — what replacing a confirmed infected commit does to content that is NOT the
payload, against REAL local git repos (no network, no mocks).

The replacement is the commit's OWN tree with the flagged paths corrected, so the rules pinned
here are about what must not move: every other path, the file modes, and the commit's message and
author. A git command exiting 0 is not evidence it changed anything, so each correction is read
back. `--rebase-merges` rebuilds a suffix merge by merging again, so a clean-but-different
re-resolution lands in a commit nobody flagged: `replay_is_faithful` has to catch it. And
`point_branch_at` runs `reset --hard` on the worktree holding the branch — any worktree — so the
uncommitted-work guard belongs in that function rather than three call layers above it.
"""
from __future__ import annotations

import shutil
import subprocess
import tempfile
import unittest
from unittest import mock
from pathlib import Path

from stayawake.lib.git.merge.tree import auto_merge
from stayawake.lib.git.query import changed_paths
from stayawake.lib.git.write import amend

_ABSENT = "0" * 40


def _git(repo: Path, *args: str) -> str:
    res = subprocess.run(["git", "-C", str(repo), *args],
                         check=True, capture_output=True, text=True)
    return res.stdout


def _git_conflicting(repo: Path, *args: str) -> None:
    """A merge that stops on a conflict exits non-zero; that is the fixture, not a failure."""
    subprocess.run(["git", "-C", str(repo), *args], capture_output=True, text=True)


def _raw_body(repo: Path, rev: str) -> bytes:
    raw = subprocess.run(["git", "-C", str(repo), "cat-file", "commit", rev],
                         capture_output=True).stdout
    return raw.partition(b"\n\n")[2]


def _author_line(repo: Path, rev: str) -> bytes:
    raw = subprocess.run(["git", "-C", str(repo), "cat-file", "commit", rev],
                         capture_output=True).stdout
    return next(ln for ln in raw.split(b"\n") if ln.startswith(b"author "))


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
    """A — the replacement must take the payload and nothing else.

    It used to rebuild the commit from its parents, which destroyed every other thing the merge
    contributed; `discarded_delta` named the casualties and the caller refused. The replacement is
    now the commit's own tree with the flagged paths corrected, so the delta is the payload alone
    and these tests pin that as an invariant rather than as a warning.
    """

    def test_the_merge_time_edit_survives_and_only_the_payload_goes(self):
        repo, evil = _repo_with_evil_merge()
        replacement = amend.replacement_commit(repo, evil, ["payload.js"])
        self.assertTrue(replacement.ok, replacement.refusal)

        dropped = amend.discarded_delta(repo, evil, replacement.sha)

        self.assertEqual(dropped, ["payload.js"])
        self.assertEqual(_git(repo, "show", f"{replacement.sha}:README.md"),
                         "readme\nnote added while merging\n",
                         "the edit made while the merge was open is not the payload")
        self.assertEqual(replacement.removed, ("payload.js",))

    def test_a_conflict_resolution_elsewhere_no_longer_blocks_the_replacement(self):
        """The shape an attacker would choose: hide the payload in a merge that plausibly needed
        a resolution. Rebuilding from the parents could not produce one at all."""
        repo = _new_repo()
        _write(repo, "f.txt", "line1\nline2\n")
        _commit(repo, "init")
        _git(repo, "checkout", "-q", "-b", "side")
        _write(repo, "f.txt", "SIDE\nline2\n")
        _commit(repo, "side")
        _git(repo, "checkout", "-q", "main")
        _write(repo, "f.txt", "MAIN\nline2\n")
        _commit(repo, "main work")
        _git_conflicting(repo, "merge", "--no-commit", "side")
        _write(repo, "f.txt", "RESOLVED BY HAND\nline2\n")
        _write(repo, "payload.js", "PAYLOAD\n")
        _git(repo, "add", "-A")
        _git(repo, "commit", "-qm", "Merge branch 'side'")
        evil = _rev(repo, "HEAD")

        replacement = amend.replacement_commit(repo, evil, ["payload.js"])

        self.assertTrue(replacement.ok, replacement.refusal)
        self.assertEqual(amend.discarded_delta(repo, evil, replacement.sha), ["payload.js"])
        self.assertEqual(_git(repo, "show", f"{replacement.sha}:f.txt"),
                         "RESOLVED BY HAND\nline2\n")

    def test_a_payload_path_git_could_not_merge_is_refused(self):
        repo = _new_repo()
        _write(repo, "shared.js", "one\n")
        _commit(repo, "init")
        _git(repo, "checkout", "-q", "-b", "side")
        _write(repo, "shared.js", "SIDE\n")
        _commit(repo, "side")
        _git(repo, "checkout", "-q", "main")
        _write(repo, "shared.js", "MAIN\n")
        _commit(repo, "main work")
        _git_conflicting(repo, "merge", "--no-commit", "side")
        _write(repo, "shared.js", "PAYLOAD\n")
        _git(repo, "add", "-A")
        _git(repo, "commit", "-qm", "Merge branch 'side'")

        replacement = amend.replacement_commit(repo, _rev(repo, "HEAD"), ["shared.js"])

        self.assertFalse(replacement.ok)
        self.assertEqual(replacement.kind, "conflicted")
        self.assertIn("shared.js", replacement.refusal)

    def test_a_deletion_the_merge_made_is_kept(self):
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
        replacement = amend.replacement_commit(repo, evil, ["payload.js"])

        dropped = amend.discarded_delta(repo, evil, replacement.sha)

        self.assertEqual(dropped, ["payload.js"])
        self.assertFalse(_git(repo, "ls-tree", "--name-only", replacement.sha, "--", "vendor.js"),
                         "the merge deleted it, and the replacement keeps that deletion")

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
        new_merge = amend.replacement_commit(repo, evil, ["payload.js"]).sha
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
        new_merge = amend.replacement_commit(repo, evil, ["payload.js"]).sha
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
        new_merge = amend.replacement_commit(repo, evil, ["payload.js"]).sha
        new_head = amend.replayed_head(repo, evil, new_merge, old_head)

        faithful, report = amend.replay_is_faithful(
            repo, old_head, new_head, evil, new_merge, ())

        self.assertFalse(faithful, "with nothing allowed, the removed payload IS a difference")
        self.assertTrue(any("payload.js" in line for line in report), report)

    def test_sequences_that_cannot_be_walked_pairwise_are_not_assumed_clean(self):
        repo, evil, old_head = _repo_with_handmade_suffix_merge()
        new_merge = amend.replacement_commit(repo, evil, ["payload.js"]).sha
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

    def test_a_reset_that_fails_puts_the_ref_back_before_refusing(self):
        """`update-ref` succeeds and `reset --hard` then fails — a held `.git/index.lock` is
        enough. Returning False with the ref already at the replacement told the caller nothing
        had moved while the branch sat on rewritten history with the old content staged, so the
        operator's next commit would put the payload back on top of the clean history."""
        repo, evil = _repo_with_evil_merge()
        before = _rev(repo, "refs/heads/main")
        target = _rev(repo, f"{evil}^1")
        (repo / ".git" / "index.lock").write_text("", encoding="utf-8")
        self.addCleanup(lambda: (repo / ".git" / "index.lock").unlink(missing_ok=True))

        moved = amend.point_branch_at(repo, "main", target, before)

        self.assertFalse(moved)
        self.assertEqual(_rev(repo, "refs/heads/main"), before,
                         "a refusal must mean the branch is where it started")

    def test_a_ref_that_cannot_be_put_back_is_raised_not_reported_as_unmoved(self):
        repo, evil = _repo_with_evil_merge()
        before = _rev(repo, "refs/heads/main")
        target = _rev(repo, f"{evil}^1")
        real = amend.run_ok

        def only_the_first_update_ref(r, args, **kw):
            if args[:1] == ["reset"]:
                return False
            if args[:1] == ["update-ref"] and args[2:3] == [before]:
                return False          # the put-back is refused too
            return real(r, args, **kw)

        with mock.patch.object(amend, "run_ok", only_the_first_update_ref):
            with self.assertRaises(amend.AmendUnwindFailed) as raised:
                amend.point_branch_at(repo, "main", target, before)
        self.assertEqual(raised.exception.unrestored, ["main"])

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


class TestEveryCheckoutIsGuarded(unittest.TestCase):
    """`git update-ref` moves a branch a LINKED worktree has checked out — it has no
    checked-out-branch protection — and that tree is then left at the old content with the
    difference STAGED, so the operator's next commit there restores the payload on top of the
    clean history. Asking `symbolic-ref HEAD` answered for one checkout and skipped the rest."""

    def _linked(self, repo: Path, branch: str) -> Path:
        wt = Path(tempfile.mkdtemp(prefix="saw-linked-")) / "wt"
        _git(repo, "worktree", "add", "-q", str(wt), branch)
        self.addCleanup(shutil.rmtree, wt.parent, True)
        return wt

    def test_uncommitted_work_in_another_worktree_refuses_the_move(self):
        repo, evil = _repo_with_evil_merge()
        _git(repo, "branch", "release")
        before = _rev(repo, "refs/heads/release")
        target = _rev(repo, f"{evil}^1")
        linked = self._linked(repo, "release")
        (linked / "WIP.txt").write_text("uncommitted\n", encoding="utf-8")

        self.assertFalse(amend.is_dirty(repo), "this tree is clean — the old guard saw only this")
        self.assertEqual(amend.checkout_holding(repo, "release").resolve(), linked.resolve())
        self.assertFalse(amend.point_branch_at(repo, "release", target, before))
        self.assertEqual(_rev(repo, "refs/heads/release"), before)
        self.assertEqual((linked / "WIP.txt").read_text(encoding="utf-8"), "uncommitted\n")

    def test_a_clean_worktree_elsewhere_is_moved_with_its_branch(self):
        repo, evil = _repo_with_evil_merge()
        _git(repo, "branch", "release")
        before = _rev(repo, "refs/heads/release")
        target = _rev(repo, f"{evil}^1")
        linked = self._linked(repo, "release")

        self.assertTrue(amend.point_branch_at(repo, "release", target, before))
        self.assertEqual(_rev(repo, "refs/heads/release"), target)
        self.assertEqual(_git(linked, "status", "--porcelain"), "",
                         "the branch moved, so its checkout has to move with it")

    def test_a_branch_no_worktree_holds_needs_no_reset(self):
        repo, evil = _repo_with_evil_merge()
        _git(repo, "branch", "unheld")
        before = _rev(repo, "refs/heads/unheld")
        self.assertIsNone(amend.checkout_holding(repo, "unheld"))
        self.assertTrue(amend.point_branch_at(repo, "unheld", _rev(repo, f"{evil}^1"), before))


class TestTheConflictSetIsPathsOnly(unittest.TestCase):
    """`merge-tree --write-tree --name-only` prints the oid, the conflicted paths, a BLANK LINE,
    and then its own messages. Reading every non-empty line as a path put `Auto-merging f.txt` and
    `CONFLICT (content): Merge conflict in f.txt` into the set — correct only by luck, because
    every message happens to carry a prefix."""

    def test_git_s_own_messages_are_not_read_as_paths(self):
        repo = _new_repo()
        _write(repo, "f.txt", "line1\nline2\n")
        _commit(repo, "init")
        _git(repo, "checkout", "-q", "-b", "side")
        _write(repo, "f.txt", "SIDE\nline2\n")
        _commit(repo, "side")
        _git(repo, "checkout", "-q", "main")
        _write(repo, "f.txt", "MAIN\nline2\n")
        _commit(repo, "main work")

        merged = auto_merge(repo, _rev(repo, "main"), _rev(repo, "side"))

        self.assertEqual(merged.conflicted, frozenset({"f.txt"}))

    def test_a_clean_merge_conflicts_on_nothing(self):
        repo, _evil = _repo_with_evil_merge()
        merged = auto_merge(repo, _rev(repo, "HEAD^1"), _rev(repo, "HEAD^2"))
        self.assertEqual(merged.conflicted, frozenset())


class TestASubmoduleIsNeverGuessedAt(unittest.TestCase):
    def test_a_flagged_gitlink_is_refused(self):
        inner = _new_repo()
        _write(inner, "a.txt", "inner\n")
        _commit(inner, "inner init")
        repo = _new_repo()
        _write(repo, "app.js", "base\n")
        _commit(repo, "init")
        _git(repo, "-c", "protocol.file.allow=always", "submodule", "--quiet", "add",
             str(inner), "vendor")
        _git(repo, "commit", "-qm", "add submodule")

        replacement = amend.replacement_commit(repo, _rev(repo, "HEAD"), ["vendor"])

        self.assertFalse(replacement.ok)
        self.assertEqual(replacement.kind, "submodule")


class TestTheModeTravelsWithTheBlob(unittest.TestCase):
    """A blob written back into an index without its mode turns an executable into a plain file
    and a symlink into a file holding its target as text — a silent change to a path the finding
    named, in the very commit meant to make that path safe."""

    def _reverted(self, repo: Path, path: str) -> str:
        replacement = amend.replacement_commit(repo, _rev(repo, "HEAD"), [path])
        self.assertTrue(replacement.ok, replacement.refusal)
        self.assertEqual(replacement.reverted, (path,))
        entry = _git(repo, "ls-tree", replacement.sha, "--", path)
        return entry.split()[0]

    def test_an_executable_stays_executable(self):
        repo = _new_repo()
        _write(repo, "run.sh", "#!/bin/sh\necho ok\n")
        _git(repo, "update-index", "--add", "--chmod=+x", "run.sh")
        _git(repo, "commit", "-qm", "init")
        _write(repo, "run.sh", "#!/bin/sh\nPAYLOAD\n")
        _commit(repo, "infected")

        self.assertEqual(self._reverted(repo, "run.sh"), "100755")

    def test_a_symlink_stays_a_symlink(self):
        repo = _new_repo()
        _write(repo, "real.txt", "real\n")
        (repo / "link").symlink_to("real.txt")
        _git(repo, "add", "-A")
        _git(repo, "commit", "-qm", "init")
        (repo / "link").unlink()
        _write(repo, "link", "PAYLOAD\n")
        _commit(repo, "infected")

        self.assertEqual(self._reverted(repo, "link"), "120000")


class TestTheCorrectionIsReadBack(unittest.TestCase):
    """A git command exiting 0 is not evidence it changed anything. `update-index --force-remove`
    on a path that is not in the index succeeds and removes nothing, so any path spelling git
    does not match produced a tree identical to the recorded one and was reported as removed."""

    def test_a_directory_is_not_reported_as_removed(self):
        repo = _new_repo()
        _write(repo, "app.js", "base\n")
        _commit(repo, "init")
        _write(repo, "node_modules/bad/index.js", "PAYLOAD\n")
        _commit(repo, "infected")

        replacement = amend.replacement_commit(repo, _rev(repo, "HEAD"), ["node_modules/bad"])

        self.assertFalse(replacement.ok)
        self.assertEqual(replacement.kind, "not-applied")

    def test_a_path_git_quotes_is_carried_through_and_actually_corrected(self):
        """`diff --name-only` without `-z` returns a C-quoted spelling for such a path, which
        matches nothing when looked up — so it read as "introduced here" and was "removed" from a
        tree it was never found in."""
        repo = _new_repo()
        _write(repo, 'we"ird.js', "ok\n")
        _commit(repo, "init")
        _write(repo, 'we"ird.js', "ok\nPAYLOAD\n")
        _commit(repo, "infected")
        head = _rev(repo, "HEAD")

        flagged = changed_paths(repo, head + "^", head, diff_filter="AM")
        self.assertEqual(flagged, {'we"ird.js'}, "the name must survive unquoted")

        replacement = amend.replacement_commit(repo, head, sorted(flagged))

        self.assertTrue(replacement.ok, replacement.refusal)
        self.assertEqual(_git(repo, "show", f'{replacement.sha}:we"ird.js'), "ok\n")


class TestTheBaselineIsJudgedNotNominated(unittest.TestCase):
    def test_a_payload_that_predates_the_commit_is_refused(self):
        """Reverting a path restores whatever the baseline holds. When the payload was already
        there, that is not a fix — and replacing this commit would report one."""
        repo = _new_repo()
        _write(repo, "x.js", "a\n")
        _commit(repo, "init")
        _write(repo, "x.js", "a\nPAYLOAD\n")
        _commit(repo, "infected")

        replacement = amend.replacement_commit(
            repo, _rev(repo, "HEAD"), ["x.js"],
            still_carries=lambda text: "payload" if "PAYLOAD" in text else None)

        self.assertTrue(replacement.ok, "the parent here is clean")

        _write(repo, "x.js", "a\nPAYLOAD\nPAYLOAD\n")
        _commit(repo, "more of it")

        second = amend.replacement_commit(
            repo, _rev(repo, "HEAD"), ["x.js"],
            still_carries=lambda text: "payload" if "PAYLOAD" in text else None)

        self.assertFalse(second.ok)
        self.assertEqual(second.kind, "baseline-carries-payload")


class TestTheCommitItselfIsReproduced(unittest.TestCase):
    def _infected(self) -> tuple[Path, str]:
        repo = _new_repo()
        _write(repo, "a.txt", "base\n")
        _commit(repo, "init")
        _write(repo, "evil.js", "PAYLOAD\n")
        _git(repo, "add", "-A")
        return repo, "evil.js"

    def test_the_message_is_byte_identical(self):
        repo, path = self._infected()
        subprocess.run(["git", "-C", str(repo), "commit", "-q", "-F", "-"],
                       input=b"subject\n\nbody with trailing spaces   \nno final newline",
                       check=True, capture_output=True)
        head = _rev(repo, "HEAD")
        before = _raw_body(repo, head)

        replacement = amend.replacement_commit(repo, head, [path])

        self.assertTrue(replacement.ok, replacement.refusal)
        self.assertEqual(_raw_body(repo, replacement.sha), before)

    def test_an_empty_author_email_is_not_filled_in_with_the_operator(self):
        repo, path = self._infected()
        _git(repo, "commit", "-qm", "empty email", "--author=Bot Account <>")
        head = _rev(repo, "HEAD")
        before = _author_line(repo, head)

        replacement = amend.replacement_commit(repo, head, [path])

        self.assertTrue(replacement.ok, replacement.refusal)
        self.assertEqual(_author_line(repo, replacement.sha), before)
        self.assertIn(b"<>", before)

    def test_a_message_a_replacement_cannot_reproduce_is_refused(self):
        """Built with `fast-import` because `git commit` will not make one: it converts the
        message to UTF-8 on the way in. Histories imported from cvs, svn or hg carry legacy
        encodings exactly this way, and MEASURED, `commit-tree` re-encodes such a message from
        the LOCALE — so the replacement would differ by the machine that produced it."""
        repo = _new_repo()
        legacy = "Café für Müller\n".encode("latin-1")
        stream = (
            b"blob\nmark :1\ndata 6\nhello\n"
            b"commit refs/heads/legacy\nmark :2\n"
            b"author A <a@b.c> 1200000000 +0100\ncommitter A <a@b.c> 1200000000 +0100\n"
            b"data 5\nbase\nM 100644 :1 a.txt\n"
            b"blob\nmark :3\ndata 8\npayload\n"
            b"commit refs/heads/legacy\nmark :4\n"
            b"author A <a@b.c> 1200000100 +0100\ncommitter A <a@b.c> 1200000100 +0100\n"
            b"data " + str(len(legacy)).encode() + b"\n" + legacy
            + b"\nM 100644 :3 evil.js\n")
        subprocess.run(["git", "-C", str(repo), "fast-import", "--quiet"],
                       input=stream, check=True, capture_output=True)
        _git(repo, "reset", "-q", "--hard", "legacy")
        self.assertNotIn(b"\xef\xbf\xbd", _raw_body(repo, _rev(repo, "HEAD")),
                         "the fixture must really hold non-UTF-8 bytes")

        replacement = amend.replacement_commit(repo, _rev(repo, "HEAD"), ["evil.js"])

        self.assertFalse(replacement.ok)
        self.assertEqual(replacement.kind, "message-encoding")


if __name__ == "__main__":
    unittest.main()
