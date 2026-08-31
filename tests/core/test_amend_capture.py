#!/usr/bin/env python3
"""lib.git.write.capture — the evidence a history rewrite is about to destroy, exercised
against REAL local git repositories that are really rewritten and really garbage-collected.

The defect these pin: the previous capture recorded blob OIDs in `.git/`. OIDs are POINTERS, so
one `git gc` pruned everything they pointed at and the evidence base vanished; and `.git/` is
neither cloned nor looked in. So the bar here is not "a file was written" — it is that after the
old commits have been pruned out of the source repository, the captured bundle still restores
them, byte for byte, into a fresh clone.
"""
from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from stayawake.lib.git.write import capture as capture_mod
from stayawake.lib.git.write.capture import BundleResult, capture_bundle

_HERMETIC = dict(
    os.environ,
    GIT_CONFIG_GLOBAL="/dev/null",
    GIT_CONFIG_NOSYSTEM="1",
    GIT_TERMINAL_PROMPT="0",
    GIT_AUTHOR_NAME="t", GIT_AUTHOR_EMAIL="t@t",
    GIT_COMMITTER_NAME="t", GIT_COMMITTER_EMAIL="t@t",
)

_CAPTURE_REFSPEC = "refs/saw-capture/*:refs/saw-capture/*"


def _git(repo: Path | None, *args: str) -> subprocess.CompletedProcess:
    """Run git for the FIXTURE (never through the module under test), with the operator's own
    global config out of the way — a scan-on-clone hook or a signing requirement inherited from
    the developer's machine would otherwise decide whether these tests pass."""
    argv = ["git", *(["-C", str(repo)] if repo else []), "-c", "commit.gpgsign=false", *args]
    return subprocess.run(argv, capture_output=True, text=True, env=_HERMETIC, check=False)


def _sha(repo: Path, rev: str) -> str:
    return _git(repo, "rev-parse", rev).stdout.strip()


def _has_object(repo: Path, oid: str) -> bool:
    return _git(repo, "cat-file", "-e", oid).returncode == 0


def _count_objects(repo: Path, *revs: str) -> int:
    return int(_git(repo, "rev-list", "--objects", "--count", *revs).stdout.strip())


class _Rewrite:
    """A repository with `base → payload → after` on `main`, plus the replayed tip that drops
    `payload`. Refs have NOT moved yet: capture runs at exactly this moment in the real flow."""

    def __init__(self, root: Path):
        self.repo = root
        _git(root, "init", "-q", "-b", "main", ".")
        for name, content, message in (("a.txt", "base\n", "base"),
                                       ("payload.js", "PAYLOAD\n", "add payload"),
                                       ("c.txt", "after\n", "after")):
            (root / name).write_text(content, encoding="utf-8")
            _git(root, "add", "-A")
            _git(root, "commit", "-qm", message)
        self.base = _sha(root, "main~2")
        self.payload = _sha(root, "main~1")
        self.old_tip = _sha(root, "main")
        self.payload_blob = _git(root, "rev-parse", f"{self.payload}:payload.js").stdout.strip()
        self.whole_history_objects = _count_objects(root, self.old_tip)

        _git(root, "branch", "replay", "main")
        _git(root, "checkout", "-q", "replay")
        _git(root, "rebase", "-q", "--onto", self.base, self.payload, "replay")
        _git(root, "checkout", "-q", "main")
        self.new_tip = _sha(root, "replay")

    def apply(self) -> None:
        """Move `main` onto the replayed tip and collect what that orphans, so the old commits
        are genuinely gone from this repository — not merely unreferenced."""
        _git(self.repo, "update-ref", "refs/heads/main", self.new_tip, self.old_tip)
        # The INDEX is a reachability root: without this the payload BLOB survives the prune
        # even though its commit and tree are gone, and the fixture would prove less than it
        # claims. The production path resets the worktree for the checked-out branch too.
        _git(self.repo, "reset", "--hard", "-q", "HEAD")
        _git(self.repo, "branch", "-D", "replay")
        _git(self.repo, "reflog", "expire", "--expire=now", "--all")
        _git(self.repo, "gc", "-q", "--prune=now")


class _CaptureCase(unittest.TestCase):
    def setUp(self):
        self.workspace = Path(tempfile.mkdtemp(prefix="saw-capture-test-"))
        self.addCleanup(shutil.rmtree, self.workspace, ignore_errors=True)
        repo = self.workspace / "repo"
        repo.mkdir()
        self.fixture = _Rewrite(repo)
        self.repo = repo
        self.destination = self.workspace / "evidence" / "orphaned.bundle"

    def capture(self) -> BundleResult:
        return capture_bundle(self.repo, [(self.fixture.old_tip, self.fixture.new_tip)],
                              self.destination)

    def fresh_clone(self) -> Path:
        clone = self.workspace / f"clone-{os.urandom(4).hex()}"
        _git(None, "clone", "-q", str(self.repo), str(clone))
        return clone


class TestRestoresWhatTheRewriteDestroyed(_CaptureCase):
    def test_pruned_commits_come_back_into_a_fresh_clone(self):
        result = self.capture()
        self.assertTrue(result.ok, result.reason)
        self.assertTrue(result.verified, "a bundle git could not read back is not evidence")
        self.assertIsNotNone(result.path)
        self.assertTrue(result.path.is_file())

        self.fixture.apply()
        # The whole point: after the rewrite the source repo cannot answer for these objects.
        self.assertFalse(_has_object(self.repo, self.fixture.old_tip))
        self.assertFalse(_has_object(self.repo, self.fixture.payload))
        self.assertFalse(_has_object(self.repo, self.fixture.payload_blob))

        clone = self.fresh_clone()
        self.assertFalse(_has_object(clone, self.fixture.payload),
                         "fixture is wrong if the clone already has the payload commit")

        fetched = _git(clone, "fetch", str(result.path), _CAPTURE_REFSPEC)
        self.assertEqual(fetched.returncode, 0, fetched.stderr)
        self.assertTrue(_has_object(clone, self.fixture.old_tip))
        self.assertTrue(_has_object(clone, self.fixture.payload))
        restored = _git(clone, "show", f"{self.fixture.payload}:payload.js").stdout
        self.assertEqual(restored, "PAYLOAD\n", "the objects themselves must survive, not OIDs")

    def test_capture_names_the_orphaned_tip_in_the_bundle(self):
        result = self.capture()
        heads = _git(None, "bundle", "list-heads", str(result.path)).stdout
        self.assertIn(self.fixture.old_tip, heads)
        self.assertIn(capture_mod.CAPTURE_REF_PREFIX, heads)


class TestCapturesTheRangeNotTheHistory(_CaptureCase):
    def test_counts_cover_only_what_the_rewrite_orphans(self):
        result = self.capture()
        self.assertEqual(result.commits, 2, "only the payload commit and the tip are orphaned")
        self.assertEqual(
            result.objects,
            _count_objects(self.repo, self.fixture.old_tip, "--not", self.fixture.new_tip))
        self.assertLess(result.objects, self.fixture.whole_history_objects,
                        "a capture the size of the whole history is not a range")

    def test_bundle_records_the_surviving_history_as_a_prerequisite(self):
        # Reads the written FILE, not our counters: a bundle of the whole history would carry
        # no prerequisite and would happily unbundle into an empty repository. This one must
        # not — that refusal is the proof the capture stopped at the range boundary.
        result = self.capture()
        empty = self.workspace / "empty"
        empty.mkdir()
        _git(empty, "init", "-q", ".")
        fetched = _git(empty, "fetch", str(result.path), _CAPTURE_REFSPEC)
        self.assertNotEqual(fetched.returncode, 0)
        self.assertIn("prerequisite", fetched.stderr.lower())
        self.assertFalse(_has_object(empty, self.fixture.base))


class TestEmptyCaptureIsNotAFailure(_CaptureCase):
    def test_no_pairs_captures_nothing_and_still_succeeds(self):
        result = capture_bundle(self.repo, [], self.destination)
        self.assertEqual(result, BundleResult(None, False, 0, 0, ""))
        self.assertTrue(result.ok)
        self.assertFalse(self.destination.exists())

    def test_a_pair_that_orphans_nothing_captures_nothing(self):
        result = capture_bundle(self.repo, [(self.fixture.base, self.fixture.new_tip)],
                                self.destination)
        self.assertTrue(result.ok, result.reason)
        self.assertIsNone(result.path)
        self.assertEqual(result.commits, 0)
        self.assertFalse(self.destination.exists())


class TestFailuresAreReturnedNotRaised(_CaptureCase):
    def test_a_bundle_that_does_not_read_back_is_a_failure(self):
        # The pin on verification: git writes the file, then rejects it on read-back. Without a
        # `git bundle verify` step this returns a happy result over unusable evidence.
        real_run = capture_mod.run

        def reject_on_verify(repo, args, **kwargs):
            if args[:2] == ["bundle", "verify"]:
                return subprocess.CompletedProcess(
                    args, 1, "", "error: does not look like a v2 or v3 bundle file\n")
            return real_run(repo, args, **kwargs)

        with mock.patch.object(capture_mod, "run", side_effect=reject_on_verify):
            result = self.capture()
        self.assertFalse(result.verified)
        self.assertFalse(result.ok)
        self.assertIn("did not read back", result.reason)
        self.assertEqual(result.path, self.destination, "keep the file for the operator to look at")

    def test_git_that_cannot_run_is_reported(self):
        with mock.patch.object(capture_mod, "run", return_value=None):
            result = self.capture()
        self.assertFalse(result.ok)
        self.assertTrue(result.reason)
        self.assertIsNone(result.path)

    def test_a_destination_that_cannot_be_written_is_reported(self):
        occupied = self.workspace / "occupied"
        occupied.mkdir()
        result = capture_bundle(self.repo, [(self.fixture.old_tip, self.fixture.new_tip)],
                                occupied)
        self.assertFalse(result.ok)
        self.assertIn("could not be written", result.reason)
        self.assertIsNone(result.path)
        self.assertEqual(result.commits, 2, "the range was still measured")

    def test_a_destination_whose_parent_cannot_exist_is_reported(self):
        blocking_file = self.workspace / "not-a-directory"
        blocking_file.write_text("x", encoding="utf-8")
        result = capture_bundle(self.repo, [(self.fixture.old_tip, self.fixture.new_tip)],
                                blocking_file / "under" / "x.bundle")
        self.assertFalse(result.ok)
        self.assertIn("destination could not be created", result.reason)
        self.assertIsNone(result.path)

    def test_a_path_that_is_not_a_repository_is_reported(self):
        outside = self.workspace / "outside"
        outside.mkdir()
        result = capture_bundle(outside, [(self.fixture.old_tip, self.fixture.new_tip)],
                                self.destination)
        self.assertFalse(result.ok)
        self.assertTrue(result.reason)
        self.assertFalse(self.destination.exists())

    def test_a_missing_new_tip_is_refused_rather_than_bundling_everything(self):
        result = capture_bundle(self.repo, [(self.fixture.old_tip, "")], self.destination)
        self.assertFalse(result.ok)
        self.assertIn("whole history", result.reason)
        self.assertFalse(self.destination.exists())


class TestCaptureLeavesTheRepositoryAlone(_CaptureCase):
    def test_no_ref_and_no_dot_git_state_is_added(self):
        before = _git(self.repo, "for-each-ref", "--format=%(refname) %(objectname)").stdout
        result = self.capture()
        self.assertTrue(result.ok, result.reason)
        after = _git(self.repo, "for-each-ref", "--format=%(refname) %(objectname)").stdout
        self.assertEqual(before, after,
                         "a capture ref left in the repo would keep the old tip reachable and "
                         "the rewrite would then orphan nothing")
        self.assertNotIn("saw-capture", after)
        self.assertFalse((self.repo / ".git" / "saw-amend").exists())
        self.assertEqual(result.path.parent, self.destination.parent,
                         "evidence belongs at the caller's destination, not inside .git")


if __name__ == "__main__":
    unittest.main()
