#!/usr/bin/env python3
"""One root per run, its release, and what survives it."""
from __future__ import annotations

import os
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from stayawake.utils import scratch


class _OwnTempRoot(unittest.TestCase):
    """Every case runs against a temp root the test owns."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="scratch-test-")).resolve()
        self.addCleanup(shutil.rmtree, self.tmp, True)
        isolated = mock.patch.dict(os.environ, {"TMPDIR": str(self.tmp)})
        isolated.start()
        self.addCleanup(isolated.stop)
        tempfile.tempdir = None
        self.addCleanup(setattr, tempfile, "tempdir", None)
        scratch._root = None
        scratch._areas.clear()
        self.addCleanup(scratch._areas.clear)

    def _roots(self):
        return [p for p in self.tmp.iterdir() if p.name.startswith(scratch.ROOT_PREFIX)]


class TestOneRootHoldsTheRun(_OwnTempRoot):
    """Check that everything a run makes sits under a single root."""

    def test_every_area_is_under_one_root(self):
        made = [scratch.new_dir("the fix worktree"), scratch.new_dir("rollback"),
                scratch.new_dir("the clone"), scratch.new_file("askpass")]
        self.assertEqual(1, len(self._roots()))
        for path in made:
            self.assertEqual(scratch.root(), path.parent.parent)

    def test_the_root_records_what_the_run_is(self):
        import json
        scratch.new_dir("rollback")
        record = json.loads((scratch.root() / scratch.RECORD).read_text())
        self.assertEqual(os.getpid(), record["pid"])
        self.assertEqual(os.getuid(), record["uid"])
        self.assertEqual(str(self.tmp), record["tmp_root"])

    def test_an_area_is_named_for_what_it_is_for(self):
        self.assertEqual("the-fix-worktree", scratch.new_dir("the fix worktree").parent.name)

    def test_the_root_is_private_to_its_owner(self):
        self.assertEqual(0o700, scratch.root().stat().st_mode & 0o777)

    def test_a_file_is_readable_only_by_its_owner(self):
        self.assertEqual(0o600, scratch.new_file("askpass").stat().st_mode & 0o777)

    def test_it_reports_what_it_still_holds(self):
        scratch.new_dir("the clone")
        scratch.new_dir("rollback")
        self.assertEqual(["rollback", "the clone"], [a.purpose for a in scratch.held()])


class TestReleaseTakesTheRunWithIt(_OwnTempRoot):
    """Check what release removes and what it leaves."""

    def test_it_removes_everything_the_run_made(self):
        made = [scratch.new_dir("the clone"), scratch.new_dir("rollback")]
        (made[1] / "original.txt").write_text("bytes")
        self.assertEqual([], scratch.release())
        self.assertFalse(any(p.exists() for p in made))
        self.assertEqual([], self._roots())

    def test_it_removes_a_directory_that_denies_it(self):
        area = scratch.new_dir("the clone")
        (area / "sub").mkdir()
        (area / "sub" / "f.txt").write_text("x")
        os.chmod(area / "sub", 0o500)
        self.assertEqual([], scratch.release())
        self.assertEqual([], self._roots())

    def test_it_holds_nothing_afterwards(self):
        scratch.new_dir("rollback")
        scratch.release()
        self.assertEqual([], scratch.held())

    def test_releasing_twice_is_not_an_error(self):
        scratch.new_dir("rollback")
        scratch.release()
        self.assertEqual([], scratch.release())


class TestWhatTheOperatorWasGivenSurvives(_OwnTempRoot):
    """Check that output handed to the operator outlives the run that made it."""

    def test_a_kept_area_survives_release(self):
        report = scratch.kept_dir("report")
        (report / "latest.md").write_text("# report")
        scratch.release()
        self.assertEqual("# report", (report / "latest.md").read_text())

    def test_the_root_survives_while_it_holds_one(self):
        scratch.kept_dir("report")
        scratch.release()
        self.assertEqual(1, len(self._roots()))

    def test_the_root_goes_when_nothing_was_kept(self):
        scratch.new_dir("rollback")
        scratch.release()
        self.assertEqual([], self._roots())


class TestATeardownThatFailsIsReported(_OwnTempRoot):
    """Check what a failure to release reports."""

    def test_the_reason_names_the_purpose_and_the_path(self):
        area = scratch.new_dir("the fix worktree", teardown=lambda p: "git would not remove it")
        reasons = scratch.release()
        self.assertEqual(1, len(reasons))
        self.assertIn("the fix worktree", reasons[0])
        self.assertIn(str(area), reasons[0])
        self.assertIn("git would not remove it", reasons[0])

    def test_a_teardown_that_succeeds_reports_nothing(self):
        seen = []
        scratch.new_dir("the fix worktree", teardown=lambda p: seen.append(p) or "")
        self.assertEqual([], scratch.release())
        self.assertEqual(1, len(seen))

    def test_a_teardown_runs_before_the_directory_is_removed(self):
        present = []
        scratch.new_dir("the fix worktree", teardown=lambda p: present.append(p.exists()) or "")
        scratch.release()
        self.assertEqual([True], present)


if __name__ == "__main__":
    unittest.main()
