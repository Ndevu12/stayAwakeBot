#!/usr/bin/env python3
"""What a removal takes, against what `saw fix` documents it takes."""
from __future__ import annotations

import io
import unittest
from contextlib import redirect_stderr, redirect_stdout

from stayawake.bots.security import remediator
from stayawake.bots.security.pr.fix import _committed_under
from stayawake.bots.security.remediator import _options
from stayawake.bots.security.remediation import installed
from stayawake.bots.security.targets.base import ScanOptions
from tests.support.gitrepo import GitSandbox


class _Project(GitSandbox):
    def setUp(self):
        super().setUp()
        self.d = self.new_repo("project", user__name="Tester")
        for name in ("dist", "build"):
            (self.d / name).mkdir()
            (self.d / name / "artifact.js").write_text("generated\n")

    def _names(self, **kw):
        return sorted(p.name for p in installed.build_output_dirs(self.d, **kw))


class TestADirectoryTheOperatorAskedToKeep(_Project):
    """Check what `keep_dirs` does to the collection."""

    def test_a_kept_tree_is_not_collected(self):
        self.assertNotIn("dist", self._names(keep={"dist"}))

    def test_the_others_are_still_collected(self):
        self.assertIn("build", self._names(keep={"dist"}))

    def test_keeping_nothing_collects_both(self):
        self.assertEqual(["build", "dist"], self._names())


class TestNotScannedIsNotTheSameAsNotRemoved(_Project):
    """Check what the scan exclusions do to the collection."""

    def test_the_default_exclusions_do_not_stop_a_removal(self):
        opts = ScanOptions()
        self.assertTrue({"dist", "build"} <= opts.exclude_dirs)
        self.assertEqual(["build", "dist"], self._names(keep=opts.keep_dirs))

    def test_nothing_is_kept_by_default(self):
        self.assertEqual(set(), ScanOptions().keep_dirs)


class TestWhatTheProjectCommitsIsKept(_Project):
    """Check what survives inside a generated tree the project partly commits."""

    def _clear(self, name="dist"):
        tree = self.d / name
        return installed.remove_generated(tree, self.d, _committed_under(self.d)(tree))

    def test_a_wholly_generated_tree_goes(self):
        self.assertTrue(self._clear())
        self.assertFalse((self.d / "dist").exists())

    def test_a_committed_file_survives(self):
        self.commit(self.d, "commits both trees")
        self._clear()
        self.assertTrue((self.d / "dist" / "artifact.js").exists())

    def test_an_untracked_file_beside_a_committed_one_is_still_removed(self):
        self.commit(self.d, "commits both trees")
        (self.d / "dist" / "dropped.js").write_text("payload\n")
        self._clear()
        self.assertFalse((self.d / "dist" / "dropped.js").exists())
        self.assertTrue((self.d / "dist" / "artifact.js").exists())

    def test_a_nested_untracked_file_is_removed_too(self):
        self.commit(self.d, "commits both trees")
        (self.d / "dist" / "sub").mkdir()
        (self.d / "dist" / "sub" / "dropped.js").write_text("payload\n")
        self._clear()
        self.assertFalse((self.d / "dist" / "sub" / "dropped.js").exists())

    def test_a_directory_holding_a_committed_file_survives(self):
        (self.d / "dist" / "keepme").mkdir()
        (self.d / "dist" / "keepme" / "tracked.js").write_text("mine\n")
        self.commit(self.d, "commits a nested file under dist")
        (self.d / "dist" / "keepme" / "dropped.js").write_text("payload\n")
        self._clear()
        self.assertTrue((self.d / "dist" / "keepme" / "tracked.js").exists())
        self.assertFalse((self.d / "dist" / "keepme" / "dropped.js").exists())

    def test_a_path_outside_the_repository_is_answered_as_tracked(self):
        self.assertEqual([str(self.root / "elsewhere")],
                         _committed_under(self.d)(self.root / "elsewhere"))


class TestTheCheckItself(_Project):
    def test_it_sees_a_tracked_tree(self):
        self.commit(self.d, "commits both")
        self.assertTrue(_committed_under(self.d)(self.d / "dist"))

    def test_it_does_not_see_an_untracked_tree(self):
        self.assertFalse(_committed_under(self.d)(self.d / "dist"))

    def test_a_path_outside_the_repository_is_treated_as_committed(self):
        self.assertTrue(_committed_under(self.d)(self.root / "elsewhere"))


class TestARunKeepsWhatTheProjectCommits(_Project):
    """Check what a removal run leaves, through the lane that calls it."""

    def test_it_clears_the_untracked_and_keeps_the_committed(self):
        self.commit(self.d, "commits both trees")
        (self.d / "dist" / "dropped.js").write_text("payload\n")
        installed.remove_installed(self.d, confirmed=True, remove_lockfiles=False,
                                   keep=(), committed=_committed_under(self.d))
        self.assertFalse((self.d / "dist" / "dropped.js").exists())
        self.assertTrue((self.d / "dist" / "artifact.js").exists())


class TestTheSettingReachesTheDecision(unittest.TestCase):
    def test_the_config_key_is_read(self):
        opts = _options({"keep_dirs": ["out"]})
        self.assertEqual({"out"}, opts.keep_dirs)

    def test_nothing_is_kept_when_the_key_is_absent(self):
        self.assertEqual(set(), _options({}).keep_dirs)

    def test_the_scan_exclusions_are_read_separately(self):
        opts = _options({"exclude_dirs": ["dist"], "keep_dirs": ["out"]})
        self.assertEqual({"dist"}, opts.exclude_dirs)
        self.assertEqual({"out"}, opts.keep_dirs)


class TestARunStillClearsAnExcludedBuildTree(GitSandbox):
    """Check what a run does to a generated tree the scan skips."""

    def setUp(self):
        super().setUp()
        self.d = self.new_repo("project", user__name="Tester")
        (self.d / "public" / "fonts").mkdir(parents=True)
        (self.d / "public" / "fonts" / "text.woff").write_text(
            "var _0x=String.fromCharCode(118,97,114);eval(_0x+\" x=1\");\n")
        self.commit(self.d, "project and payload")
        (self.d / "dist").mkdir()
        (self.d / "dist" / "bundle.js").write_text("generated\n")

    def test_the_generated_tree_is_removed_even_though_it_is_not_scanned(self):
        self.assertIn("dist", ScanOptions().exclude_dirs)
        with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            remediator.fix(None, paths=[str(self.d)], no_stream=True)
        self.assertFalse((self.d / "dist").exists())


if __name__ == "__main__":
    unittest.main()
