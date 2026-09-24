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

LOADER = "var _0x=String.fromCharCode(118,97,114);eval(_0x+\" x=1\");\n"


def _reads_clean(path):
    """A reader that read every file and found nothing. Takes the path. Returns False."""
    return False


def _carries_the_loader(path):
    """A reader that finds the loader. Takes the path. Returns whether the file holds it."""
    try:
        return LOADER.strip() in path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return True


class _Project(GitSandbox):
    def setUp(self):
        super().setUp()
        self.d = self.new_repo("project", user__name="Tester")
        self.write(self.d, "package-lock.json", '{"lockfileVersion": 3, "packages": {"": {}}}\n')
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

    def _clear(self, name="dist", confirms=None):
        tree = self.d / name
        reader = confirms or _reads_clean
        return installed.remove_generated(tree, self.d, _committed_under(self.d)(tree),
                                          confirms=reader)

    def _clear_unread(self, name="dist"):
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


class TestAConfirmedRunClearsAGeneratedTreeWhole(_Project):
    """Check what a confirmed run leaves in a generated directory."""

    def _run(self, keep=()):
        installed.remove_installed(self.d, confirmed=True, remove_lockfiles=False,
                                   keep=keep, committed=_committed_under(self.d))

    def test_what_the_project_commits_there_goes_too(self):
        self.commit(self.d, "commits both trees")
        (self.d / "dist" / "dropped.js").write_text("payload\n")
        self._run()
        self.assertFalse((self.d / "dist").exists())

    def test_naming_it_is_how_the_operator_keeps_it(self):
        self.commit(self.d, "commits both trees")
        self._run(keep=("dist",))
        self.assertTrue((self.d / "dist" / "artifact.js").exists())
        self.assertFalse((self.d / "build").exists())


class TestKeepingReachesEveryRemoval(_Project):
    """Check that a directory `keep_dirs` names survives whatever kind of directory it is."""

    def setUp(self):
        super().setUp()
        (self.d / installed.INSTALLED_DIR / "left-pad").mkdir(parents=True)
        (self.d / installed.INSTALLED_DIR / "left-pad" / "index.js").write_text("module.exports=1;\n")
        (self.d / "vendor").mkdir()
        (self.d / "vendor" / "package-lock.json").write_text("{}\n")

    def _remove(self, keep):
        installed.remove_installed(self.d, confirmed=True, keep=keep,
                                   committed=_committed_under(self.d))

    def test_the_installed_tree_survives_when_it_is_named(self):
        self._remove(("node_modules",))
        self.assertTrue((self.d / installed.INSTALLED_DIR / "left-pad" / "index.js").is_file())

    def test_the_installed_tree_goes_when_it_is_not(self):
        self._remove(())
        self.assertFalse((self.d / installed.INSTALLED_DIR).exists())

    def test_a_lockfile_inside_a_kept_directory_survives(self):
        self._remove(("vendor",))
        self.assertTrue((self.d / "vendor" / "package-lock.json").is_file())

    def test_a_file_inside_a_kept_directory_of_a_generated_tree_survives(self):
        (self.d / "dist" / "keep-me").mkdir()
        (self.d / "dist" / "keep-me" / "asset.js").write_text("generated\n")
        self._remove(("dist/keep-me",))
        self.assertTrue((self.d / "dist" / "keep-me" / "asset.js").is_file())
        self.assertFalse((self.d / "dist" / "artifact.js").exists())

    def test_a_directory_inside_the_installed_tree_survives_when_it_is_named(self):
        (self.d / installed.INSTALLED_DIR / "keepme").mkdir(parents=True)
        (self.d / installed.INSTALLED_DIR / "keepme" / "PRECIOUS.txt").write_text("patched\n")
        self._remove(("node_modules/keepme",))
        self.assertTrue((self.d / installed.INSTALLED_DIR / "keepme" / "PRECIOUS.txt").is_file())
        self.assertFalse((self.d / installed.INSTALLED_DIR / "left-pad").exists())

    def test_a_name_does_not_keep_the_same_name_somewhere_else(self):
        deep = self.d / "dist" / "data"
        deep.mkdir(parents=True)
        (deep / "evil.js").write_text("payload\n")
        (self.d / "data").mkdir()
        (self.d / "data" / "mine.csv").write_text("theirs\n")
        self._remove(("data",))
        self.assertTrue((self.d / "data" / "mine.csv").is_file())
        self.assertFalse((deep / "evil.js").exists(),
                         "a bare name must not keep the same name at depth")

    def test_an_entry_outside_the_repository_names_nothing(self):
        self.assertEqual([], installed.kept_paths(self.d, ("../elsewhere", "/etc", "", "..")))

    def test_an_entry_with_a_separator_names_the_path_it_spells(self):
        self.assertEqual([self.d.resolve() / "dist" / "assets"],
                         installed.kept_paths(self.d, ("dist/assets",)))

    def test_the_run_says_what_it_left_because_it_was_asked(self):
        report = installed.remove_installed(self.d, confirmed=True, keep=("vendor",),
                                            committed=_committed_under(self.d))
        self.assertIn("left in place as you asked", report.note())
        self.assertIn("vendor", report.note())


class TestACommittedFileIsOnlyKeptWhenItWasRead(_Project):
    """Check what decides that a file the project commits may stay."""

    def setUp(self):
        super().setUp()
        self.commit(self.d, "commits both trees")

    def _clear(self, confirms=None):
        tree = self.d / "dist"
        reader = confirms if confirms is not None else _carries_the_loader
        return installed.remove_generated(tree, self.d, _committed_under(self.d)(tree),
                                          confirms=reader)

    def test_a_committed_file_that_carries_the_payload_is_removed(self):
        (self.d / "dist" / "artifact.js").write_text(LOADER)
        self.commit(self.d, "commits the payload too")
        self._clear()
        self.assertFalse((self.d / "dist" / "artifact.js").exists())

    def test_a_committed_file_that_reads_clean_stays(self):
        self._clear()
        self.assertTrue((self.d / "dist" / "artifact.js").exists())

    def test_without_a_reader_the_tree_goes_whole(self):
        tree = self.d / "dist"
        installed.remove_generated(tree, self.d, _committed_under(self.d)(tree))
        self.assertFalse(tree.exists())


class TestNothingSaysABuildProducesThem(GitSandbox):
    """Check a repository where no lockfile states that its output directories are produced."""

    def setUp(self):
        super().setUp()
        self.d = self.new_repo("project", user__name="Tester")
        self.write(self.d, "setup.py", "from setuptools import setup\nsetup()\n")
        (self.d / "out").mkdir()
        (self.d / "out" / "experiment-results.csv").write_text("a,b\n1,2\n")
        (self.d / "dist").mkdir()
        (self.d / "dist" / "myproj-1.0.tar.gz").write_bytes(b"a source release\n")

    def _run(self):
        return installed.remove_installed(self.d, confirmed=True,
                                          committed=_committed_under(self.d))

    def test_the_operators_only_copy_is_left_alone(self):
        self._run()
        self.assertTrue((self.d / "out" / "experiment-results.csv").is_file())
        self.assertTrue((self.d / "dist" / "myproj-1.0.tar.gz").is_file())

    def test_the_run_says_it_left_them_and_why(self):
        note = self._run().note()
        self.assertIn("nothing here says a build produces them", note)
        self.assertIn("out", note)

    def test_a_lockfile_is_what_says_they_are_produced(self):
        self.write(self.d, "package-lock.json", '{"lockfileVersion": 3, "packages": {"": {}}}\n')
        self._run()
        self.assertFalse((self.d / "out").exists())
        self.assertFalse((self.d / "dist").exists())


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
        self.write(self.d, "package-lock.json", '{"lockfileVersion": 3, "packages": {"": {}}}\n')
        self.commit(self.d, "project and payload")
        (self.d / "dist").mkdir()
        (self.d / "dist" / "bundle.js").write_text("generated\n")

    def _fix(self):
        with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            remediator.fix(None, paths=[str(self.d)], no_stream=True)

    def test_the_generated_tree_is_removed_even_though_it_is_not_scanned(self):
        self.assertIn("dist", ScanOptions().exclude_dirs)
        self._fix()
        self.assertFalse((self.d / "dist").exists())

    def test_without_a_lockfile_it_is_left_where_it_is(self):
        self.git(self.d, "rm", "-q", "package-lock.json")
        self.commit(self.d, "no lockfile")
        self._fix()
        self.assertTrue((self.d / "dist" / "bundle.js").is_file())


if __name__ == "__main__":
    unittest.main()
