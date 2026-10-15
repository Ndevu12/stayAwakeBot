#!/usr/bin/env python3
"""Removing an installed dependency tree."""
from __future__ import annotations

import contextlib
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from stayawake.bots.security.models import ROLLBACK_DIR
from stayawake.bots.security.remediation import installed


def _loader() -> str:
    charcode = "from" + "CharCode"
    run = "ev" + "al"
    return f"const x = String.{charcode}(127); {run}(x);"


class _Repo:
    def __init__(self, *, infected: bool = True, lockfile: bool = True):
        self.root = Path(tempfile.mkdtemp())
        (self.root / "package.json").write_text(json.dumps(
            {"name": "app", "version": "1.0.0", "dependencies": {"left-pad": "1.0.0"}}),
            encoding="utf-8")
        if lockfile:
            self.lock = self.root / "package-lock.json"
            self.lock.write_text(json.dumps({"lockfileVersion": 3, "packages": {
                "": {}, "node_modules/left-pad": {"version": "1.0.0"}}}), encoding="utf-8")
        (self.root / "index.js").write_text(_loader() if infected else "module.exports = 1;\n",
                                            encoding="utf-8")

    def install(self, name: str, version: str | None) -> Path:
        package = self.root / installed.INSTALLED_DIR / name
        package.mkdir(parents=True)
        manifest = {"name": name}
        if version:
            manifest["version"] = version
        (package / "package.json").write_text(json.dumps(manifest), encoding="utf-8")
        (package / "index.js").write_text("module.exports = 1;\n", encoding="utf-8")
        return package


def _prepare_fix_against(scans, spy, extra=(), live=None):
    """Drive `saw fix` far enough that the CONFIRMED gate either fires or does not.

    Takes the scans the fix worktree is read with, the remover to call in place of the real one,
    extra patches, and the scan the operator's own checkout is read with — the first of `scans`
    when none is given.
    """
    from stayawake.bots.security import pr
    from stayawake.bots.security.models import ScanResult
    from stayawake.lib.git.write.commit import CommitResult

    idle = ScanResult("owner/repo", "local", [])
    checkout_reads = live if live is not None else (scans[0] if scans else idle)
    real_clean_checkout = pr.fix.live.clean_checkout

    def clean_checkout(repo, opts, signatures, allowlist, **kw):
        kw["scan"] = lambda *a, **k: checkout_reads
        return real_clean_checkout(repo, opts, signatures, allowlist, **kw)

    patches = [
        mock.patch.object(pr.fix.live, "clean_checkout", clean_checkout),
        mock.patch.object(pr.fix.live.preserve, "can_hold", return_value=""),
        mock.patch.object(pr.fix.live.preserve, "uncommitted", return_value=[]),
        mock.patch.object(pr.gitutil, "origin_slug", return_value=None),
        mock.patch.object(pr.gitutil, "default_branch", return_value="main"),
        mock.patch.object(pr.gitutil, "ref_exists", return_value=True),
        mock.patch.object(pr.gitutil, "ancestry", return_value=True),
        mock.patch.object(pr.gitutil, "add_worktree", return_value=True),
        mock.patch.object(pr.gitutil, "remove_worktree", return_value=True),
        mock.patch.object(pr.gitutil, "unstage_cached", return_value=True),
        mock.patch.object(pr.gitutil, "tracked_under", return_value=[]),
        mock.patch.object(pr.gitutil, "stage_all", return_value=True),
        mock.patch.object(pr.gitutil, "commit_fix",
                          return_value=CommitResult(committed=True, signed=True)),
        mock.patch.object(pr.fix, "choose_fix_branch", return_value="security/auto-clean-main"),
        mock.patch.object(pr.fix, "scan_target",
                          side_effect=lambda *a, **k: scans.pop(0) if scans else idle),
        mock.patch.object(pr.remediation, "plan", return_value=[]),
        mock.patch.object(pr.remediation, "apply", return_value=[]),
        mock.patch.object(pr.fix.installed, "remove_installed", spy),
        *extra,
    ]
    with contextlib.ExitStack() as stack:
        for patch in patches:
            stack.enter_context(patch)
        pr.prepare_fix(Path("/repo"), object(), {}, [])


class TestAConfirmedInfectionLeavesNoDerivedState(unittest.TestCase):
    """A confirmed infection deletes what can be rebuilt, and copies none of it."""

    def _repo(self):
        repo = _Repo()
        (repo.root / "package.json").write_text(json.dumps(
            {"name": "app", "version": "1.0.0", "workspaces": ["packages/*"]}), encoding="utf-8")
        return repo

    def test_a_store_of_links_and_what_sits_beside_it_all_go(self):
        repo = self._repo()
        nm = repo.root / installed.INSTALLED_DIR
        real = nm / ".pnpm" / "left-pad@1.0.0" / installed.INSTALLED_DIR / "left-pad"
        real.mkdir(parents=True)
        (real / "package.json").write_text(json.dumps({"name": "left-pad", "version": "1.0.0"}),
                                           encoding="utf-8")
        (nm / "left-pad").symlink_to(real)
        (nm / ".bin").mkdir()
        (nm / ".bin" / "worm").write_text("#!/bin/sh\n", encoding="utf-8")
        (nm / "loose.js").write_text("module.exports = 1;\n", encoding="utf-8")
        report = installed.remove_confirmed(repo.root, remove_lockfiles=False)
        self.assertFalse(nm.exists())
        self.assertEqual(report.removed_trees, 1)

    def test_a_workspace_keeps_none_of_its_own(self):
        repo = self._repo()
        repo.install("left-pad", "1.0.0")
        ws = repo.root / "packages" / "app"
        (ws / installed.INSTALLED_DIR / "evil-dep").mkdir(parents=True)
        (ws / "package.json").write_text(json.dumps({"name": "w"}), encoding="utf-8")
        report = installed.remove_confirmed(repo.root, remove_lockfiles=False)
        self.assertFalse((ws / installed.INSTALLED_DIR).exists())
        self.assertEqual(report.removed_trees, 2)

    def test_a_tree_under_a_checkout_nested_in_this_one_goes_too(self):
        # Whatever installed it can install it again; what runs on the next require is what counts.
        repo = self._repo()
        repo.install("left-pad", "1.0.0")
        other = repo.root / "packages" / "vendored"
        (other / ".git").mkdir(parents=True)
        (other / "package.json").write_text(json.dumps({"name": "other"}), encoding="utf-8")
        (other / installed.INSTALLED_DIR / "keep-me").mkdir(parents=True)
        installed.remove_confirmed(repo.root, remove_lockfiles=False)
        self.assertFalse((other / installed.INSTALLED_DIR).exists())
        self.assertTrue((other / ".git").is_dir(), "another checkout's git directory was removed")

    def test_a_tree_the_manifest_never_mentions_goes_too(self):
        repo = self._repo()
        buried = repo.root / "tools" / "scripts" / installed.INSTALLED_DIR / "evil-dep"
        buried.mkdir(parents=True)
        report = installed.remove_confirmed(repo.root, remove_lockfiles=False)
        self.assertFalse(buried.parent.exists())
        self.assertEqual(report.removed_trees, 1)

    def test_a_resolver_that_needs_no_installed_tree_loses_its_cache(self):
        repo = self._repo()
        cache = repo.root / ".yarn" / "cache"
        cache.mkdir(parents=True)
        (cache / "left-pad-npm-1.0.0.zip").write_bytes(b"PK\x03\x04")
        (repo.root / ".yarn" / "unplugged").mkdir()
        (repo.root / ".pnp.cjs").write_text("module.exports = {};\n", encoding="utf-8")
        installed.remove_confirmed(repo.root, remove_lockfiles=False)
        self.assertFalse(cache.exists())
        self.assertFalse((repo.root / ".yarn" / "unplugged").exists())
        self.assertFalse((repo.root / ".pnp.cjs").exists())

    def test_a_tool_directory_keeps_what_the_project_committed(self):
        repo = self._repo()
        (repo.root / ".yarn" / "cache").mkdir(parents=True)
        for kept in ("patches", "plugins", "releases"):
            held = repo.root / ".yarn" / kept
            held.mkdir()
            (held / "keep.txt").write_text("committed\n", encoding="utf-8")
        installed.remove_confirmed(repo.root, remove_lockfiles=False)
        for kept in ("patches", "plugins", "releases"):
            self.assertTrue((repo.root / ".yarn" / kept / "keep.txt").is_file(),
                            f"a project's committed .yarn/{kept} was removed")

    def test_every_lockfile_the_ecosystem_writes_is_removed(self):
        for name in ("package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml",
                     "bun.lock", "bun.lockb", "deno.lock"):
            with self.subTest(lockfile=name):
                repo = _Repo(lockfile=False)
                lock = repo.root / name
                lock.write_bytes(b"{}")
                installed.remove_confirmed(repo.root, remove_lockfiles=True)
                self.assertFalse(lock.exists(), f"{name} survived a confirmed removal")

    def test_a_build_output_goes_with_whatever_it_bundled(self):
        repo = self._repo()
        repo.install("left-pad", "1.0.0")
        bundled = repo.root / ".next" / "standalone" / installed.INSTALLED_DIR / "evil-dep"
        bundled.mkdir(parents=True)
        (bundled / "index.js").write_text("module.exports = 1;\n", encoding="utf-8")
        report = installed.remove_confirmed(repo.root, remove_lockfiles=False)
        self.assertFalse((repo.root / ".next").exists())
        self.assertIn(".next", report.removed_builds)

    def test_nothing_is_copied_anywhere(self):
        repo = self._repo()
        repo.install("left-pad", "1.0.0")
        report = installed.remove_confirmed(repo.root, remove_lockfiles=True)
        self.assertFalse((repo.root / ROLLBACK_DIR).exists(),
                         "a confirmed removal kept a copy of the payload")
        self.assertIsNone(report.copies)

    def test_a_package_linked_out_of_the_repository_keeps_its_target(self):
        repo = self._repo()
        repo.install("left-pad", "1.0.0")
        outside = Path(tempfile.mkdtemp()) / "elsewhere"
        outside.mkdir()
        (outside / "package.json").write_text(json.dumps({"name": "linked"}), encoding="utf-8")
        (repo.root / installed.INSTALLED_DIR / "linked").symlink_to(outside)
        installed.remove_confirmed(repo.root, remove_lockfiles=False)
        self.assertFalse((repo.root / installed.INSTALLED_DIR).exists())
        self.assertTrue(outside.is_dir(), "a link's target was removed")

    def test_a_tree_that_is_itself_a_link_out_keeps_what_it_points_at(self):
        repo = self._repo()
        store = Path(tempfile.mkdtemp()) / "store"
        (store / "left-pad").mkdir(parents=True)
        (store / "left-pad" / "index.js").write_text("module.exports = 1;\n", encoding="utf-8")
        (repo.root / installed.INSTALLED_DIR).symlink_to(store)
        report = installed.remove_confirmed(repo.root, remove_lockfiles=False)
        self.assertFalse((repo.root / installed.INSTALLED_DIR).is_symlink())
        self.assertTrue((store / "left-pad" / "index.js").is_file(),
                        "a link's target was removed")
        self.assertEqual(report.removed_trees, 1)

    def test_a_tree_the_write_guard_refuses_is_left_alone(self):
        repo = self._repo()
        repo.install("left-pad", "1.0.0")
        with mock.patch.object(installed, "is_safe_write_target", return_value=False):
            report = installed.remove_confirmed(repo.root, remove_lockfiles=True)
        self.assertTrue((repo.root / installed.INSTALLED_DIR).is_dir())
        self.assertEqual(report.removed_trees, 0)

    def test_the_lockfile_goes_and_ci_keeps_it(self):
        repo = self._repo()
        repo.install("left-pad", "1.0.0")
        installed.remove_confirmed(repo.root, remove_lockfiles=False)
        self.assertTrue(repo.lock.is_file())
        installed.remove_confirmed(repo.root, remove_lockfiles=True)
        self.assertFalse(repo.lock.exists())

    def test_a_repository_with_nothing_derived_removes_nothing(self):
        repo = self._repo()
        report = installed.remove_confirmed(repo.root, remove_lockfiles=False)
        self.assertEqual(report.removed_trees, 0)
        self.assertEqual(report.note(), "")

    def test_a_forged_ci_signal_keeps_the_lockfile(self):
        with mock.patch.object(installed.env, "is_ci", return_value=True), \
             mock.patch.object(installed.env, "any_set", return_value=False):
            self.assertTrue(installed.lockfile_stays())
        with mock.patch.object(installed.env, "is_ci", return_value=False), \
             mock.patch.object(installed.env, "any_set", return_value=True):
            self.assertTrue(installed.lockfile_stays())

    def test_a_confirmed_infection_takes_the_whole_tree_and_keeps_no_copy(self):
        repo = _Repo()
        repo.install("left-pad", "1.0.0")
        repo.install("mystery", "9.9.9")
        report = installed.remove_installed(repo.root, remove_lockfiles=False)
        self.assertFalse((repo.root / installed.INSTALLED_DIR).exists())
        self.assertEqual(report.unaccounted_packages, 0)
        self.assertFalse((repo.root / ROLLBACK_DIR).exists())

    def test_the_lockfile_on_the_fix_worktree_is_what_proves_and_is_removed(self):
        repo = _Repo()
        package = repo.install("left-pad", "1.0.0")
        wt = Path(tempfile.mkdtemp())
        (wt / "package.json").write_text(
            (repo.root / "package.json").read_text(encoding="utf-8"), encoding="utf-8")
        (wt / "package-lock.json").write_text(
            repo.lock.read_text(encoding="utf-8"), encoding="utf-8")
        installed.remove_installed(repo.root, remove_lockfiles=True, lockfile_root=wt)
        self.assertFalse((wt / "package-lock.json").is_file())
        self.assertFalse(repo.lock.is_file())
        self.assertFalse(package.exists())


class TestARemovalThatDidNotHappenSaysSo(unittest.TestCase):
    """A confirmed removal that did not remove must never read as a finished cleanup."""

    def _infected(self):
        repo = _Repo()
        repo.install("evil", "9.9.9")
        return repo

    def test_a_removal_the_guard_refuses_is_named(self):
        repo = self._infected()
        with mock.patch.object(installed, "is_safe_write_target", return_value=False):
            report = installed.remove_confirmed(repo.root, remove_lockfiles=False)
        self.assertTrue((repo.root / installed.INSTALLED_DIR).is_dir())
        self.assertEqual(report.removed_trees, 0)
        self.assertIn("still there: node_modules", report.note())
        self.assertNotIn("sudo", report.note(), "a report of state carries no advice")

    def test_a_directory_that_cannot_be_read_is_named(self):
        if os.geteuid() == 0:
            self.skipTest("root reads a directory whatever its mode says")
        repo = self._infected()
        buried = repo.root / "locked"
        (buried / installed.INSTALLED_DIR / "evil").mkdir(parents=True)
        buried.chmod(0o000)
        try:
            report = installed.remove_confirmed(repo.root, remove_lockfiles=False)
        finally:
            buried.chmod(0o755)
        self.assertTrue((buried / installed.INSTALLED_DIR).is_dir())
        self.assertIn("still there: locked", report.note())

    def test_a_build_output_that_survived_is_named(self):
        repo = self._infected()
        (repo.root / "dist").mkdir()
        (repo.root / "dist" / "app.js").write_text("built\n", encoding="utf-8")
        real = installed.remove_derived

        def refuse_the_build(path, root):
            return False if path.name == "dist" else real(path, root)

        with mock.patch.object(installed, "remove_derived", side_effect=refuse_the_build):
            report = installed.remove_confirmed(repo.root, remove_lockfiles=False)
        self.assertTrue((repo.root / "dist").is_dir())
        self.assertIn("dist", report.survived_note())

    def test_a_removal_that_finished_claims_nothing_survived(self):
        repo = self._infected()
        report = installed.remove_confirmed(repo.root, remove_lockfiles=False)
        self.assertFalse((repo.root / installed.INSTALLED_DIR).exists())
        self.assertEqual(report.survived_note(), "")
        self.assertNotIn("still there", report.note())

    def test_the_line_stays_one_line_however_many_survive(self):
        repo = self._infected()
        for extra in ("dist", "build", "out"):
            (repo.root / extra).mkdir()
        with mock.patch.object(installed, "remove_derived", return_value=False):
            note = installed.remove_confirmed(repo.root, remove_lockfiles=False).survived_note()
        self.assertEqual(note.count("\n"), 0, "the operator asked for an action, not a report")
        self.assertLess(len(note), 120, note)
        self.assertIn("more", note, "the names are summarised, not all listed")

    def test_a_path_that_cannot_be_stat_ed_counts_as_still_there(self):
        # An answer nobody can give is not an answer that it is gone.
        with mock.patch.object(installed.Path, "exists", side_effect=OSError("boom")):
            self.assertTrue(installed._still_there(Path("/nowhere")))


class TestConfirmedFixReachesTheRemover(unittest.TestCase):
    def test_a_confirmed_scan_calls_the_remover_on_that_repository(self):
        from stayawake.bots.security.models import Finding, ScanResult, Severity

        called = []

        def spy(root, **kw):
            called.append((root, kw))
            return installed.Report()

        finding = Finding("x", "code-loader", Severity.CRITICAL, "postcss.config.mjs",
                          "loader", remediation="strip-appended-payload")
        infected = ScanResult("owner/repo", "local", [finding])
        idle = ScanResult("owner/repo", "local", [])
        _prepare_fix_against([infected, idle, idle], spy)
        self.assertEqual(len(called), 1)
        self.assertEqual(called[0][0], Path("/repo"))
        lockfile_root = called[0][1].get("lockfile_root")
        self.assertIsNotNone(lockfile_root)
        self.assertNotEqual(lockfile_root, called[0][0])
        self.assertIn("the-fix-worktree", Path(lockfile_root).parent.name)

    def test_ci_tells_the_remover_to_keep_the_lockfile(self):
        from stayawake.bots.security import pr
        from stayawake.bots.security.models import Finding, ScanResult, Severity

        called = []

        def spy(root, **kw):
            called.append((root, kw))
            return installed.Report()

        finding = Finding("x", "code-loader", Severity.CRITICAL, "postcss.config.mjs",
                          "loader", remediation="strip-appended-payload")
        infected = ScanResult("owner/repo", "local", [finding])
        idle = ScanResult("owner/repo", "local", [])
        _prepare_fix_against(
            [infected, idle, idle], spy,
            extra=(mock.patch.object(pr.fix.installed, "lockfile_stays", return_value=True),))
        self.assertEqual(called[0][1].get("remove_lockfiles"), False)

    def test_the_fix_branch_lists_the_lockfile_removal(self):
        from stayawake.bots.security.pr import fix as fixmod

        wt = Path(tempfile.mkdtemp())
        lock = wt / "package-lock.json"
        report = installed.Report(removed_lockfiles=[lock])
        changes = fixmod._lockfile_changes(wt, report.removed_lockfiles)
        self.assertEqual([c.path for c in changes], ["package-lock.json"])


class TestWhatTheOperatorIsToldToDo(unittest.TestCase):
    """Check the next step the run names after removing what a package manager produced."""

    def test_a_removed_lockfile_is_regenerated_by_reinstalling(self):
        note = installed.Report(removed_lockfiles=[Path("package-lock.json")]).note()
        self.assertIn("reinstall", note)
        for wrong in ("git checkout", "git restore", "restore it", "bring it back"):
            self.assertNotIn(wrong, note)

    def test_every_removal_names_the_same_step(self):
        for report in (installed.Report(removed_trees=1), installed.Report(removed_packages=2),
                       installed.Report(removed_builds=["dist"])):
            with self.subTest(report=report):
                self.assertIn("reinstall and rebuild", report.note())

    def test_nothing_removed_names_no_step(self):
        self.assertNotIn("reinstall", installed.Report().note())


if __name__ == "__main__":
    unittest.main()
