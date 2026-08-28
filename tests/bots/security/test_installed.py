#!/usr/bin/env python3
"""Removing an installed dependency tree."""
from __future__ import annotations

import contextlib
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

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


def _prepare_fix_against(scans, spy, extra=()):
    """Drive `saw fix` far enough that the CONFIRMED gate either fires or does not."""
    from stayawake.bots.security import pr
    from stayawake.bots.security.models import ScanResult
    from stayawake.lib.git.write.commit import CommitResult

    idle = ScanResult("owner/repo", "local", [])
    patches = [
        mock.patch.object(pr.gitutil, "origin_slug", return_value=None),
        mock.patch.object(pr.gitutil, "default_branch", return_value="main"),
        mock.patch.object(pr.gitutil, "ref_exists", return_value=True),
        mock.patch.object(pr.gitutil, "is_ancestor", return_value=True),
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
        mock.patch.object(pr.fix.installed, "remove_rebuildable", spy),
        *extra,
    ]
    with contextlib.ExitStack() as stack:
        for patch in patches:
            stack.enter_context(patch)
        pr.prepare_fix(Path("/repo"), object(), {}, [])


class TestItRefusesWhereRemovalWouldBeAGuess(unittest.TestCase):
    def test_a_clean_scan_does_not_reach_the_remover(self):
        # The CONFIRMED gate is `saw fix`. A clean scan must not call the remover.
        from stayawake.bots.security.models import ScanResult

        called = []

        def spy(root, **kw):
            called.append(root)
            return installed.Report()

        clean = ScanResult("owner/repo", "local", [])
        _prepare_fix_against([clean, clean, clean], spy)
        self.assertEqual(called, [])

    def test_a_heuristic_scan_does_not_reach_the_remover(self):
        from stayawake.bots.security.models import Finding, ScanResult, Severity

        called = []

        def spy(root, **kw):
            called.append(root)
            return installed.Report()

        finding = Finding("x", "code-loader", Severity.CRITICAL, "postcss.config.mjs",
                          "loader", confidence="heuristic")
        suspect = ScanResult("owner/repo", "local", [finding])
        idle = ScanResult("owner/repo", "local", [])
        _prepare_fix_against([suspect, idle, idle], spy)
        self.assertEqual(called, [])

    def test_a_scan_that_did_not_finish_does_not_reach_the_remover(self):
        from stayawake.bots.security.models import Finding, ScanResult, Severity

        called = []

        def spy(root, **kw):
            called.append(root)
            return installed.Report()

        finding = Finding("x", "code-loader", Severity.CRITICAL, "postcss.config.mjs",
                          "loader", remediation="strip-appended-payload")
        partial = ScanResult("owner/repo", "local", [finding],
                             error="1 file(s) unreadable: secret.env")
        idle = ScanResult("owner/repo", "local", [])
        _prepare_fix_against([partial, idle, idle], spy)
        self.assertEqual(called, [])

    def test_a_finding_that_does_not_say_it_is_confirmed_does_not_reach_the_remover(self):
        from types import SimpleNamespace

        from stayawake.bots.security.models import ScanResult, Severity

        called = []

        def spy(root, **kw):
            called.append(root)
            return installed.Report()

        finding = SimpleNamespace(
            path="index.js", signature_id="x", category="other",
            vector=None, commit_sha=None, related_paths=(), line=None,
            severity=Severity.CRITICAL, description="x")
        infected = ScanResult("owner/repo", "local", [finding])
        idle = ScanResult("owner/repo", "local", [])
        _prepare_fix_against([infected, idle, idle], spy)
        self.assertEqual(called, [])

    def test_without_a_lockfile_nothing_proves_the_tree(self):
        plan = installed.plan_removal(Path("/nowhere"), {("a", "1")}, [])
        self.assertFalse(plan.safe_to_remove)
        self.assertIn("no lockfile", plan.reason)

    def test_a_lockfile_that_declares_nothing_proves_nothing(self):
        plan = installed.plan_removal(Path("/nowhere"), set(), [Path("/nowhere/lock")])
        self.assertFalse(plan.safe_to_remove)

    def test_a_tree_matching_no_declaration_is_left_alone(self):
        repo = _Repo()
        repo.install("mystery", "9.9.9")
        plan = installed.plan_removal(repo.root, {("left-pad", "1.0.0")}, [repo.lock])
        self.assertFalse(plan.safe_to_remove)
        self.assertEqual(installed.apply_removal(plan, repo.root / "q"), (0, 0))


class TestWhatTheLockfileCannotAccountForIsKept(unittest.TestCase):
    def test_a_package_absent_from_the_lockfile_is_preserved(self):
        repo = _Repo()
        repo.install("left-pad", "1.0.0")
        repo.install("mystery", "9.9.9")
        plan = installed.plan_removal(repo.root, {("left-pad", "1.0.0")}, [repo.lock])
        self.assertEqual([p.name for p in plan.derivable], ["left-pad"])
        self.assertEqual([p.name for p in plan.preserve], ["mystery"])

    def test_a_version_that_drifted_from_the_lockfile_is_preserved(self):
        # The case the lockfile reads clean over: an install never refreshed.
        repo = _Repo()
        repo.install("left-pad", "0.9.0")
        plan = installed.plan_removal(repo.root, {("left-pad", "1.0.0")}, [repo.lock])
        self.assertEqual([p.name for p in plan.preserve], ["left-pad"])
        self.assertFalse(plan.derivable)

    def test_a_package_in_a_directory_its_name_does_not_match_is_preserved(self):
        # An install recreates the name's own location. This directory would simply be missing, so
        # nothing reconstructs it and it is not ours to remove.
        repo = _Repo()
        elsewhere = repo.root / installed.INSTALLED_DIR / "weird-dir"
        elsewhere.mkdir(parents=True)
        (elsewhere / "package.json").write_text(
            json.dumps({"name": "left-pad", "version": "1.0.0"}), encoding="utf-8")
        plan = installed.plan_removal(repo.root, {("left-pad", "1.0.0")}, [repo.lock])
        self.assertFalse(plan.derivable)
        self.assertEqual([p.path.name for p in plan.preserve], ["weird-dir"])

    def test_a_scoped_package_in_its_own_place_is_derivable(self):
        repo = _Repo()
        scoped = repo.root / installed.INSTALLED_DIR / "@acme" / "widget"
        scoped.mkdir(parents=True)
        (scoped / "package.json").write_text(
            json.dumps({"name": "@acme/widget", "version": "2.0.0"}), encoding="utf-8")
        plan = installed.plan_removal(repo.root, {("@acme/widget", "2.0.0")}, [repo.lock])
        self.assertEqual([p.name for p in plan.derivable], ["@acme/widget"])

    def test_a_package_that_will_not_say_what_it_is_is_preserved(self):
        repo = _Repo()
        repo.install("left-pad", "1.0.0")
        repo.install("silent", None)
        plan = installed.plan_removal(repo.root, {("left-pad", "1.0.0")}, [repo.lock])
        self.assertIn("silent", [p.name for p in plan.preserve])


class TestTheTreeIsWalkedAsItActuallyIs(unittest.TestCase):
    def test_a_package_nested_inside_another_is_seen(self):
        # A package the lockfile accounts for can contain one it does not.
        repo = _Repo()
        parent = repo.install("left-pad", "1.0.0")
        nested = parent / installed.INSTALLED_DIR / "stowaway"
        nested.mkdir(parents=True)
        (nested / "package.json").write_text(json.dumps({"name": "stowaway", "version": "0.1"}),
                                             encoding="utf-8")
        plan = installed.plan_removal(repo.root, {("left-pad", "1.0.0")}, [repo.lock])
        self.assertIn("stowaway", [p.name for p in plan.preserve])

    def test_the_nested_one_is_kept_before_its_parent_goes(self):
        repo = _Repo()
        parent = repo.install("left-pad", "1.0.0")
        nested = parent / installed.INSTALLED_DIR / "stowaway"
        nested.mkdir(parents=True)
        (nested / "package.json").write_text(json.dumps({"name": "stowaway", "version": "0.1"}),
                                             encoding="utf-8")
        quarantine = repo.root / "q"
        plan = installed.plan_removal(repo.root, {("left-pad", "1.0.0")}, [repo.lock])
        installed.apply_removal(plan, quarantine)
        self.assertFalse(parent.exists())
        self.assertTrue((quarantine / installed.INSTALLED_DIR / "left-pad" / installed.INSTALLED_DIR
                         / "stowaway" / "package.json").is_file())

    def test_a_linked_package_is_never_removed(self):
        # pnpm and `npm link` put links here. The target lives somewhere this tree does not own.
        repo = _Repo()
        repo.install("left-pad", "1.0.0")
        outside = Path(tempfile.mkdtemp()) / "elsewhere"
        outside.mkdir()
        (outside / "package.json").write_text(json.dumps({"name": "linked", "version": "1.0.0"}),
                                              encoding="utf-8")
        (repo.root / installed.INSTALLED_DIR / "linked").symlink_to(outside)
        plan = installed.plan_removal(repo.root, {("left-pad", "1.0.0"), ("linked", "1.0.0")},
                                         [repo.lock])
        self.assertNotIn("linked", [p.name for p in plan.derivable])
        installed.apply_removal(plan, repo.root / "q")
        self.assertTrue(outside.is_dir(), "a link's target was removed")


class TestOnlyALockfileMayProveAnything(unittest.TestCase):
    """A manifest records what someone asked for. It does not record what an install produced, and
    a peer dependency is never written into a tree at all."""

    def _declared(self, repo):
        return installed.declared_from_lockfiles(repo.root)

    def test_a_manifest_pin_does_not_make_a_package_removable(self):
        repo = _Repo()
        (repo.root / "package.json").write_text(json.dumps(
            {"name": "app", "version": "1.0.0",
             "dependencies": {"left-pad": "1.0.0", "ghost": "9.9.9"}}), encoding="utf-8")
        declared, _lockfiles = self._declared(repo)
        self.assertIn(("left-pad", "1.0.0"), declared)
        self.assertNotIn(("ghost", "9.9.9"), declared, "a manifest proved a package removable")

    def test_a_manifest_elsewhere_in_the_repository_proves_nothing(self):
        # A test fixture's own manifest is not a statement about this install.
        repo = _Repo()
        fixture = repo.root / "tests" / "fixtures" / "broken"
        fixture.mkdir(parents=True)
        (fixture / "package.json").write_text(json.dumps(
            {"name": "f", "version": "1.0.0", "dependencies": {"victim": "4.2.0"}}),
            encoding="utf-8")
        declared, _lockfiles = self._declared(repo)
        self.assertNotIn(("victim", "4.2.0"), declared)


class TestRemovalIsDeepestFirst(unittest.TestCase):
    def test_a_nested_derivable_package_does_not_abort_the_run(self):
        # Removing the parent first takes the child with it, and the walk then deletes a path that
        # is already gone — raising part-way through a destructive operation.
        repo = _Repo()
        parent = repo.install("left-pad", "1.0.0")
        nested = parent / installed.INSTALLED_DIR / "ms"
        nested.mkdir(parents=True)
        (nested / "package.json").write_text(json.dumps({"name": "ms", "version": "1.0.0"}),
                                             encoding="utf-8")
        plan = installed.plan_removal(
            repo.root, {("left-pad", "1.0.0"), ("ms", "1.0.0")}, [repo.lock])
        self.assertEqual(len(plan.derivable), 2)
        preserved, removed = installed.apply_removal(plan, repo.root / "q")
        self.assertEqual((preserved, removed), (0, 2))
        self.assertFalse(parent.exists())


class TestEachRunKeepsItsOwnEvidence(unittest.TestCase):
    def test_a_second_run_does_not_write_into_the_first(self):
        repo = _Repo()
        base = repo.root / ".malware-quarantine"
        first = installed.next_quarantine(repo.root, base)
        first.mkdir(parents=True)
        second = installed.next_quarantine(repo.root, base)
        self.assertNotEqual(first, second)


class TestPreservationHappensBeforeRemoval(unittest.TestCase):
    def test_the_kept_copy_exists_before_anything_is_deleted(self):
        repo = _Repo()
        derivable = repo.install("left-pad", "1.0.0")
        kept = repo.install("mystery", "9.9.9")
        quarantine = repo.root / "q"
        plan = installed.plan_removal(repo.root, {("left-pad", "1.0.0")}, [repo.lock])
        preserved, removed = installed.apply_removal(plan, quarantine)
        self.assertEqual((preserved, removed), (1, 1))
        self.assertTrue((quarantine / installed.INSTALLED_DIR / "mystery" / "package.json").is_file())
        self.assertTrue(kept.is_dir(), "the original of a preserved package was removed")
        self.assertFalse(derivable.exists())

    def test_a_failed_preservation_removes_nothing(self):
        # The copy being preserved is the only one there is, so a partial preserve must not be
        # followed by a delete.
        repo = _Repo()
        derivable = repo.install("left-pad", "1.0.0")
        repo.install("mystery", "9.9.9")
        plan = installed.plan_removal(repo.root, {("left-pad", "1.0.0")}, [repo.lock])
        with mock.patch.object(installed.shutil, "copytree", side_effect=OSError("disk full")):
            with self.assertRaises(OSError):
                installed.apply_removal(plan, repo.root / "q")
        self.assertTrue(derivable.is_dir(), "a package was removed after preservation failed")


class TestItRemovesAndDoesNotRebuild(unittest.TestCase):
    def test_it_cannot_run_anything(self):
        # Reinstalling re-runs the lifecycle scripts, which is the path the payload arrived by. The
        # property is that this module executes nothing at all — not that it avoids one spelling.
        import ast
        source = Path("src/stayawake/bots/security/remediation/installed.py").read_text()
        tree = ast.parse(source)
        imported = {alias.name.split(".")[0]
                    for node in ast.walk(tree) if isinstance(node, (ast.Import, ast.ImportFrom))
                    for alias in (node.names if isinstance(node, ast.Import) else node.names)}
        imported |= {node.module.split(".")[0] for node in ast.walk(tree)
                     if isinstance(node, ast.ImportFrom) and node.module}
        for runner in ("subprocess", "os", "popen", "pty", "multiprocessing"):
            self.assertNotIn(runner, imported, f"the remover can reach {runner}")
        called = {node.func.attr for node in ast.walk(tree)
                  if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)}
        for runner in ("run", "system", "popen", "spawn", "exec", "check_call"):
            self.assertNotIn(runner, called, f"the remover calls {runner}()")

    def test_the_lockfile_is_not_touched_by_package_removal_alone(self):
        repo = _Repo()
        repo.install("left-pad", "1.0.0")
        plan = installed.plan_removal(repo.root, {("left-pad", "1.0.0")}, [repo.lock])
        installed.apply_removal(plan, repo.root / "q")
        self.assertTrue(repo.lock.is_file())

    def test_planning_changes_nothing(self):
        repo = _Repo()
        package = repo.install("left-pad", "1.0.0")
        plan = installed.plan_removal(repo.root, {("left-pad", "1.0.0")}, [repo.lock])
        self.assertTrue(plan.safe_to_remove)
        self.assertTrue(package.is_dir())


class TestTheProjectTreeIsRemovedOnTheRepo(unittest.TestCase):
    def test_the_lockfile_is_copied_then_removed(self):
        repo = _Repo()
        package = repo.install("left-pad", "1.0.0")
        report = installed.remove_rebuildable(repo.root, remove_lockfiles=True)
        self.assertFalse(repo.lock.is_file())
        self.assertFalse(package.exists())
        kept = list((repo.root / ".malware-quarantine").rglob("package-lock.json"))
        self.assertTrue(kept, "the lockfile was deleted without a copy")
        self.assertTrue(report.removed_lockfiles)

    def test_a_failed_lockfile_copy_removes_nothing(self):
        repo = _Repo()
        package = repo.install("left-pad", "1.0.0")
        with mock.patch.object(installed.shutil, "copy2", side_effect=OSError("disk full")):
            with self.assertRaises(OSError):
                installed.remove_rebuildable(repo.root, remove_lockfiles=True)
        self.assertTrue(repo.lock.is_file(), "the lockfile was deleted after its copy failed")
        self.assertTrue(package.is_dir(), "a package was removed after the lockfile copy failed")

    def test_the_lockfile_is_kept_when_told_to_stay(self):
        repo = _Repo()
        repo.install("left-pad", "1.0.0")
        installed.remove_rebuildable(repo.root, remove_lockfiles=False)
        self.assertTrue(repo.lock.is_file())

    def test_a_forged_ci_signal_keeps_the_lockfile(self):
        with mock.patch.object(installed.env, "is_ci", return_value=True), \
             mock.patch.object(installed.env, "any_set", return_value=False):
            self.assertTrue(installed.lockfile_stays())
        with mock.patch.object(installed.env, "is_ci", return_value=False), \
             mock.patch.object(installed.env, "any_set", return_value=True):
            self.assertTrue(installed.lockfile_stays())

    def test_build_outputs_in_the_repository_are_removed(self):
        repo = _Repo()
        (repo.root / "dist").mkdir()
        (repo.root / "dist" / "app.js").write_text("x", encoding="utf-8")
        (repo.root / ".next").mkdir()
        (repo.root / ".next" / "cache").write_text("x", encoding="utf-8")
        (repo.root / ".venv").mkdir()
        (repo.root / ".venv" / "pyvenv.cfg").write_text("x", encoding="utf-8")
        installed.remove_rebuildable(repo.root, exclude_dirs={".git", "node_modules", "dist", ".venv"})
        self.assertFalse((repo.root / "dist").exists())
        self.assertFalse((repo.root / ".next").exists())
        self.assertTrue((repo.root / ".venv").is_dir())

    def test_a_tree_outside_the_repository_is_not_touched(self):
        repo = _Repo()
        repo.install("left-pad", "1.0.0")
        outside = Path(tempfile.mkdtemp()) / "node_modules"
        outside.mkdir()
        marker = outside / "keep"
        marker.write_text("x", encoding="utf-8")
        installed.remove_rebuildable(repo.root)
        self.assertTrue(marker.is_file())

    def test_a_linked_installed_tree_is_not_walked(self):
        # The target lives on the host. A link here is not this repository's tree.
        repo = _Repo()
        host = Path(tempfile.mkdtemp()) / "node_modules"
        host.mkdir()
        marker = host / "keep"
        marker.write_text("x", encoding="utf-8")
        (repo.root / installed.INSTALLED_DIR).symlink_to(host)
        installed.remove_rebuildable(repo.root)
        self.assertTrue(marker.is_file())
        self.assertTrue((repo.root / installed.INSTALLED_DIR).is_symlink())

    def test_a_nested_linked_tree_is_not_removed(self):
        repo = _Repo()
        package = repo.install("left-pad", "1.0.0")
        host = Path(tempfile.mkdtemp())
        inner = host / "left-pad"
        inner.mkdir()
        (inner / "package.json").write_text(
            json.dumps({"name": "left-pad", "version": "1.0.0"}), encoding="utf-8")
        marker = inner / "keep"
        marker.write_text("x", encoding="utf-8")
        nested = package / installed.INSTALLED_DIR
        nested.symlink_to(host)
        installed.remove_rebuildable(repo.root)
        self.assertTrue(marker.is_file())

    def test_a_linked_quarantine_is_not_written(self):
        repo = _Repo()
        package = repo.install("left-pad", "1.0.0")
        host = Path(tempfile.mkdtemp())
        marker = host / "keep"
        marker.write_text("x", encoding="utf-8")
        (repo.root / ".malware-quarantine").symlink_to(host)
        with self.assertRaises(OSError):
            installed.remove_rebuildable(repo.root)
        self.assertTrue(marker.is_file())
        self.assertTrue(package.is_dir())
        self.assertTrue(repo.lock.is_file())
        self.assertEqual(list(host.iterdir()), [marker])


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
        self.assertIn("sab-fix-", Path(lockfile_root).name)

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

    def test_the_lockfile_on_the_fix_worktree_is_what_proves_and_is_removed(self):
        repo = _Repo()
        package = repo.install("left-pad", "1.0.0")
        wt = Path(tempfile.mkdtemp())
        (wt / "package.json").write_text(
            (repo.root / "package.json").read_text(encoding="utf-8"), encoding="utf-8")
        (wt / "package-lock.json").write_text(
            repo.lock.read_text(encoding="utf-8"), encoding="utf-8")
        installed.remove_rebuildable(repo.root, remove_lockfiles=True, lockfile_root=wt)
        self.assertFalse((wt / "package-lock.json").is_file())
        self.assertFalse(repo.lock.is_file())
        self.assertFalse(package.exists())

    def test_the_fix_branch_lists_the_lockfile_removal(self):
        from stayawake.bots.security.pr import fix as fixmod

        wt = Path(tempfile.mkdtemp())
        lock = wt / "package-lock.json"
        report = installed.Report(removed_lockfiles=[lock])
        changes = fixmod._lockfile_changes(wt, report)
        self.assertEqual([c.path for c in changes], ["package-lock.json"])


if __name__ == "__main__":
    unittest.main()
