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

from stayawake.bots.security.models import QUARANTINE_DIR
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
        mock.patch.object(pr.fix.installed, "remove_installed", spy),
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

    def test_a_scan_that_did_not_finish_does_not_apply_a_plan(self):
        from stayawake.bots.security import pr
        from stayawake.bots.security.models import Finding, ScanResult, Severity

        planned = []

        def spy_apply(*a, **k):
            planned.append(1)
            return []

        finding = Finding("x", "code-loader", Severity.CRITICAL, "postcss.config.mjs",
                          "loader", remediation="strip-appended-payload")
        partial = ScanResult("owner/repo", "local", [finding],
                             error="1 file(s) unreadable: secret.env")
        idle = ScanResult("owner/repo", "local", [])
        _prepare_fix_against(
            [partial, idle, idle], lambda *a, **k: installed.Report(),
            extra=(mock.patch.object(pr.remediation, "apply", side_effect=spy_apply),))
        self.assertEqual(planned, [])

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

    def test_a_finding_that_does_not_say_it_is_confirmed_is_not_recovered(self):
        from types import SimpleNamespace

        from stayawake.bots.security import pr
        from stayawake.bots.security.models import ScanResult, Severity
        from stayawake.bots.security.remediation.classify import Recovery

        recovered = []

        def spy_rec(*a, **k):
            recovered.append(1)
            return True

        def plant(repo, wt, *a, **k):
            Path(wt).mkdir(parents=True, exist_ok=True)
            (Path(wt) / "index.js").write_text("x\n", encoding="utf-8")
            return True

        finding = SimpleNamespace(
            path="index.js", signature_id="x", category="code-loader",
            vector=None, commit_sha=None, related_paths=(), line=None,
            severity=Severity.CRITICAL, description="x")
        infected = ScanResult("owner/repo", "local", [finding])
        idle = ScanResult("owner/repo", "local", [])
        rec = Recovery("index.js", "HEAD", "restored", "", "ok")
        _prepare_fix_against(
            [infected, idle, idle], lambda *a, **k: installed.Report(),
            extra=(
                mock.patch.object(pr.gitutil, "add_worktree", side_effect=plant),
                mock.patch.object(pr.remediation, "has_concealment_seam", return_value=True),
                mock.patch.object(pr.remediation, "classify_recovery", return_value=rec),
                mock.patch.object(pr.remediation, "apply_recovery", side_effect=spy_rec),
            ))
        self.assertEqual(recovered, [])

    def test_a_confidence_that_changes_mid_loop_is_not_a_computed_strip(self):
        from stayawake.bots.security import pr
        from stayawake.bots.security.models import HEURISTIC, ScanResult, Severity
        from stayawake.bots.security.remediation.classify import Suggested

        stripped = []

        def spy_strip(*a, **k):
            stripped.append(1)
            return True

        def plant(repo, wt, *a, **k):
            Path(wt).mkdir(parents=True, exist_ok=True)
            (Path(wt) / "index.js").write_text("x\n", encoding="utf-8")
            return True

        class Flip:
            n = 0
            path = "index.js"
            signature_id = "x"
            category = "code-loader"
            vector = None
            commit_sha = None
            related_paths = ()
            line = None
            severity = Severity.CRITICAL
            description = "x"

            @property
            def confidence(self):
                type(self).n += 1
                return HEURISTIC if type(self).n == 1 else "confirmed"

        infected = ScanResult("owner/repo", "local", [Flip()])
        idle = ScanResult("owner/repo", "local", [])
        sug = Suggested("index.js", "x", "untracked", "review", "", "stripped\n")
        _prepare_fix_against(
            [infected, idle, idle], lambda *a, **k: installed.Report(),
            extra=(
                mock.patch.object(pr.gitutil, "add_worktree", side_effect=plant),
                mock.patch.object(pr.remediation, "has_concealment_seam", return_value=True),
                mock.patch.object(pr.remediation, "classify_recovery", return_value=sug),
                mock.patch.object(pr.remediation, "apply_suggested", side_effect=spy_strip),
            ))
        self.assertEqual(stripped, [])

    def test_a_frozen_finding_does_not_take_a_later_grade(self):
        from stayawake.bots.security.models import Finding, HEURISTIC, Severity
        from stayawake.bots.security.pr.fix import _Frozen
        from stayawake.bots.security import remediation

        wrap = _Frozen(Finding(
            "x", "persistence", Severity.HIGH, "payload.js", "drop",
            remediation="quarantine-file", confidence=HEURISTIC))
        with self.assertRaises(AttributeError):
            wrap.confidence = "confirmed"
        with self.assertRaises(AttributeError):
            del wrap.confidence
        self.assertFalse(remediation.is_auto_fixable(wrap))
        self.assertEqual(remediation.plan([wrap]), [])

    def test_a_scan_that_did_not_finish_does_not_quarantine(self):
        from stayawake.bots.security import pr
        from stayawake.bots.security.models import Finding, ScanResult, Severity

        quarantined = []

        def spy_q(root, findings, q):
            quarantined.extend(findings)
            return []

        finding = Finding("x", "persistence", Severity.HIGH, "telemetry.js",
                          "drop", remediation="quarantine-file")
        partial = ScanResult("owner/repo", "local", [finding],
                             error="1 file(s) unreadable: secret.env")
        idle = ScanResult("owner/repo", "local", [])
        _prepare_fix_against(
            [partial, partial, idle], lambda *a, **k: installed.Report(),
            extra=(mock.patch.object(pr.remediation, "quarantine_residual", side_effect=spy_q),))
        self.assertEqual(quarantined, [])

    def test_an_unfinished_first_scan_does_not_quarantine_off_a_later_one(self):
        from stayawake.bots.security import pr
        from stayawake.bots.security.models import Finding, ScanResult, Severity

        quarantined = []

        def spy_q(root, findings, q):
            quarantined.extend(findings)
            return []

        finding = Finding("x", "persistence", Severity.HIGH, "telemetry.js",
                          "drop", remediation="quarantine-file")
        partial = ScanResult("owner/repo", "local", [finding],
                             error="1 file(s) unreadable: secret.env")
        later = ScanResult("owner/repo", "local", [finding])
        idle = ScanResult("owner/repo", "local", [])
        _prepare_fix_against(
            [partial, later, idle], lambda *a, **k: installed.Report(),
            extra=(mock.patch.object(pr.remediation, "quarantine_residual", side_effect=spy_q),))
        self.assertEqual(quarantined, [])

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


class TestNothingUnaccountedSurvivesTheTree(unittest.TestCase):
    """A confirmed removal clears the installed tree, and says so only about what it could not."""

    def _stored(self, repo, name="left-pad", version="1.0.0"):
        held = repo.root / installed.INSTALLED_DIR / ".store"
        real = held / f"{name}@{version}" / installed.INSTALLED_DIR / name
        real.mkdir(parents=True)
        (real / "package.json").write_text(json.dumps({"name": name, "version": version}),
                                           encoding="utf-8")
        (real / "index.js").write_text("module.exports = 1;\n", encoding="utf-8")
        (repo.root / installed.INSTALLED_DIR / name).symlink_to(real)
        return real

    def test_a_store_of_links_is_removed_like_any_other_tree(self):
        repo = _Repo()
        self._stored(repo)
        report = installed.remove_rebuildable(repo.root, remove_lockfiles=False)
        self.assertFalse((repo.root / installed.INSTALLED_DIR).exists())
        self.assertEqual(report.removed_packages, 1)
        self.assertEqual(report.kept_note(), "")

    def test_a_dot_directory_and_a_loose_file_do_not_survive(self):
        repo = _Repo()
        repo.install("left-pad", "1.0.0")
        repo.install("mystery", "9.9.9")
        shims = repo.root / installed.INSTALLED_DIR / ".bin"
        shims.mkdir()
        (shims / "worm").write_text("#!/bin/sh\n", encoding="utf-8")
        loose = repo.root / installed.INSTALLED_DIR / "loose.js"
        loose.write_text("module.exports = 1;\n", encoding="utf-8")
        installed.remove_rebuildable(repo.root, remove_lockfiles=False)
        self.assertFalse((repo.root / installed.INSTALLED_DIR).exists())

    def test_what_is_swept_is_copied_before_it_is_removed(self):
        repo = _Repo()
        repo.install("left-pad", "1.0.0")
        loose = repo.root / installed.INSTALLED_DIR / "loose.js"
        loose.write_text("module.exports = 42;\n", encoding="utf-8")
        installed.remove_rebuildable(repo.root, remove_lockfiles=False)
        saved = list((repo.root / QUARANTINE_DIR).rglob("loose.js"))
        self.assertEqual(len(saved), 1, "a swept file was removed without a copy")
        self.assertEqual(saved[0].read_text(encoding="utf-8"), "module.exports = 42;\n")

    def test_a_link_out_of_the_repository_loses_the_link_and_keeps_its_target(self):
        repo = _Repo()
        repo.install("left-pad", "1.0.0")
        outside = Path(tempfile.mkdtemp()) / "elsewhere"
        outside.mkdir()
        (outside / "package.json").write_text(json.dumps({"name": "linked", "version": "1.0.0"}),
                                              encoding="utf-8")
        (repo.root / installed.INSTALLED_DIR / "linked").symlink_to(outside)
        installed.remove_rebuildable(repo.root, remove_lockfiles=False)
        self.assertFalse((repo.root / installed.INSTALLED_DIR).exists())
        self.assertTrue(outside.is_dir(), "a link's target was removed")

    def test_a_tree_that_is_itself_a_link_is_left_and_named(self):
        repo = _Repo()
        store = Path(tempfile.mkdtemp()) / "store"
        (store / "left-pad").mkdir(parents=True)
        (store / "left-pad" / "package.json").write_text(
            json.dumps({"name": "left-pad", "version": "1.0.0"}), encoding="utf-8")
        (repo.root / installed.INSTALLED_DIR).symlink_to(store)
        report = installed.remove_rebuildable(repo.root, remove_lockfiles=False)
        self.assertTrue((store / "left-pad").is_dir(), "a link's target was removed")
        self.assertIn("left in place", report.note())

    def test_an_incomplete_sweep_copy_removes_nothing(self):
        repo = _Repo()
        repo.install("left-pad", "1.0.0")
        shims = repo.root / installed.INSTALLED_DIR / ".bin"
        shims.mkdir()
        (shims / "worm").write_text("#!/bin/sh\n", encoding="utf-8")
        with mock.patch.object(installed, "_every_file_arrived", return_value=False):
            with self.assertRaises(OSError):
                installed.remove_rebuildable(repo.root, remove_lockfiles=False)
        self.assertTrue((shims / "worm").is_file(), "a stray was removed without a whole copy")

    def test_a_tree_that_cannot_be_read_is_named_as_kept(self):
        if os.geteuid() == 0:
            self.skipTest("root reads a directory whatever its mode says")
        repo = _Repo(lockfile=False)
        repo.install("left-pad", "1.0.0")
        tree = repo.root / installed.INSTALLED_DIR
        tree.chmod(0o000)
        try:
            report = installed.remove_rebuildable(repo.root, remove_lockfiles=False)
        finally:
            tree.chmod(0o755)
        self.assertIn("could not be read", report.note())

    def test_a_tree_nothing_proves_derivable_is_named_as_kept(self):
        repo = _Repo(lockfile=False)
        repo.install("left-pad", "1.0.0")
        report = installed.remove_rebuildable(repo.root, remove_lockfiles=False)
        self.assertEqual(report.removed_packages, 0)
        self.assertIn("no lockfile declares", report.note())

    def test_a_tree_that_was_cleared_does_not_claim_anything_was_kept(self):
        repo = _Repo()
        repo.install("left-pad", "1.0.0")
        report = installed.remove_rebuildable(repo.root, remove_lockfiles=False)
        self.assertEqual(report.removed_packages, 1)
        self.assertEqual(report.kept_note(), "")

    def test_a_repository_with_nothing_installed_says_nothing(self):
        repo = _Repo()
        report = installed.remove_rebuildable(repo.root, remove_lockfiles=False)
        self.assertEqual(report.kept_note(), "")


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
    def test_the_copy_exists_before_anything_is_deleted(self):
        """An unaccounted package used to be copied and LEFT, so the packages surviving a confirmed
        removal were exactly the ones nobody could account for — and `npm install` does not prune
        them, so the rebuild carried them through. It is taken too, once its copy is read back."""
        repo = _Repo()
        derivable = repo.install("left-pad", "1.0.0")
        unaccounted = repo.install("mystery", "9.9.9")
        quarantine = repo.root / "q"
        plan = installed.plan_removal(repo.root, {("left-pad", "1.0.0")}, [repo.lock])
        preserved, removed = installed.apply_removal(plan, quarantine)
        self.assertEqual((preserved, removed), (1, 2))
        self.assertTrue((quarantine / installed.INSTALLED_DIR / "mystery" / "package.json").is_file())
        self.assertFalse(unaccounted.exists(), "nothing unaccounted for survives the removal")
        self.assertFalse(derivable.exists())

    def test_an_incomplete_copy_removes_nothing(self):
        """`copytree` can copy part of a tree and report the failures at the end, so "it did not
        raise" is weaker than the delete needs: the copy is the only one there is."""
        repo = _Repo()
        derivable = repo.install("left-pad", "1.0.0")
        unaccounted = repo.install("mystery", "9.9.9")
        plan = installed.plan_removal(repo.root, {("left-pad", "1.0.0")}, [repo.lock])
        with mock.patch.object(installed.shutil, "copytree", lambda *a, **k: None):
            with self.assertRaises(OSError):
                installed.apply_removal(plan, repo.root / "q")
        self.assertTrue(derivable.is_dir(), "a package was removed after an incomplete copy")
        self.assertTrue(unaccounted.is_dir())

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
        installed.remove_rebuildable(repo.root)
        self.assertFalse((repo.root / "dist").exists())
        self.assertFalse((repo.root / ".next").exists())
        self.assertTrue((repo.root / ".venv").is_dir())

    def test_a_directory_the_user_excluded_from_scanning_is_never_removed(self):
        """`exclude_dirs` is documented as directories never TRAVERSED. It was unioned into the
        delete set, so vendored code, fixtures and test corpora were destroyed — with no copy,
        because this path made no quarantine at all."""
        repo = _Repo()
        repo.install("left-pad", "1.0.0")
        for name in ("vendor", "fixtures", "testdata"):
            (repo.root / name).mkdir()
            (repo.root / name / "hand-written.txt").write_text("mine", encoding="utf-8")
        installed.remove_rebuildable(repo.root)
        for name in ("vendor", "fixtures", "testdata"):
            self.assertTrue((repo.root / name / "hand-written.txt").is_file(), name)

    def test_generated_outputs_are_kept_when_nothing_proves_the_tree(self):
        """The removal sat outside the guard, so it ran after the plan had already concluded that
        no lockfile means nothing proves what the tree should contain."""
        repo = _Repo(lockfile=False)
        (repo.root / "dist").mkdir()
        (repo.root / "dist" / "app.js").write_text("x", encoding="utf-8")
        report = installed.remove_rebuildable(repo.root)
        self.assertEqual(report.removed_builds, [])
        self.assertTrue((repo.root / "dist" / "app.js").is_file())

    def test_a_declared_project_with_no_installed_tree_still_clears_its_outputs(self):
        """The first gate for this used `safe_to_remove`, which also requires an installed package
        proven derivable — so a repository with a lockfile and nothing installed stopped clearing
        its own `dist`. That is the right test for deleting the installed tree and the wrong one
        for a generated output."""
        repo = _Repo()
        (repo.root / "dist").mkdir()
        (repo.root / "dist" / "app.js").write_text("built", encoding="utf-8")
        report = installed.remove_rebuildable(repo.root)
        self.assertEqual(report.removed_builds, ["dist"])
        self.assertFalse((repo.root / "dist").exists())

    def test_a_generated_output_is_copied_out_before_it_is_removed(self):
        """Copy it out, then delete — the rule the package path already follows, and the one
        removal here that followed neither."""
        repo = _Repo()
        repo.install("left-pad", "1.0.0")
        (repo.root / "dist").mkdir()
        (repo.root / "dist" / "app.js").write_text("built", encoding="utf-8")
        report = installed.remove_rebuildable(repo.root)
        self.assertIn("dist", report.removed_builds)
        self.assertFalse((repo.root / "dist").exists())
        saved = list((repo.root / QUARANTINE_DIR).rglob("dist/app.js"))
        self.assertTrue(saved, "the content is gone with no copy")
        self.assertEqual(saved[0].read_text(encoding="utf-8"), "built")

    def test_the_note_says_the_working_tree_changed_and_where_the_copies_are(self):
        """A reader of `--pr` may take it as "prepare a branch for review". The removals happen in
        the checkout they are standing in, and do not wait for the pull request."""
        repo = _Repo()
        repo.install("left-pad", "1.0.0")
        note = installed.remove_rebuildable(repo.root).note()
        self.assertIn("working tree", note)
        self.assertIn(QUARANTINE_DIR, note)
        self.assertEqual(installed.Report().note(), "", "a run that did nothing claims nothing")

    def test_the_note_does_not_call_a_removed_package_kept(self):
        """It said "kept N" of the unaccounted packages, which was true when they were left in
        place and is the opposite of true now that they are taken."""
        repo = _Repo()
        repo.install("left-pad", "1.0.0")
        repo.install("mystery", "9.9.9")
        note = installed.remove_rebuildable(repo.root).note()
        self.assertNotIn("kept", note)
        self.assertIn("unaccounted for", note)

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
        self.assertFalse((repo.root / QUARANTINE_DIR).exists(),
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


class TestConfidenceChoosesTheRemoval(unittest.TestCase):
    """Which removal runs is the finding's confidence, decided in one place."""

    def test_a_confirmed_infection_takes_the_whole_tree_and_keeps_no_copy(self):
        repo = _Repo()
        repo.install("left-pad", "1.0.0")
        repo.install("mystery", "9.9.9")
        report = installed.remove_installed(repo.root, confirmed=True, remove_lockfiles=False)
        self.assertFalse((repo.root / installed.INSTALLED_DIR).exists())
        self.assertEqual(report.preserved_packages, 0)
        self.assertFalse((repo.root / QUARANTINE_DIR).exists())

    def test_anything_less_keeps_what_no_lockfile_accounts_for(self):
        repo = _Repo()
        repo.install("left-pad", "1.0.0")
        repo.install("mystery", "9.9.9")
        report = installed.remove_installed(repo.root, confirmed=False, remove_lockfiles=False)
        self.assertEqual(report.preserved_packages, 1)
        self.assertIsNotNone(report.copies)


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
