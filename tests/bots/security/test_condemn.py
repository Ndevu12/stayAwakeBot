#!/usr/bin/env python3
"""Removing an installed dependency tree.

A lockfile records what should be installed; it does not record what was. The part it accounts for
is reconstructible, and the part it does not is the only record of what actually ran — so that part
is kept before anything is removed, and nothing is reinstalled afterwards."""
from __future__ import annotations

import io
import json
import shutil
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest import mock

from stayawake.bots.security.remediation import condemn


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
        package = self.root / condemn.INSTALLED_DIR / name
        package.mkdir(parents=True)
        manifest = {"name": name}
        if version:
            manifest["version"] = version
        (package / "package.json").write_text(json.dumps(manifest), encoding="utf-8")
        (package / "index.js").write_text("module.exports = 1;\n", encoding="utf-8")
        return package

    def run(self, *args) -> tuple[int, str]:
        import sys
        from stayawake import cli
        buf = io.StringIO()
        with mock.patch.object(sys, "argv", ["saw", "condemn", str(self.root), *args]), \
             redirect_stdout(buf):
            return cli.main(), buf.getvalue()


class TestItRefusesWhereRemovalWouldBeAGuess(unittest.TestCase):
    def test_a_clean_repository_is_refused(self):
        repo = _Repo(infected=False)
        repo.install("left-pad", "1.0.0")
        rc, out = repo.run()
        self.assertEqual(rc, 2)
        self.assertIn("not confirmed infected", out)
        self.assertTrue((repo.root / condemn.INSTALLED_DIR / "left-pad").is_dir())

    def test_without_a_lockfile_nothing_proves_the_tree(self):
        plan = condemn.plan_condemnation(Path("/nowhere"), {("a", "1")}, [])
        self.assertFalse(plan.safe_to_remove)
        self.assertIn("no lockfile", plan.reason)

    def test_a_lockfile_that_declares_nothing_proves_nothing(self):
        plan = condemn.plan_condemnation(Path("/nowhere"), set(), [Path("/nowhere/lock")])
        self.assertFalse(plan.safe_to_remove)

    def test_a_tree_matching_no_declaration_is_left_alone(self):
        repo = _Repo()
        repo.install("mystery", "9.9.9")
        plan = condemn.plan_condemnation(repo.root, {("left-pad", "1.0.0")}, [repo.lock])
        self.assertFalse(plan.safe_to_remove)
        self.assertEqual(condemn.carry_out(plan, repo.root / "q"), (0, 0))


class TestWhatTheLockfileCannotAccountForIsKept(unittest.TestCase):
    def test_a_package_absent_from_the_lockfile_is_preserved(self):
        repo = _Repo()
        repo.install("left-pad", "1.0.0")
        repo.install("mystery", "9.9.9")
        plan = condemn.plan_condemnation(repo.root, {("left-pad", "1.0.0")}, [repo.lock])
        self.assertEqual([p.name for p in plan.derivable], ["left-pad"])
        self.assertEqual([p.name for p in plan.preserve], ["mystery"])

    def test_a_version_that_drifted_from_the_lockfile_is_preserved(self):
        # The case the lockfile reads clean over: an install never refreshed.
        repo = _Repo()
        repo.install("left-pad", "0.9.0")
        plan = condemn.plan_condemnation(repo.root, {("left-pad", "1.0.0")}, [repo.lock])
        self.assertEqual([p.name for p in plan.preserve], ["left-pad"])
        self.assertFalse(plan.derivable)

    def test_a_package_in_a_directory_its_name_does_not_match_is_preserved(self):
        # An install recreates the name's own location. This directory would simply be missing, so
        # nothing reconstructs it and it is not ours to remove.
        repo = _Repo()
        elsewhere = repo.root / condemn.INSTALLED_DIR / "weird-dir"
        elsewhere.mkdir(parents=True)
        (elsewhere / "package.json").write_text(
            json.dumps({"name": "left-pad", "version": "1.0.0"}), encoding="utf-8")
        plan = condemn.plan_condemnation(repo.root, {("left-pad", "1.0.0")}, [repo.lock])
        self.assertFalse(plan.derivable)
        self.assertEqual([p.path.name for p in plan.preserve], ["weird-dir"])

    def test_a_scoped_package_in_its_own_place_is_derivable(self):
        repo = _Repo()
        scoped = repo.root / condemn.INSTALLED_DIR / "@acme" / "widget"
        scoped.mkdir(parents=True)
        (scoped / "package.json").write_text(
            json.dumps({"name": "@acme/widget", "version": "2.0.0"}), encoding="utf-8")
        plan = condemn.plan_condemnation(repo.root, {("@acme/widget", "2.0.0")}, [repo.lock])
        self.assertEqual([p.name for p in plan.derivable], ["@acme/widget"])

    def test_a_package_that_will_not_say_what_it_is_is_preserved(self):
        repo = _Repo()
        repo.install("left-pad", "1.0.0")
        repo.install("silent", None)
        plan = condemn.plan_condemnation(repo.root, {("left-pad", "1.0.0")}, [repo.lock])
        self.assertIn("silent", [p.name for p in plan.preserve])


class TestTheTreeIsWalkedAsItActuallyIs(unittest.TestCase):
    def test_a_package_nested_inside_another_is_seen(self):
        # A package the lockfile accounts for can contain one it does not.
        repo = _Repo()
        parent = repo.install("left-pad", "1.0.0")
        nested = parent / condemn.INSTALLED_DIR / "stowaway"
        nested.mkdir(parents=True)
        (nested / "package.json").write_text(json.dumps({"name": "stowaway", "version": "0.1"}),
                                             encoding="utf-8")
        plan = condemn.plan_condemnation(repo.root, {("left-pad", "1.0.0")}, [repo.lock])
        self.assertIn("stowaway", [p.name for p in plan.preserve])

    def test_the_nested_one_is_kept_before_its_parent_goes(self):
        repo = _Repo()
        parent = repo.install("left-pad", "1.0.0")
        nested = parent / condemn.INSTALLED_DIR / "stowaway"
        nested.mkdir(parents=True)
        (nested / "package.json").write_text(json.dumps({"name": "stowaway", "version": "0.1"}),
                                             encoding="utf-8")
        quarantine = repo.root / "q"
        plan = condemn.plan_condemnation(repo.root, {("left-pad", "1.0.0")}, [repo.lock])
        condemn.carry_out(plan, quarantine)
        self.assertFalse(parent.exists())
        self.assertTrue((quarantine / condemn.INSTALLED_DIR / "left-pad" / condemn.INSTALLED_DIR
                         / "stowaway" / "package.json").is_file())

    def test_a_linked_package_is_never_removed(self):
        # pnpm and `npm link` put links here. The target lives somewhere this tree does not own.
        repo = _Repo()
        repo.install("left-pad", "1.0.0")
        outside = Path(tempfile.mkdtemp()) / "elsewhere"
        outside.mkdir()
        (outside / "package.json").write_text(json.dumps({"name": "linked", "version": "1.0.0"}),
                                              encoding="utf-8")
        (repo.root / condemn.INSTALLED_DIR / "linked").symlink_to(outside)
        plan = condemn.plan_condemnation(repo.root, {("left-pad", "1.0.0"), ("linked", "1.0.0")},
                                         [repo.lock])
        self.assertNotIn("linked", [p.name for p in plan.derivable])
        condemn.carry_out(plan, repo.root / "q")
        self.assertTrue(outside.is_dir(), "a link's target was removed")


class TestOnlyALockfileMayProveAnything(unittest.TestCase):
    """A manifest records what someone asked for. It does not record what an install produced, and
    a peer dependency is never written into a tree at all."""

    def _declared(self, repo):
        from stayawake.cli.commands.condemn import _declared
        return _declared(repo.root)

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
        nested = parent / condemn.INSTALLED_DIR / "ms"
        nested.mkdir(parents=True)
        (nested / "package.json").write_text(json.dumps({"name": "ms", "version": "1.0.0"}),
                                             encoding="utf-8")
        plan = condemn.plan_condemnation(
            repo.root, {("left-pad", "1.0.0"), ("ms", "1.0.0")}, [repo.lock])
        self.assertEqual(len(plan.derivable), 2)
        preserved, removed = condemn.carry_out(plan, repo.root / "q")
        self.assertEqual((preserved, removed), (0, 2))
        self.assertFalse(parent.exists())


class TestEachRunKeepsItsOwnEvidence(unittest.TestCase):
    def test_a_second_run_does_not_write_into_the_first(self):
        repo = _Repo()
        base = repo.root / ".malware-quarantine"
        first = condemn.next_quarantine(repo.root, base)
        first.mkdir(parents=True)
        second = condemn.next_quarantine(repo.root, base)
        self.assertNotEqual(first, second)


class TestPreservationHappensBeforeRemoval(unittest.TestCase):
    def test_the_kept_copy_exists_before_anything_is_deleted(self):
        repo = _Repo()
        derivable = repo.install("left-pad", "1.0.0")
        kept = repo.install("mystery", "9.9.9")
        quarantine = repo.root / "q"
        plan = condemn.plan_condemnation(repo.root, {("left-pad", "1.0.0")}, [repo.lock])
        preserved, removed = condemn.carry_out(plan, quarantine)
        self.assertEqual((preserved, removed), (1, 1))
        self.assertTrue((quarantine / condemn.INSTALLED_DIR / "mystery" / "package.json").is_file())
        self.assertTrue(kept.is_dir(), "the original of a preserved package was removed")
        self.assertFalse(derivable.exists())

    def test_a_failed_preservation_removes_nothing(self):
        # The copy being preserved is the only one there is, so a partial preserve must not be
        # followed by a delete.
        repo = _Repo()
        derivable = repo.install("left-pad", "1.0.0")
        repo.install("mystery", "9.9.9")
        plan = condemn.plan_condemnation(repo.root, {("left-pad", "1.0.0")}, [repo.lock])
        with mock.patch.object(condemn.shutil, "copytree", side_effect=OSError("disk full")):
            with self.assertRaises(OSError):
                condemn.carry_out(plan, repo.root / "q")
        self.assertTrue(derivable.is_dir(), "a package was removed after preservation failed")


class TestItRemovesAndDoesNotRebuild(unittest.TestCase):
    def test_it_cannot_run_anything(self):
        # Reinstalling re-runs the lifecycle scripts, which is the path the payload arrived by. The
        # property is that this module executes nothing at all — not that it avoids one spelling.
        import ast
        source = Path("src/stayawake/bots/security/remediation/condemn.py").read_text()
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

    def test_the_lockfile_is_never_touched(self):
        repo = _Repo()
        repo.install("left-pad", "1.0.0")
        plan = condemn.plan_condemnation(repo.root, {("left-pad", "1.0.0")}, [repo.lock])
        condemn.carry_out(plan, repo.root / "q")
        self.assertTrue(repo.lock.is_file())

    def test_a_dry_run_changes_nothing(self):
        repo = _Repo()
        package = repo.install("left-pad", "1.0.0")
        rc, out = repo.run("--dry-run")
        self.assertEqual(rc, 0)
        self.assertTrue(package.is_dir())
        self.assertIn("would be removed", out)


if __name__ == "__main__":
    unittest.main()
