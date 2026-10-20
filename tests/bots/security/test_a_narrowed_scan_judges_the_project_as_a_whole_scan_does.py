#!/usr/bin/env python3
"""A scan narrowed to the files that changed, as the checkout and pull hooks run it, judges the
project as a whole the way `saw scan` does: installed packages against every lockfile, the scripts a
folder-open task runs, and the dependencies every lockfile lists. A scan of one named file still
answers about that file alone."""
from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from stayawake.bots.security.dependencies import Advisory, AdvisoryStore
from stayawake.bots.security.matchers import REGISTRY
from stayawake.bots.security.models import CLEAN, INFECTED
from stayawake.bots.security.scanner import scan_target
from stayawake.bots.security.signatures import load_signatures
from stayawake.bots.security.targets import LocalRepoTarget, ScanOptions
from tests.bots.security.test_a_package_script_an_editor_task_runs_is_read import _PAYLOADS, _open

_SIGNATURES = load_signatures()
_LOCKED = {"is-odd": "3.0.1", "is-number": "6.0.0"}
_NARROWINGS = (("README.md",), ("package.json",), ("src/app.ts",), ("README.md", "src/app.ts"))


def _scan(root: Path, include_only=None, *, names_one_file: bool = False):
    target = LocalRepoTarget(root, str(root), ScanOptions(), include_only=include_only)
    target.names_one_file = names_one_file
    return scan_target(target, _SIGNATURES, [])


def _project(layout: str, installed: dict[str, str]) -> Path:
    """Make a project whose lockfile lists `_LOCKED`, with `installed` on disk in the layout's tree.
    Takes the package manager and the installed packages. Returns its root."""
    root = Path(tempfile.mkdtemp(prefix="narrowed-"))
    (root / "README.md").write_text("two\n")
    (root / "src").mkdir()
    (root / "src" / "app.ts").write_text("export const a = 1;\n")
    (root / "package.json").write_text(json.dumps({"name": "app", "dependencies": {"is-odd": "3.0.1"}}))
    if layout == "npm":
        packages = {"": {"name": "app"}} | {f"node_modules/{n}": {"version": v} for n, v in _LOCKED.items()}
        (root / "package-lock.json").write_text(json.dumps({"lockfileVersion": 3, "packages": packages}))
    elif layout == "yarn":
        (root / "yarn.lock").write_text("# yarn lockfile v1\n\n" + "".join(
            f'"{n}@^{v}":\n  version "{v}"\n\n' for n, v in _LOCKED.items()))
    else:
        (root / "pnpm-lock.yaml").write_text("lockfileVersion: '9.0'\n\npackages:\n\n" + "".join(
            f"  {n}@{v}:\n    resolution: {{integrity: sha512-x}}\n\n" for n, v in _LOCKED.items()))
    for name, version in installed.items():
        manifest = json.dumps({"name": name, "version": version})
        if layout == "pnpm":
            real = root / "node_modules" / ".pnpm" / f"{name}@{version}" / "node_modules" / name
            real.mkdir(parents=True)
            (real / "package.json").write_text(manifest)
            (root / "node_modules" / name).symlink_to(real)
        else:
            (root / "node_modules" / name).mkdir(parents=True)
            (root / "node_modules" / name / "package.json").write_text(manifest)
    return root


def _ghosts(result) -> set[str]:
    return {f.evidence.split("@", 1)[0] for f in result.findings if f.signature_id == "ghost-package"}


class TestInstalledPackagesAreReadAgainstEveryLockfile(unittest.TestCase):
    def test_packages_every_lockfile_lists_are_not_reported_whatever_changed(self):
        for layout in ("npm", "yarn", "pnpm"):
            root = _project(layout, dict(_LOCKED))
            for narrowed in _NARROWINGS:
                with self.subTest(layout=layout, narrowed=narrowed):
                    result = _scan(root, narrowed)
                    self.assertEqual(_ghosts(result), set())
                    self.assertEqual(result.verdict, CLEAN)

    def test_a_package_no_lockfile_lists_is_reported_whatever_changed(self):
        for layout in ("npm", "yarn", "pnpm"):
            root = _project(layout, {**_LOCKED, "dropped": "1.0.0"})
            for narrowed in (None, *_NARROWINGS):
                with self.subTest(layout=layout, narrowed=narrowed):
                    self.assertEqual(_ghosts(_scan(root, narrowed)), {"dropped"})


class TestAScriptAFolderOpenTaskRunsIsReadWhateverChanged(unittest.TestCase):
    def _project(self, payload: str) -> Path:
        root = Path(tempfile.mkdtemp(prefix="narrowed-task-"))
        (root / ".vscode").mkdir()
        (root / ".vscode" / "tasks.json").write_text(json.dumps(
            {"version": "2.0.0", "tasks": [_open(command="npm run watch")]}))
        (root / "package.json").write_text(json.dumps({"name": "app", "scripts": {"watch": payload}}))
        (root / "README.md").write_text("x\n")
        return root

    def test_a_payload_in_the_script_reads_infected_when_any_one_file_changed(self):
        for kind, payload in _PAYLOADS.items():
            root = self._project(payload())
            for narrowed in (("package.json",), (".vscode/tasks.json",), ("README.md",)):
                with self.subTest(kind=kind, narrowed=narrowed):
                    result = _scan(root, narrowed)
                    self.assertIn("vscode-task-runs-payload-script",
                                  {f.signature_id for f in result.findings})
                    self.assertEqual(result.verdict, INFECTED)


class TestADependencyEveryLockfileListsIsAudited(unittest.TestCase):
    def setUp(self):
        store = AdvisoryStore({"late-evil@1.0.0": Advisory(signature={
            "id": "malicious-dependency", "category": "supply-chain-dep", "severity": "critical",
            "description": "known-malicious dependency", "corpus": True})})
        patch = mock.patch.object(REGISTRY["dependency-audit"], "_store_factory", lambda sigs: store)
        patch.start()
        self.addCleanup(patch.stop)
        self.root = Path(tempfile.mkdtemp(prefix="narrowed-dep-"))
        for folder, name in (("app", "late-evil"), ("tools", "left-pad")):
            (self.root / folder).mkdir()
            (self.root / folder / "package-lock.json").write_text(json.dumps({"lockfileVersion": 3, "packages": {
                "": {"name": folder}, f"node_modules/{name}": {"version": "1.0.0"}}}))
        (self.root / "README.md").write_text("x\n")

    def _reported(self, result) -> set[str]:
        return {f.path for f in result.findings if f.signature_id == "malicious-dependency"}

    def test_a_known_malicious_dependency_in_a_lockfile_that_did_not_change_is_reported(self):
        self.assertEqual(self._reported(_scan(self.root, ("README.md",))), {"app/package-lock.json"})

    def test_a_scan_of_one_named_lockfile_answers_about_that_file_alone(self):
        named = _scan(self.root, ("tools/package-lock.json",), names_one_file=True)
        self.assertEqual(self._reported(named), set())
        named = _scan(self.root, ("app/package-lock.json",), names_one_file=True)
        self.assertEqual(self._reported(named), {"app/package-lock.json"})


class TestTheFileChecksJudgeTheFilesThatChanged(unittest.TestCase):
    def test_a_marker_reads_infected_when_its_file_is_among_those_that_changed(self):
        root = Path(tempfile.mkdtemp(prefix="narrowed-per-file-"))
        (root / ".gitignore").write_text("node_modules\ntemp_auto_push.bat\nbranch_structure.json\n")
        (root / "README.md").write_text("x\n")
        self.assertEqual(_scan(root, (".gitignore", "README.md")).verdict, INFECTED)
        self.assertEqual(_scan(root, ("README.md",)).verdict, CLEAN)


class TestTheTargetReadInFull(unittest.TestCase):
    def setUp(self):
        self.root = Path(tempfile.mkdtemp(prefix="narrowed-target-"))
        for rel in ("README.md", "src/app.ts", "package-lock.json"):
            (self.root / rel).parent.mkdir(parents=True, exist_ok=True)
            (self.root / rel).write_text("{}\n")

    def test_it_reads_every_file_and_records_where_the_narrowed_target_does(self):
        narrowed = LocalRepoTarget(self.root, str(self.root), ScanOptions(), include_only=("README.md",))
        narrowed.merge_scope = ["c0ffee"]
        whole = narrowed.unnarrowed()
        self.assertEqual(sorted(whole.iter_files()), ["README.md", "package-lock.json", "src/app.ts"])
        self.assertEqual(list(narrowed.iter_files()), ["README.md"])
        whole.read_errors.append("package-lock.json: PermissionError")
        self.assertEqual(narrowed.read_errors, ["package-lock.json: PermissionError"])
        self.assertEqual(whole.merge_scope, ["c0ffee"])

    def test_a_target_read_in_full_already_or_naming_one_file_is_itself(self):
        whole = LocalRepoTarget(self.root, str(self.root), ScanOptions())
        self.assertIs(whole.unnarrowed(), whole)
        named = LocalRepoTarget(self.root, str(self.root), ScanOptions(), include_only=("README.md",))
        named.names_one_file = True
        self.assertIs(named.unnarrowed(), named)

    @unittest.skipIf(os.name == "nt" or (hasattr(os, "geteuid") and os.geteuid() == 0),
                     "needs a file its owner cannot read")
    def test_a_lockfile_a_narrowed_scan_cannot_read_leaves_it_unverified(self):
        root = _project("npm", dict(_LOCKED))
        lockfile = root / "package-lock.json"
        lockfile.chmod(0)
        self.addCleanup(lockfile.chmod, 0o644)
        self.assertIsNotNone(_scan(root, ("README.md",)).error)


if __name__ == "__main__":
    unittest.main()
