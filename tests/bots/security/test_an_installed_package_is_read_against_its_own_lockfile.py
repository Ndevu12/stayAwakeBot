#!/usr/bin/env python3
"""An installed package is read against the lockfiles in the folder it is installed in or above it,
by version: one no such lockfile lists, or one installed at a version they do not list, is reported
off-lockfile. An alias is read as the package it installs, by the installed-package check and by
the lockfile audit."""
from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from stayawake.bots.security.dependencies import Advisory, AdvisoryStore
from stayawake.bots.security.matchers.dependency_audit import DependencyAuditMatcher
from stayawake.bots.security.matchers.installed_package_audit import InstalledPackageAuditMatcher
from stayawake.bots.security.targets import LocalRepoTarget, ScanOptions

_GHOST = {"id": "ghost-package", "category": "supply-chain-dep", "severity": "high",
          "confidence": "heuristic", "description": "off-lockfile"}
_MALICIOUS = {"id": "malicious-dependency", "category": "supply-chain-dep", "severity": "critical",
              "description": "known-malicious dependency", "corpus": True}


class _NoAdvisories:
    def is_empty(self):
        return True

    def advisory_for(self, purl):
        return None


def _lock(folder: Path, packages: dict[str, str]) -> None:
    folder.mkdir(parents=True, exist_ok=True)
    entries = {"": {"name": folder.name}} | {f"node_modules/{n}": {"version": v} for n, v in packages.items()}
    (folder / "package-lock.json").write_text(json.dumps({"lockfileVersion": 3, "packages": entries}))


def _install(folder: Path, packages: dict[str, str | None]) -> None:
    for name, version in packages.items():
        (folder / "node_modules" / name).mkdir(parents=True)
        manifest = {"name": name} | ({"version": version} if version else {})
        (folder / "node_modules" / name / "package.json").write_text(json.dumps(manifest))


def _off_lockfile(root: Path) -> dict[str, str]:
    target = LocalRepoTarget(root, str(root), ScanOptions())
    found = InstalledPackageAuditMatcher(store_factory=lambda s: _NoAdvisories()).scan(target, [_GHOST])
    return {f.path: f.evidence for f in found}


class TestAPackageIsReadAgainstItsOwnLockfile(unittest.TestCase):
    def setUp(self):
        self.root = Path(tempfile.mkdtemp(prefix="own-lockfile-"))

    def test_a_package_only_a_nested_projects_lockfile_lists_is_reported(self):
        _lock(self.root, {"is-odd": "3.0.1"})
        _lock(self.root / "tools", {"dropped": "1.0.0"})
        _install(self.root, {"is-odd": "3.0.1", "dropped": "1.0.0"})
        self.assertEqual(set(_off_lockfile(self.root)), {"node_modules/dropped/package.json"})

    def test_a_package_installed_at_a_version_its_lockfile_does_not_list_is_reported(self):
        _lock(self.root, {"is-odd": "3.0.1"})
        _install(self.root, {"is-odd": "9.9.9"})
        found = _off_lockfile(self.root)
        self.assertEqual(set(found), {"node_modules/is-odd/package.json"})
        self.assertIn("is-odd@9.9.9 is installed, but the lockfile lists is-odd at 3.0.1",
                      found["node_modules/is-odd/package.json"])

    def test_every_package_its_lockfile_lists_at_its_version_reads_clean(self):
        _lock(self.root, {"is-odd": "3.0.1", "is-number": "6.0.0"})
        _install(self.root, {"is-odd": "3.0.1", "is-number": "6.0.0"})
        self.assertEqual(_off_lockfile(self.root), {})

    def test_a_workspace_package_the_root_lockfile_lists_reads_clean(self):
        root_lock = {"": {"name": "app"}, "packages/web/node_modules/left-pad": {"version": "1.3.0"}}
        (self.root / "package-lock.json").write_text(json.dumps({"lockfileVersion": 3, "packages": root_lock}))
        _install(self.root / "packages" / "web", {"left-pad": "1.3.0"})
        self.assertEqual(_off_lockfile(self.root), {})

    def test_a_nested_projects_package_its_own_lockfile_lists_reads_clean(self):
        _lock(self.root, {"is-odd": "3.0.1"})
        _install(self.root, {"is-odd": "3.0.1"})
        _lock(self.root / "tools", {"left-pad": "1.3.0"})
        _install(self.root / "tools", {"left-pad": "1.3.0"})
        self.assertEqual(_off_lockfile(self.root), {})

    def test_a_package_whose_installed_version_is_not_known_is_read_by_its_name(self):
        _lock(self.root, {"is-odd": "3.0.1"})
        _install(self.root, {"is-odd": None})
        self.assertEqual(_off_lockfile(self.root), {})

    def test_a_pnpm_package_installed_at_a_version_the_lockfile_does_not_list_is_reported(self):
        (self.root / "pnpm-lock.yaml").write_text(
            "lockfileVersion: '9.0'\n\npackages:\n\n  is-odd@3.0.1:\n    resolution: {integrity: sha512-x}\n")
        real = self.root / "node_modules" / ".pnpm" / "is-odd@9.9.9" / "node_modules" / "is-odd"
        real.mkdir(parents=True)
        (real / "package.json").write_text(json.dumps({"name": "is-odd", "version": "9.9.9"}))
        (self.root / "node_modules" / "is-odd").symlink_to(real)
        self.assertEqual(len(_off_lockfile(self.root)), 1)


class TestAnAliasIsReadAsThePackageItInstalls(unittest.TestCase):
    def setUp(self):
        self.root = Path(tempfile.mkdtemp(prefix="alias-"))
        (self.root / "yarn.lock").write_text(
            '# yarn lockfile v1\n\n'
            '"my-lodash@npm:lodash@^3.10.1":\n  version "3.10.1"\n\n'
            '"lodash@^4.17.21":\n  version "4.17.21"\n\n')
        (self.root / "node_modules" / "my-lodash").mkdir(parents=True)
        (self.root / "node_modules" / "my-lodash" / "package.json").write_text(
            json.dumps({"name": "lodash", "version": "3.10.1"}))
        (self.root / "node_modules" / "lodash").mkdir(parents=True)
        (self.root / "node_modules" / "lodash" / "package.json").write_text(
            json.dumps({"name": "lodash", "version": "4.17.21"}))

    def test_an_aliased_install_its_lockfile_lists_reads_clean(self):
        self.assertEqual(_off_lockfile(self.root), {})

    def test_a_known_malicious_package_behind_an_alias_is_reported_by_the_lockfile_audit(self):
        store = AdvisoryStore({"lodash@3.10.1": Advisory(signature=_MALICIOUS)})
        found = DependencyAuditMatcher(store_factory=lambda sigs: store).scan(
            LocalRepoTarget(self.root, str(self.root), ScanOptions()), [_MALICIOUS])
        self.assertEqual([f.signature_id for f in found], ["malicious-dependency"])


if __name__ == "__main__":
    unittest.main()
