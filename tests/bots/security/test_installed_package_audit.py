#!/usr/bin/env python3
"""Installed-package audit (#1144): reconcile the on-disk tree against the lockfile + corpus.
Identity-on-disk (known-malicious installed pkg → INFECTED) and ghost (on disk, not locked →
SUSPICIOUS), even when the lockfile was never edited. No network; injected store."""
from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from stayawake.bots.security.dependencies import Advisory
from stayawake.bots.security.matchers.installed_package_audit import InstalledPackageAuditMatcher
from stayawake.bots.security.targets.base import ScanOptions, Target

_MAL_SIG = {"id": "malicious-installed-package", "category": "supply-chain-dep",
            "severity": "critical", "description": "malicious installed", "corpus": True}
_GHOST_SIG = {"id": "ghost-package", "category": "supply-chain-dep", "severity": "high",
              "confidence": "heuristic", "description": "off-lockfile"}


class _FakeStore:
    def __init__(self, malicious):
        self._malicious = set(malicious)

    def is_empty(self):
        return False

    def advisory_for(self, purl):
        return Advisory(signature=_MAL_SIG) if purl.coordinate in self._malicious else None


def _repo(locked, installed) -> Target:
    d = Path(tempfile.mkdtemp())
    packages = {"": {"name": "app"}}
    for n in locked:
        packages[f"node_modules/{n}"] = {"version": "1.0.0"}
    (d / "package-lock.json").write_text(json.dumps({"lockfileVersion": 3, "packages": packages}))
    for name, ver in installed.items():
        pdir = d / "node_modules" / name
        pdir.mkdir(parents=True, exist_ok=True)
        (pdir / "package.json").write_text(json.dumps({"name": name, "version": ver}))
    return Target(d, str(d), ScanOptions())


def _scan(target, malicious=()):
    m = InstalledPackageAuditMatcher(store_factory=lambda sigs: _FakeStore(malicious))
    return m.scan(target, [_MAL_SIG, _GHOST_SIG])


class TestInstalledPackageAudit(unittest.TestCase):
    def test_identity_ghost_and_locked(self):
        t = _repo(locked=["good"], installed={"good": "1.0.0", "evil": "9.9.9", "extra": "6.6.6"})
        by = {f.path.split("/")[1]: f for f in _scan(t, malicious={"evil@9.9.9"})}
        self.assertEqual(by["evil"].signature_id, "malicious-installed-package")  # known-bad → INFECTED tier
        self.assertEqual(by["extra"].signature_id, "ghost-package")               # off-lockfile → SUSPICIOUS
        self.assertNotIn("good", by, "a locked package must not be flagged")

    def test_scoped_ghost(self):
        t = _repo(locked=[], installed={"@scope/pkg": "2.0.0"})
        f = _scan(t)
        self.assertEqual(len(f), 1)
        self.assertEqual((f[0].signature_id, f[0].path),
                         ("ghost-package", "node_modules/@scope/pkg/package.json"))

    def test_no_installed_tree_is_a_noop(self):
        # a remote clone with a lockfile but no node_modules → nothing (lockfile audit is the coverage)
        d = Path(tempfile.mkdtemp())
        (d / "package-lock.json").write_text('{"lockfileVersion":3,"packages":{}}')
        self.assertEqual(_scan(Target(d, str(d), ScanOptions())), [])


if __name__ == "__main__":
    unittest.main()
