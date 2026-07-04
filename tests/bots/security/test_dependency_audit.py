#!/usr/bin/env python3
"""Malicious upstream dependency audit (#1101, T1195.001).

Parses package.json + npm/yarn/pnpm lockfiles and flags a dependency (direct OR transitive) whose
exact name@version is on the data-driven known-bad blocklist. Exact match → confirmed (INFECTED);
a package.json version RANGE is ambiguous and deferred to the lockfile (not matched).
"""
from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from stayawake.bots.security.models import INFECTED, CLEAN
from stayawake.bots.security.signatures import load_signatures
from stayawake.bots.security.scanner import scan_target
from stayawake.bots.security.targets import LocalRepoTarget, ScanOptions

SIGS = load_signatures()
DEP = "malicious-dependency"
BAD = "html-to-gutenberg@4.2.11"          # a documented known-bad from the campaign
BAD2 = "fetch-page-assets@1.2.9"


def _scan(files, allow=None):
    d = Path(tempfile.mkdtemp())
    for rel, content in files.items():
        p = d / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content, encoding="utf-8")
    return scan_target(LocalRepoTarget(d, "t", ScanOptions()), SIGS, allow or [])


class TestDependencyAudit(unittest.TestCase):
    def test_manifest_exact_pinned_known_bad_is_infected(self):
        r = _scan({"package.json": json.dumps({"dependencies": {"html-to-gutenberg": "4.2.11"}})})
        self.assertIn(DEP, {f.signature_id for f in r.findings})
        self.assertEqual(r.verdict, INFECTED)              # exact match is confirmed

    def test_manifest_range_is_not_matched(self):
        # `^4.2.11` may or may not resolve to the bad version — ambiguous, so deferred to the
        # lockfile's resolved version (no false positive on the manifest range).
        r = _scan({"package.json": json.dumps({"dependencies": {"html-to-gutenberg": "^4.2.11"}})})
        self.assertEqual([f.signature_id for f in r.findings], [])
        self.assertEqual(r.verdict, CLEAN)

    def test_manifest_good_version_is_clean(self):
        r = _scan({"package.json": json.dumps({"dependencies": {"html-to-gutenberg": "4.3.0"}})})
        self.assertEqual([f.signature_id for f in r.findings], [])

    def test_manifest_dev_dependencies_covered(self):
        r = _scan({"package.json": json.dumps({"devDependencies": {"fetch-page-assets": "1.2.9"}})})
        self.assertIn(DEP, {f.signature_id for f in r.findings})

    def test_npm_lock_v3_packages_transitive(self):
        lock = json.dumps({"lockfileVersion": 3, "packages": {
            "": {}, "node_modules/react": {"version": "18.2.0"},
            "node_modules/a/node_modules/fetch-page-assets": {"version": "1.2.9"}}})
        self.assertIn(DEP, {f.signature_id for f in _scan({"package-lock.json": lock}).findings})

    def test_npm_lock_v1_nested_dependencies(self):
        lock = json.dumps({"lockfileVersion": 1, "dependencies": {
            "x": {"version": "1.0.0",
                  "dependencies": {"html-to-gutenberg": {"version": "4.2.11"}}}}})
        self.assertIn(DEP, {f.signature_id for f in _scan({"npm-shrinkwrap.json": lock}).findings})

    def test_yarn_lock_multi_spec_header(self):
        yarn = ('"html-to-gutenberg@^4.2.11", "html-to-gutenberg@^4.0.0":\n'
                '  version "4.2.11"\n  resolved "https://x"\n')
        self.assertIn(DEP, {f.signature_id for f in _scan({"yarn.lock": yarn}).findings})

    def test_yarn_lock_scoped_package(self):
        yarn = ('"@acme/fetch-page-assets@^1.0.0":\n  version "1.0.0"\n'
                '"fetch-page-assets@^1.2.9":\n  version "1.2.9"\n')
        self.assertIn(DEP, {f.signature_id for f in _scan({"yarn.lock": yarn}).findings})

    def test_pnpm_lock_v9_name_at_version_with_peers(self):
        pnpm = ('lockfileVersion: "9.0"\npackages:\n'
                "  /fetch-page-assets@1.2.9(react@18.2.0):\n    resolution: {integrity: sha512-x}\n")
        self.assertIn(DEP, {f.signature_id for f in _scan({"pnpm-lock.yaml": pnpm}).findings})

    def test_pnpm_lock_v5_name_slash_version(self):
        pnpm = "packages:\n  /html-to-gutenberg/4.2.11:\n    dev: false\n"
        self.assertIn(DEP, {f.signature_id for f in _scan({"pnpm-lock.yaml": pnpm}).findings})

    def test_yarn_berry_colon_version(self):
        # Yarn Berry (v2+) writes `version: x.y.z` (YAML colon), not classic `version "x.y.z"`.
        yarn = ('"html-to-gutenberg@npm:^4.2.11":\n  version: 4.2.11\n  resolution: "x"\n')
        self.assertIn(DEP, {f.signature_id for f in _scan({"yarn.lock": yarn}).findings})

    def test_pnpm_v5_peer_underscore_suffix(self):
        # pnpm v5 decorates the key with an underscore peer suffix: /name/version_peer@ver.
        pnpm = "packages:\n  /html-to-gutenberg/4.2.11_react@18.2.0:\n    dev: false\n"
        self.assertIn(DEP, {f.signature_id for f in _scan({"pnpm-lock.yaml": pnpm}).findings})

    def test_pnpm_v9_no_leading_slash_and_snapshots(self):
        pnpm = ('packages:\n  fetch-page-assets@1.2.9:\n    resolution: {integrity: sha512-x}\n'
                "snapshots:\n  'fetch-page-assets@1.2.9(react@18.2.0)':\n    dependencies: {}\n")
        self.assertIn(DEP, {f.signature_id for f in _scan({"pnpm-lock.yaml": pnpm}).findings})

    def test_npm_aliased_install_uses_authoritative_name(self):
        # An aliased install: the install-path segment is the ALIAS; the real package is meta['name'].
        lock = json.dumps({"packages": {
            "node_modules/innocent-alias": {"version": "4.2.11", "name": "html-to-gutenberg"}}})
        self.assertIn(DEP, {f.signature_id for f in _scan({"package-lock.json": lock}).findings})

    def test_v_prefixed_exact_pin(self):
        r = _scan({"package.json": json.dumps({"dependencies": {"fetch-page-assets": "v1.2.9"}})})
        self.assertIn(DEP, {f.signature_id for f in r.findings})

    def test_clean_lockfile_is_clean(self):
        lock = json.dumps({"packages": {"node_modules/react": {"version": "18.2.0"},
                                        "node_modules/lodash": {"version": "4.17.21"}}})
        r = _scan({"package-lock.json": lock})
        self.assertEqual([f.signature_id for f in r.findings], [])
        self.assertEqual(r.verdict, CLEAN)

    def test_malformed_files_do_not_crash(self):
        r = _scan({"package.json": "{ not json ,,", "pnpm-lock.yaml": "::: not: yaml ["})
        self.assertIsNone(r.error)
        self.assertEqual([f.signature_id for f in r.findings], [])

    def test_blocklist_is_loaded_from_signature(self):
        # The known-bad list is data-driven (shipped in signatures.yml), not hard-coded in the matcher.
        dep_sigs = [s for s in SIGS.get("dependency-audit", []) if s["id"] == DEP]
        self.assertTrue(dep_sigs and BAD in dep_sigs[0].get("known_bad", []))

    def test_allowlist_suppresses_by_signature(self):
        r = _scan({"package.json": json.dumps({"dependencies": {"html-to-gutenberg": "4.2.11"}})},
                  allow=[{"signature": DEP, "path_glob": "package.json"}])
        self.assertNotIn(DEP, {f.signature_id for f in r.findings})


if __name__ == "__main__":
    unittest.main()
