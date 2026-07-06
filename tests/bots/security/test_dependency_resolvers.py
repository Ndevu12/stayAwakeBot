#!/usr/bin/env python3
"""Unit tests for the decomposed dependency-audit spine (#1119).

Exercises each piece in isolation — `Purl`, `NpmResolver`, `AdvisoryStore`, and the thin
`DependencyAuditMatcher` coordinator with an injected in-memory store — so a regression is
localised to one component instead of only showing up in the end-to-end scan
(`test_dependency_audit.py` covers that path).
"""
from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from stayawake.bots.security.dependencies import (
    Advisory, AdvisoryStore, Purl, ResolvedDependency,
)
from stayawake.bots.security.dependencies.resolvers import NpmResolver
from stayawake.bots.security.matchers.dependency_audit import DependencyAuditMatcher
from stayawake.bots.security.targets import LocalRepoTarget, ScanOptions

BAD = "html-to-gutenberg@4.2.11"
SIG = {"id": "malicious-dependency", "category": "supply-chain-dep", "severity": "critical",
       "description": "known-malicious upstream package", "remediation": "manual",
       "known_bad": [BAD, "fetch-page-assets@1.2.9"]}


def _target(files):
    d = Path(tempfile.mkdtemp())
    for rel, content in files.items():
        p = d / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content, encoding="utf-8")
    return LocalRepoTarget(d, "t", ScanOptions())


# ── Purl ──────────────────────────────────────────────────────────────────────────────
class TestPurl(unittest.TestCase):
    def test_coordinate_is_name_at_version(self):
        self.assertEqual(Purl("npm", "html-to-gutenberg", "4.2.11").coordinate,
                         "html-to-gutenberg@4.2.11")

    def test_scoped_name_round_trips_in_coordinate(self):
        self.assertEqual(Purl("npm", "@acme/foo", "1.0.0").coordinate, "@acme/foo@1.0.0")

    def test_str_is_a_purl(self):
        self.assertEqual(str(Purl("pypi", "requests", "2.0")), "pkg:pypi/requests@2.0")

    def test_frozen_and_hashable(self):
        a, b = Purl("npm", "x", "1.0.0"), Purl("npm", "x", "1.0.0")
        self.assertEqual(a, b)
        self.assertEqual(len({a, b}), 1)          # usable in the matcher's dedup set

    def test_resolved_dependency_source_name(self):
        dep = ResolvedDependency(Purl("npm", "x", "1.0.0"), "a/b/package-lock.json")
        self.assertEqual(dep.source_name, "package-lock.json")


# ── AdvisoryStore ─────────────────────────────────────────────────────────────────────
class TestAdvisoryStore(unittest.TestCase):
    def test_from_signatures_indexes_known_bad(self):
        store = AdvisoryStore.from_signatures([SIG])
        self.assertFalse(store.is_empty())
        self.assertIsNotNone(store.advisory_for(Purl("npm", "html-to-gutenberg", "4.2.11")))

    def test_advisory_carries_owning_signature(self):
        store = AdvisoryStore.from_signatures([SIG])
        adv = store.advisory_for(Purl("npm", "fetch-page-assets", "1.2.9"))
        self.assertEqual(adv.signature["id"], "malicious-dependency")

    def test_clean_version_is_not_matched(self):
        store = AdvisoryStore.from_signatures([SIG])
        self.assertIsNone(store.advisory_for(Purl("npm", "html-to-gutenberg", "4.3.0")))

    def test_empty_when_no_known_bad(self):
        self.assertTrue(AdvisoryStore.from_signatures([{"id": "x"}]).is_empty())

    def test_bare_name_entry_is_rejected(self):
        # An entry with no version separator must not match every version of the package.
        store = AdvisoryStore.from_signatures([{"known_bad": ["html-to-gutenberg", "@scope"]}])
        self.assertTrue(store.is_empty())

    def test_in_memory_store_construction(self):
        # The matcher depends on the type, not the source — a test can build one directly.
        store = AdvisoryStore({"x@1.0.0": Advisory(signature=SIG)})
        self.assertIsNotNone(store.advisory_for(Purl("npm", "x", "1.0.0")))


# ── NpmResolver ───────────────────────────────────────────────────────────────────────
class TestNpmResolver(unittest.TestCase):
    def _resolve(self, files):
        return list(NpmResolver().resolve(_target(files)))

    def test_manifest_exact_pin_yields_purl_with_source(self):
        deps = self._resolve({"package.json": json.dumps(
            {"dependencies": {"html-to-gutenberg": "4.2.11"}})})
        self.assertEqual(len(deps), 1)
        self.assertEqual(deps[0].purl, Purl("npm", "html-to-gutenberg", "4.2.11"))
        self.assertEqual(deps[0].source_path, "package.json")

    def test_manifest_range_is_not_resolved(self):
        self.assertEqual(
            self._resolve({"package.json": json.dumps(
                {"dependencies": {"html-to-gutenberg": "^4.2.11"}})}), [])

    def test_lockfile_transitive_is_resolved(self):
        lock = json.dumps({"packages": {
            "node_modules/a/node_modules/fetch-page-assets": {"version": "1.2.9"}}})
        purls = {d.purl for d in self._resolve({"package-lock.json": lock})}
        self.assertIn(Purl("npm", "fetch-page-assets", "1.2.9"), purls)

    def test_ecosystem_is_npm_for_yarn_and_pnpm(self):
        yarn = '"html-to-gutenberg@^4.2.11":\n  version "4.2.11"\n'
        pnpm = "packages:\n  /fetch-page-assets@1.2.9:\n    dev: false\n"
        for d in self._resolve({"yarn.lock": yarn, "pnpm-lock.yaml": pnpm}):
            self.assertEqual(d.purl.type, "npm")


# ── Coordinator with an injected store (dependency inversion) ─────────────────────────
class TestMatcherInjection(unittest.TestCase):
    def test_coordinator_uses_injected_store(self):
        # Inject a store that flags a package the inline seed does NOT know — proving the
        # matcher depends on the store abstraction, not on signatures.yml.
        factory = lambda sigs: AdvisoryStore({"left-pad@1.3.0": Advisory(signature=SIG)})
        matcher = DependencyAuditMatcher(store_factory=factory)
        target = _target({"package.json": json.dumps({"dependencies": {"left-pad": "1.3.0"}})})
        findings = matcher.scan(target, signatures=[])
        self.assertEqual([f.signature_id for f in findings], ["malicious-dependency"])
        self.assertIn("left-pad@1.3.0", findings[0].evidence)

    def test_empty_store_short_circuits(self):
        matcher = DependencyAuditMatcher(store_factory=lambda sigs: AdvisoryStore({}))
        target = _target({"package.json": json.dumps({"dependencies": {"left-pad": "1.3.0"}})})
        self.assertEqual(matcher.scan(target, signatures=[]), [])


if __name__ == "__main__":
    unittest.main()
