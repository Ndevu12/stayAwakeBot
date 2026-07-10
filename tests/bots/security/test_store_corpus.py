#!/usr/bin/env python3
"""AdvisoryStore + matcher over the offline corpus (#1120) — inline seed and corpus together,
and the full scan path resolving to INFECTED via the default cache."""
from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path

from stayawake.bots.security.dependencies import AdvisoryStore, db
from stayawake.bots.security.dependencies.purl import Purl
from stayawake.bots.security.matchers.dependency_audit import DependencyAuditMatcher
from stayawake.bots.security.models import INFECTED
from stayawake.bots.security.scanner import scan_target
from stayawake.bots.security.targets import LocalRepoTarget, ScanOptions
from tests.bots.security._osv_fixtures import mal_record, osv_zip

# A malicious-dependency-shaped signature: opts into the corpus AND carries an inline seed.
SIG = {"id": "malicious-dependency", "category": "supply-chain-dep", "severity": "critical",
       "matcher": "dependency-audit", "description": "known-malicious upstream package",
       "remediation": "manual", "corpus": True, "known_bad": ["html-to-gutenberg@4.2.11"]}


def _target(files):
    d = Path(tempfile.mkdtemp())
    for rel, content in files.items():
        (d / rel).parent.mkdir(parents=True, exist_ok=True)
        (d / rel).write_text(content, encoding="utf-8")
    return LocalRepoTarget(d, "t", ScanOptions())


class TestStoreCorpus(unittest.TestCase):
    def setUp(self):
        self.cache = Path(tempfile.mkdtemp())
        db._CORPUS_MEMO.clear()
        z = osv_zip({"MAL-1.json": mal_record("evil-lib", ["9.9.9"], rid="MAL-2024-777")})
        db.write_manifest(self.cache, [db.update_ecosystem("npm", self.cache, fetch=lambda b: z)])

    def tearDown(self):
        db._CORPUS_MEMO.clear()

    def test_default_store_matches_corpus_with_osv_id(self):
        store = AdvisoryStore.default([SIG], cache_dir=self.cache)
        adv = store.advisory_for(Purl("npm", "evil-lib", "9.9.9"))
        self.assertIsNotNone(adv)
        self.assertEqual(adv.osv_id, "MAL-2024-777")

    def test_inline_seed_still_matches_and_has_no_osv_id(self):
        store = AdvisoryStore.default([SIG], cache_dir=self.cache)
        adv = store.advisory_for(Purl("npm", "html-to-gutenberg", "4.2.11"))
        self.assertIsNotNone(adv)
        self.assertIsNone(adv.osv_id)

    def test_no_corpus_signature_disables_corpus(self):
        # A signature without `corpus: true` (and no known_bad) never consults the cache.
        store = AdvisoryStore.default([{"id": "x"}], cache_dir=self.cache)
        self.assertTrue(store.is_empty())
        self.assertIsNone(store.advisory_for(Purl("npm", "evil-lib", "9.9.9")))

    def test_matcher_corpus_hit_cites_osv_id(self):
        matcher = DependencyAuditMatcher(
            store_factory=lambda s: AdvisoryStore.default(s, cache_dir=self.cache))
        target = _target({"package-lock.json": json.dumps(
            {"packages": {"node_modules/evil-lib": {"version": "9.9.9"}}})})
        findings = matcher.scan(target, [SIG])
        self.assertEqual([f.signature_id for f in findings], ["malicious-dependency"])
        self.assertIn("MAL-2024-777", findings[0].evidence)

    def test_range_matched_malware_is_infected(self):
        # #1124: a package matched ONLY by a range (no explicit version) → INFECTED in range, clean
        # outside it. Exercises resolver → corpus range eval → verdict, offline.
        cache = Path(tempfile.mkdtemp())
        db._CORPUS_MEMO.clear()
        z = osv_zip({"MAL.json": {"id": "MAL-2024-99", "affected": [
            {"package": {"ecosystem": "npm", "name": "range-evil"},
             "ranges": [{"type": "SEMVER", "events": [{"introduced": "1.0.0"}, {"fixed": "2.0.0"}]}]}]}})
        db.write_manifest(cache, [db.update_ecosystem("npm", cache, fetch=lambda b: z)])
        matcher = DependencyAuditMatcher(store_factory=lambda s: AdvisoryStore.default(s, cache_dir=cache))

        def scan(ver):
            t = _target({"package-lock.json": json.dumps(
                {"packages": {"node_modules/range-evil": {"version": ver}}})})
            return [f.signature_id for f in matcher.scan(t, [SIG])]

        self.assertEqual(scan("1.5.0"), ["malicious-dependency"])   # in [1.0.0, 2.0.0)
        self.assertEqual(scan("2.0.0"), [])                          # fixed → out of range
        self.assertEqual(scan("0.9.0"), [])                          # before introduced
        db._CORPUS_MEMO.clear()

    def test_full_scan_path_is_infected_via_default_cache_env(self):
        # Prove the REGISTRY default matcher (no explicit cache_dir) reads the cache through the
        # SAW_ADVISORY_CACHE_DIR override and reaches an INFECTED verdict end-to-end.
        old = os.environ.get("SAW_ADVISORY_CACHE_DIR")
        os.environ["SAW_ADVISORY_CACHE_DIR"] = str(self.cache)
        db._CORPUS_MEMO.clear()
        try:
            target = _target({"package-lock.json": json.dumps(
                {"packages": {"node_modules/evil-lib": {"version": "9.9.9"}}})})
            r = scan_target(target, {"dependency-audit": [SIG]}, [])
            self.assertEqual(r.verdict, INFECTED)
            self.assertIn("MAL-2024-777", r.findings[0].evidence)
        finally:
            if old is None:
                os.environ.pop("SAW_ADVISORY_CACHE_DIR", None)
            else:
                os.environ["SAW_ADVISORY_CACHE_DIR"] = old
            db._CORPUS_MEMO.clear()


class _StubCorpus:
    def malicious_match(self, purl):
        return None

    def vulnerability_matches(self, purl):
        return []

    def is_empty(self):
        return True


class TestLazyCorpusLoad(unittest.TestCase):
    """The ~10s corpus build must be DEFERRED to first query — a repo with no dependency files never
    resolves a package, so it must never pay the load (#1163)."""

    def _counting_store(self):
        calls = {"n": 0}

        def loader():
            calls["n"] += 1
            return _StubCorpus()
        store = AdvisoryStore(AdvisoryStore._inline_index([SIG]), corpus_signature=SIG,
                              corpus_loader=loader)
        return store, calls

    def test_construction_does_not_load(self):
        _, calls = self._counting_store()
        self.assertEqual(calls["n"], 0)

    def test_is_empty_does_not_load_with_a_seed(self):
        store, calls = self._counting_store()
        self.assertFalse(store.is_empty())          # inline seed present
        self.assertEqual(calls["n"], 0, "is_empty must short-circuit on the seed, not build the corpus")

    def test_seed_hit_does_not_load(self):
        store, calls = self._counting_store()
        self.assertIsNotNone(store.advisory_for(Purl("npm", "html-to-gutenberg", "4.2.11")))
        self.assertEqual(calls["n"], 0, "an inline-seed hit needs no corpus")

    def test_seed_miss_loads_once(self):
        store, calls = self._counting_store()
        store.advisory_for(Purl("npm", "some-other-pkg", "1.0.0"))
        store.advisory_for(Purl("npm", "yet-another", "2.0.0"))
        self.assertEqual(calls["n"], 1, "corpus builds on first miss, then is cached")

    def test_no_lockfile_scan_never_builds_corpus(self):
        # End-to-end: the matcher over a repo with NO lockfile must not trigger db.load_corpus.
        calls = {"n": 0}
        real = db.load_corpus

        def spy(*a, **k):
            calls["n"] += 1
            return real(*a, **k)
        db.load_corpus = spy
        try:
            target = _target({"src/app.js": "const x = 1;\n"})     # no lockfile / manifest
            DependencyAuditMatcher().scan(target, [SIG])
            self.assertEqual(calls["n"], 0, "no dependency files → corpus must never be built")
        finally:
            db.load_corpus = real


if __name__ == "__main__":
    unittest.main()
