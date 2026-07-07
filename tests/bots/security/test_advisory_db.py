#!/usr/bin/env python3
"""Offline advisory DB: update pipeline, cache round-trip, determinism, offline load (#1120).

Fully offline — a stubbed `fetch` returns a synthetic OSV zip, so no test touches the network.
"""
from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from stayawake.bots.security.dependencies import db
from stayawake.bots.security.dependencies.purl import Purl
from tests.bots.security._osv_fixtures import mal_record, osv_zip


def _fetch(zip_bytes):
    return lambda bucket: zip_bytes


class TestAdvisoryDb(unittest.TestCase):
    def setUp(self):
        self.cache = Path(tempfile.mkdtemp())
        db._CORPUS_MEMO.clear()

    def test_update_keeps_both_tiers_with_explicit_versions(self):
        z = osv_zip({
            "MAL-1.json": mal_record("evil-pkg", ["1.0.0"], rid="MAL-2024-1"),
            # an ordinary CVE — kept as the vulnerability tier (not malware)
            "GHSA-cve.json": {"id": "GHSA-x", "aliases": ["CVE-2024-9"],
                              "affected": [{"package": {"ecosystem": "npm", "name": "legit"},
                                            "versions": ["2.0.0"]}]},
            # malicious but range-only (no explicit versions) → deferred to #1124 → dropped
            "MAL-range.json": {"id": "MAL-2024-2",
                               "affected": [{"package": {"ecosystem": "npm", "name": "rangeonly"},
                                             "ranges": [{"type": "SEMVER",
                                                         "events": [{"introduced": "0"}]}]}]},
        })
        res = db.update_ecosystem("npm", self.cache, fetch=_fetch(z))
        self.assertEqual((res["count"], res["malicious"], res["vulnerabilities"]), (2, 1, 1))
        db.write_manifest(self.cache, [res])
        corpus = db.load_corpus(self.cache)
        self.assertIsNotNone(corpus.malicious_match(Purl("npm", "evil-pkg", "1.0.0")))
        self.assertIsNone(corpus.malicious_match(Purl("npm", "legit", "2.0.0")))    # a CVE, not malware
        self.assertTrue(corpus.vulnerability_matches(Purl("npm", "legit", "2.0.0")))
        self.assertIsNone(corpus.malicious_match(Purl("npm", "rangeonly", "0.5.0")))  # dropped

    def test_cache_is_deterministic(self):
        z = osv_zip({"MAL-b.json": mal_record("b", ["2.0.0"], rid="MAL-2024-2"),
                     "MAL-a.json": mal_record("a", ["1.0.0"], rid="MAL-2024-1")})
        a = db.update_ecosystem("npm", self.cache, fetch=_fetch(z))
        b = db.update_ecosystem("npm", Path(tempfile.mkdtemp()), fetch=_fetch(z))
        self.assertEqual(a["sha256"], b["sha256"])      # same export → identical bytes

    def test_load_corpus_none_when_no_cache(self):
        self.assertIsNone(db.load_corpus(Path(tempfile.mkdtemp())))

    def test_unsupported_ecosystem_raises_before_fetch(self):
        called = []
        with self.assertRaises(ValueError):        # "hex" (Elixir) is not a supported ecosystem
            db.update_ecosystem("hex", self.cache, fetch=lambda b: called.append(b) or b"")
        self.assertEqual(called, [])

    def test_update_writes_manifest_and_invalidates_memo(self):
        z = osv_zip({"MAL-1.json": mal_record("evil", ["1.0.0"])})
        # Populate the memo with a "no cache yet" read, then update must invalidate it.
        self.assertIsNone(db.load_corpus(self.cache))
        manifest = db.update(["npm"], self.cache, fetch=_fetch(z))
        self.assertIn("npm", manifest["ecosystems"])
        self.assertTrue((self.cache / "manifest.json").exists())
        self.assertIsNotNone(db.load_corpus(self.cache).malicious_match(Purl("npm", "evil", "1.0.0")))

    def test_malformed_zip_member_is_skipped(self):
        z = osv_zip({"good.json": mal_record("evil", ["1.0.0"])})
        # append a junk member
        import io
        import zipfile
        buf = io.BytesIO(z)
        with zipfile.ZipFile(buf, "a") as zf:
            zf.writestr("broken.json", "{ not json")
        res = db.update_ecosystem("npm", self.cache, fetch=_fetch(buf.getvalue()))
        self.assertEqual(res["count"], 1)               # junk skipped, good kept


if __name__ == "__main__":
    unittest.main()
