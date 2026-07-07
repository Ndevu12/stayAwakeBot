#!/usr/bin/env python3
"""DB trust hardening (#1126): snapshot fingerprint, content-hash integrity, `saw db status`, and
the `--require-db` fail-closed gate. Offline throughout (synthetic OSV zips)."""
from __future__ import annotations

import argparse
import io
import json
import os
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

from stayawake.bots.security.dependencies import db
from stayawake.bots.security.dependencies.purl import Purl
from stayawake.cli.commands import db as db_cmd
from tests.bots.security._osv_fixtures import mal_record, osv_zip


def _build(cache, members):
    db._CORPUS_MEMO.clear()
    z = osv_zip(members)
    return db.write_manifest(cache, [db.update_ecosystem("npm", cache, fetch=lambda b: z)])


class TestSnapshot(unittest.TestCase):
    def test_manifest_has_snapshot_and_timestamp(self):
        m = _build(Path(tempfile.mkdtemp()), {"MAL.json": mal_record("evil", ["1.0.0"])})
        self.assertEqual(m["schema"], 2)
        self.assertTrue(m["snapshot"])
        self.assertTrue(m["generated_at"])

    def test_snapshot_is_deterministic_and_data_sensitive(self):
        members = {"MAL.json": mal_record("evil", ["1.0.0"])}
        a = _build(Path(tempfile.mkdtemp()), members)["snapshot"]
        b = _build(Path(tempfile.mkdtemp()), members)["snapshot"]           # same data → same snapshot
        c = _build(Path(tempfile.mkdtemp()), {"MAL.json": mal_record("evil", ["2.0.0"])})["snapshot"]
        self.assertEqual(a, b)
        self.assertNotEqual(a, c)


class TestCacheStatus(unittest.TestCase):
    def test_absent(self):
        self.assertFalse(db.cache_status(Path(tempfile.mkdtemp()))["present"])

    def test_present_counts_and_integrity(self):
        cache = Path(tempfile.mkdtemp())
        _build(cache, {"MAL.json": mal_record("evil", ["1.0.0"]),
                       "CVE.json": {"id": "CVE-1", "affected": [{"package": {"ecosystem": "npm",
                                    "name": "vulnpkg"}, "versions": ["3.0.0"]}]}})
        s = db.cache_status(cache)
        self.assertTrue(s["present"] and s["integrity_ok"])
        self.assertEqual((s["total_malicious"], s["total_vulnerabilities"]), (1, 1))
        self.assertEqual(s["age_days"], 0)

    def test_age_days_parsing(self):
        self.assertGreater(db._age_days("2020-01-01T00:00:00+00:00"), 1000)
        self.assertIsNone(db._age_days(None))
        self.assertIsNone(db._age_days("not-a-date"))


class TestIntegrity(unittest.TestCase):
    def test_tampered_records_file_is_rejected(self):
        cache = Path(tempfile.mkdtemp())
        _build(cache, {"MAL.json": mal_record("evil", ["1.0.0"])})
        # inject a fake malicious record — the sha no longer matches the manifest
        rec = cache / "records" / "npm.jsonl"
        rec.write_text(rec.read_text() + json.dumps(
            {"id": "MAL-INJECTED", "malicious": True,
             "affected": [{"ecosystem": "npm", "name": "injected", "versions": ["1.0.0"]}]}) + "\n")
        db._CORPUS_MEMO.clear()

        self.assertFalse(db.cache_status(cache)["integrity_ok"])
        self.assertEqual(db.cache_status(cache)["mismatches"], ["npm"])
        # load rejects the tampered ecosystem → the injected package is NOT trusted
        import sys
        buf = io.StringIO()
        old, sys.stderr = sys.stderr, buf
        try:
            corpus = db.load_corpus(cache)
        finally:
            sys.stderr = old
        self.assertIn("integrity check FAILED", buf.getvalue())
        self.assertTrue(corpus is None or corpus.malicious_match(Purl("npm", "injected", "1.0.0")) is None)


class TestDbStatusCli(unittest.TestCase):
    def _run(self, cache, **kw):
        fields = dict(cache_dir=str(cache), require_snapshot=None, max_age_days=None)
        fields.update(kw)
        with redirect_stdout(io.StringIO()):
            return db_cmd.run_status(argparse.Namespace(**fields))

    def test_healthy_exit_zero(self):
        cache = Path(tempfile.mkdtemp())
        _build(cache, {"MAL.json": mal_record("evil", ["1.0.0"])})
        self.assertEqual(self._run(cache), 0)

    def test_absent_exit_one(self):
        self.assertEqual(self._run(Path(tempfile.mkdtemp())), 1)

    def test_require_snapshot_mismatch(self):
        cache = Path(tempfile.mkdtemp())
        _build(cache, {"MAL.json": mal_record("evil", ["1.0.0"])})
        self.assertEqual(self._run(cache, require_snapshot="deadbeef"), 3)

    def test_max_age_exceeded(self):
        cache = Path(tempfile.mkdtemp())
        _build(cache, {"MAL.json": mal_record("evil", ["1.0.0"])})
        # rewrite generated_at to old (outside the integrity hash, so the cache stays valid)
        mp = cache / "manifest.json"
        m = json.loads(mp.read_text()); m["generated_at"] = "2020-01-01T00:00:00+00:00"
        mp.write_text(json.dumps(m))
        self.assertEqual(self._run(cache, max_age_days=7), 3)


class TestRequireDbGate(unittest.TestCase):
    def _with_cache_env(self, cache):
        os.environ["SAW_ADVISORY_CACHE_DIR"] = str(cache)
        db._CORPUS_MEMO.clear()

    def tearDown(self):
        os.environ.pop("SAW_ADVISORY_CACHE_DIR", None)
        db._CORPUS_MEMO.clear()

    def test_gate_fails_closed_when_absent(self):
        from stayawake.bots.security import service
        self._with_cache_env(Path(tempfile.mkdtemp()))          # empty → no manifest
        self.assertEqual(service._require_db_or_error(), 2)

    def test_gate_passes_when_valid(self):
        from stayawake.bots.security import service
        cache = Path(tempfile.mkdtemp())
        _build(cache, {"MAL.json": mal_record("evil", ["1.0.0"])})
        self._with_cache_env(cache)
        self.assertIsNone(service._require_db_or_error())

    def test_scan_cli_exposes_require_db(self):
        from stayawake.cli.dispatch import build_parser
        self.assertTrue(build_parser().parse_args(["scan", "--require-db"]).require_db)
        self.assertFalse(build_parser().parse_args(["scan"]).require_db)


if __name__ == "__main__":
    unittest.main()
