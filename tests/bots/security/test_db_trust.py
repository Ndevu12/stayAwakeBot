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
from contextlib import redirect_stderr, redirect_stdout
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


class TestSchemaSkew(unittest.TestCase):
    """#1137 — an older-format cache (manifest schema ≠ this saw's) is a benign version skew, NOT
    tampering. It must be diagnosed as "older format, run db update", never trip the
    "integrity check FAILED / tampered" alarm (which would train users to ignore the real one),
    and still fail closed (falls back to the inline seed)."""

    def _make_old(self, cache, *, tamper=False):
        # a valid schema-2 cache, then downgrade the manifest's schema to mimic an older `saw`
        _build(cache, {"MAL.json": mal_record("evil", ["1.0.0"])})
        if tamper:                                    # mutate a records file too — schema gate must WIN
            rec = cache / "records" / "npm.jsonl"
            rec.write_text(rec.read_text() + "garbage\n")
        mp = cache / "manifest.json"
        m = json.loads(mp.read_text()); m["schema"] = 1
        mp.write_text(json.dumps(m))
        db._CORPUS_MEMO.clear()

    def test_load_falls_back_to_seed_without_crying_tamper(self):
        cache = Path(tempfile.mkdtemp())
        self._make_old(cache, tamper=True)            # even mutated records → still "older", not "tampered"
        buf = io.StringIO()
        with redirect_stderr(buf):
            corpus = db.load_corpus(cache)
        out = buf.getvalue()
        self.assertIsNone(corpus)                     # → inline seed
        self.assertIn("older format", out)
        self.assertNotIn("integrity check FAILED", out)

    def test_cache_status_reports_incompatible_not_tampered(self):
        cache = Path(tempfile.mkdtemp())
        self._make_old(cache)
        s = db.cache_status(cache)
        self.assertTrue(s["present"])
        self.assertFalse(s["schema_compatible"])
        self.assertFalse(s["integrity_ok"])           # unusable → fail-closed for naive callers
        self.assertEqual(s["mismatches"], [])         # but NO spurious per-ecosystem "tamper" list

    def test_db_status_cli_says_older_format(self):
        cache = Path(tempfile.mkdtemp())
        self._make_old(cache)
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            rc = db_cmd.run_status(argparse.Namespace(
                cache_dir=str(cache), require_snapshot=None, max_age_days=None))
        self.assertEqual(rc, 2)                        # fail closed for CI
        self.assertIn("older format", out.getvalue())
        self.assertNotIn("tampered", out.getvalue() + err.getvalue())

    def test_require_db_gate_says_older_format(self):
        from stayawake.bots.security import service
        cache = Path(tempfile.mkdtemp())
        self._make_old(cache)
        os.environ["SAW_ADVISORY_CACHE_DIR"] = str(cache)
        db._CORPUS_MEMO.clear()
        try:
            err = io.StringIO()
            with redirect_stderr(err):
                rc = service._require_db_or_error()
            self.assertEqual(rc, 2)                     # fail closed
            self.assertIn("older format", err.getvalue())
            self.assertNotIn("integrity check FAILED", err.getvalue())
        finally:
            os.environ.pop("SAW_ADVISORY_CACHE_DIR", None)
            db._CORPUS_MEMO.clear()


class TestCorruptManifest(unittest.TestCase):
    """#1137 (adversarial follow-up) — a manifest that parses as valid JSON but is NOT an object
    (`null`, an array, a scalar — from a partial write or a tamper) must degrade to 'no usable
    cache', never crash the scan with an AttributeError from `.get()` on a non-dict."""

    def _cache_with_manifest(self, raw_text):
        cache = Path(tempfile.mkdtemp())
        _build(cache, {"MAL.json": mal_record("evil", ["1.0.0"])})
        (cache / "manifest.json").write_text(raw_text)
        db._CORPUS_MEMO.clear()
        return cache

    def test_non_dict_manifest_does_not_crash_load(self):
        for raw in ("null", "[1, 2, 3]", "42", "\"hi\""):
            cache = self._cache_with_manifest(raw)
            with redirect_stderr(io.StringIO()):
                self.assertIsNone(db.load_corpus(cache))         # → inline seed, no AttributeError

    def test_non_dict_manifest_reads_as_absent(self):
        for raw in ("null", "[1, 2, 3]", "42"):
            s = db.cache_status(self._cache_with_manifest(raw))
            self.assertFalse(s["present"])                       # treated like a missing cache

    def test_malformed_ecosystems_shape_does_not_crash(self):
        # manifest IS a dict (schema 2) but the ecosystems it iterates are malformed — a non-dict
        # `ecosystems`, or a non-dict entry. Must degrade (dropped/empty), never crash `.items()`.
        for eco_val in ("[1, 2, 3]", "\"oops\"", "{\"npm\": [1, 2]}", "{\"npm\": null}"):
            cache = Path(tempfile.mkdtemp())
            _build(cache, {"MAL.json": mal_record("evil", ["1.0.0"])})
            mp = cache / "manifest.json"
            m = json.loads(mp.read_text()); m["ecosystems"] = json.loads(eco_val)
            mp.write_text(json.dumps(m)); db._CORPUS_MEMO.clear()
            with redirect_stderr(io.StringIO()):
                corpus = db.load_corpus(cache)           # no AttributeError from .items()/.get()
            s = db.cache_status(cache)                    # nor here
            self.assertTrue(s["present"])
            self.assertEqual(s["ecosystems"], {})         # malformed entries dropped
            # empty corpus → nothing trusted from the malformed cache
            self.assertTrue(corpus is None
                            or corpus.malicious_match(Purl("npm", "evil", "1.0.0")) is None)

    def test_non_numeric_counts_do_not_crash_status(self):
        # a structurally-valid schema-2 manifest whose count fields are corrupt (null/str/list) must
        # not crash the status / --require-db surface on a sum() TypeError — coerce each to 0. (The
        # records sha256 is untouched, so integrity stays OK and this isolates the numeric path.)
        for bad in (None, "lots", [1, 2]):
            cache = Path(tempfile.mkdtemp())
            _build(cache, {"MAL.json": mal_record("evil", ["1.0.0"])})
            mp = cache / "manifest.json"
            m = json.loads(mp.read_text())
            m["ecosystems"]["npm"]["malicious"] = bad
            m["ecosystems"]["npm"]["vulnerabilities"] = bad
            mp.write_text(json.dumps(m)); db._CORPUS_MEMO.clear()
            s = db.cache_status(cache)                    # no TypeError
            self.assertIsInstance(s["total_malicious"], int)
            self.assertEqual((s["total_malicious"], s["total_vulnerabilities"]), (0, 0))
            with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
                rc = db_cmd.run_status(argparse.Namespace(
                    cache_dir=str(cache), require_snapshot=None, max_age_days=None))
            self.assertEqual(rc, 0)                        # runs to completion, integrity still OK

    def test_gates_fail_closed_on_non_dict_manifest(self):
        from stayawake.bots.security import service
        cache = self._cache_with_manifest("null")
        with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            rc = db_cmd.run_status(argparse.Namespace(
                cache_dir=str(cache), require_snapshot=None, max_age_days=None))
        self.assertEqual(rc, 1)                                  # db status: not found
        os.environ["SAW_ADVISORY_CACHE_DIR"] = str(cache)
        db._CORPUS_MEMO.clear()
        try:
            with redirect_stderr(io.StringIO()):
                self.assertEqual(service._require_db_or_error(), 2)   # --require-db: fail closed
        finally:
            os.environ.pop("SAW_ADVISORY_CACHE_DIR", None)
            db._CORPUS_MEMO.clear()


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

    def test_max_age_unknown_fails_closed(self):
        # --max-age-days requested but age unknown (legacy manifest, no generated_at) → fail closed,
        # never silently pass a DB of unknown freshness.
        cache = Path(tempfile.mkdtemp())
        _build(cache, {"MAL.json": mal_record("evil", ["1.0.0"])})
        mp = cache / "manifest.json"
        m = json.loads(mp.read_text()); m.pop("generated_at", None)
        mp.write_text(json.dumps(m))
        self.assertEqual(self._run(cache, max_age_days=7), 3)             # not 0
        self.assertEqual(self._run(cache), 0)                            # no --max-age-days → healthy


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
