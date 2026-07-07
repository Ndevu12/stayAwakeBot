#!/usr/bin/env python3
"""`saw db update` command wiring (#1120) — stubbed fetch, no network."""
from __future__ import annotations

import argparse
import io
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

from stayawake.bots.security.dependencies import db
from stayawake.bots.security.dependencies.purl import Purl
from stayawake.cli.commands import db as db_cmd
from stayawake.cli.dispatch import build_parser
from tests.bots.security._osv_fixtures import mal_record, osv_zip


class TestCliDb(unittest.TestCase):
    def setUp(self):
        self.cache = Path(tempfile.mkdtemp())
        db._CORPUS_MEMO.clear()
        self._orig_fetch = db.fetch_ecosystem_zip
        z = osv_zip({"MAL-1.json": mal_record("evil", ["1.0.0"], rid="MAL-2024-42")})
        db.fetch_ecosystem_zip = lambda bucket, **k: z      # stub the only network call

    def tearDown(self):
        db.fetch_ecosystem_zip = self._orig_fetch
        db._CORPUS_MEMO.clear()

    def test_db_update_populates_cache_offline(self):
        args = argparse.Namespace(ecosystems=None, cache_dir=str(self.cache), no_stream=True)
        out = io.StringIO()
        with redirect_stdout(out):
            rc = db_cmd.run_update(args)
        self.assertEqual(rc, 0)
        self.assertIn("Advisory database updated", out.getvalue())
        self.assertIsNotNone(db.load_corpus(self.cache).malicious_match(Purl("npm", "evil", "1.0.0")))

    def test_unsupported_ecosystem_exit_2(self):
        args = argparse.Namespace(ecosystems=["cargo"], cache_dir=str(self.cache), no_stream=True)
        with redirect_stdout(io.StringIO()):
            rc = db_cmd.run_update(args)
        self.assertEqual(rc, 2)

    def test_db_subcommand_is_registered(self):
        parser = build_parser()
        ns = parser.parse_args(["db", "update", "--cache-dir", str(self.cache), "--no-stream"])
        self.assertTrue(hasattr(ns, "func"))
        self.assertEqual(ns.cache_dir, str(self.cache))


if __name__ == "__main__":
    unittest.main()
