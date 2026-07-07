#!/usr/bin/env python3
"""OSV record parsing + malicious classification (#1120)."""
from __future__ import annotations

import unittest

from stayawake.bots.security.dependencies.osv import is_malicious, parse_osv_record


class TestIsMalicious(unittest.TestCase):
    def test_mal_id(self):
        self.assertTrue(is_malicious({"id": "MAL-2024-1"}))

    def test_mal_alias(self):
        self.assertTrue(is_malicious({"id": "GHSA-x", "aliases": ["MAL-2024-9"]}))

    def test_database_specific_type_malware(self):
        self.assertTrue(is_malicious({"id": "GHSA-x", "database_specific": {"type": "malware"}}))

    def test_cwe_506(self):
        self.assertTrue(is_malicious({"id": "GHSA-x", "database_specific": {"cwe_ids": ["CWE-506"]}}))

    def test_ordinary_cve_is_not_malicious(self):
        self.assertFalse(is_malicious({"id": "GHSA-x", "aliases": ["CVE-2024-1"],
                                       "database_specific": {"cwe_ids": ["CWE-79"]}}))

    def test_text_mention_does_not_classify(self):
        # Structured signals only — a CVE that merely says "malicious" must NOT be flagged as malware.
        self.assertFalse(is_malicious({"id": "CVE-2024-2", "summary": "malicious input crash"}))


class TestParseOsvRecord(unittest.TestCase):
    def test_extracts_explicit_versions(self):
        rec = parse_osv_record({"id": "MAL-2024-1",
                                "affected": [{"package": {"ecosystem": "npm", "name": "evil"},
                                              "versions": ["1.0.0", "1.0.1"]}]})
        self.assertEqual(rec.id, "MAL-2024-1")
        self.assertTrue(rec.malicious)
        self.assertEqual(rec.affected[0].name, "evil")
        self.assertEqual(rec.affected[0].versions, frozenset({"1.0.0", "1.0.1"}))

    def test_ranges_only_entry_is_dropped(self):
        # No explicit versions → nothing matchable in phase 1b → None (deferred to #1124).
        self.assertIsNone(parse_osv_record(
            {"id": "MAL-2024-2",
             "affected": [{"package": {"ecosystem": "npm", "name": "r"},
                           "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}]}]}]}))

    def test_no_id_is_none(self):
        self.assertIsNone(parse_osv_record({"affected": [{"package": {"ecosystem": "npm",
                                                                      "name": "x"}, "versions": ["1"]}]}))

    def test_no_affected_is_none(self):
        self.assertIsNone(parse_osv_record({"id": "MAL-2024-3"}))

    def test_non_dict_is_none(self):
        self.assertIsNone(parse_osv_record("not a dict"))


if __name__ == "__main__":
    unittest.main()
