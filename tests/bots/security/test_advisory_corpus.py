#!/usr/bin/env python3
"""AdvisoryCorpus lookup (#1120) — pure, no I/O."""
from __future__ import annotations

import unittest

from stayawake.bots.security.dependencies.corpus import AdvisoryCorpus
from stayawake.bots.security.dependencies.osv import OsvAffected, OsvRecord
from stayawake.bots.security.dependencies.purl import Purl


def _rec(name, versions, rid="MAL-2024-1", ecosystem="npm", malicious=True):
    return OsvRecord(id=rid, aliases=(), malicious=malicious,
                     affected=(OsvAffected(ecosystem, name, frozenset(versions)),))


class TestAdvisoryCorpus(unittest.TestCase):
    def setUp(self):
        self.corpus = AdvisoryCorpus.from_records([
            _rec("evil", ["1.0.0", "1.0.1"]),
            _rec("also-bad", ["2.3.4"], rid="MAL-2024-2"),
        ])

    def test_match_exact_version(self):
        rec = self.corpus.malicious_match(Purl("npm", "evil", "1.0.1"))
        self.assertIsNotNone(rec)
        self.assertEqual(rec.id, "MAL-2024-1")

    def test_clean_version_no_match(self):
        self.assertIsNone(self.corpus.malicious_match(Purl("npm", "evil", "1.0.2")))

    def test_unknown_package_no_match(self):
        self.assertIsNone(self.corpus.malicious_match(Purl("npm", "innocent", "1.0.0")))

    def test_ecosystem_case_insensitive(self):
        # OSV writes "PyPI"; our PURLs write "pypi" — must still match.
        corpus = AdvisoryCorpus.from_records([_rec("evilpy", ["9.0"], ecosystem="PyPI")])
        self.assertIsNotNone(corpus.malicious_match(Purl("pypi", "evilpy", "9.0")))

    def test_ecosystem_must_match(self):
        self.assertIsNone(self.corpus.malicious_match(Purl("pypi", "evil", "1.0.0")))

    def test_is_empty(self):
        self.assertTrue(AdvisoryCorpus.from_records([]).is_empty())
        self.assertFalse(self.corpus.is_empty())

    def test_malicious_and_vulnerability_tiers_are_separate(self):
        corpus = AdvisoryCorpus.from_records([
            _rec("bad", ["1.0.0"], rid="MAL-2024-1", malicious=True),
            _rec("vuln", ["2.0.0"], rid="CVE-2024-9", malicious=False),
        ])
        # malware only surfaces via malicious_match; a CVE only via vulnerability_matches.
        self.assertIsNotNone(corpus.malicious_match(Purl("npm", "bad", "1.0.0")))
        self.assertIsNone(corpus.malicious_match(Purl("npm", "vuln", "2.0.0")))
        self.assertEqual([r.id for r in corpus.vulnerability_matches(Purl("npm", "vuln", "2.0.0"))],
                         ["CVE-2024-9"])
        self.assertEqual(corpus.vulnerability_matches(Purl("npm", "bad", "1.0.0")), [])


if __name__ == "__main__":
    unittest.main()
