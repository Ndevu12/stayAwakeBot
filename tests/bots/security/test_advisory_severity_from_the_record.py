#!/usr/bin/env python3
"""An offline advisory is graded at the advisory's own severity, not a flat medium: a critical
framework RCE (React2Shell class) reads as critical. A dependency audit against a cache older than a
month says so; a fresh or absent cache does not."""
from __future__ import annotations

import unittest

from stayawake.bots.security.dependencies.corpus import AdvisoryCorpus
from stayawake.bots.security.dependencies.osv import advisory_severity, parse_osv_record
from stayawake.bots.security.dependencies.purl import Purl
from stayawake.bots.security.dependencies.store import Advisory, AdvisoryStore
from stayawake.bots.security.matchers.dependency_audit import _note_stale_advisories
from stayawake.bots.security.models import Severity


def _record(name, sev_label, introduced, fixed):
    return parse_osv_record({
        "id": f"GHSA-{name}", "aliases": ["CVE-2025-55182"],
        "database_specific": {"severity": sev_label},
        "affected": [{"package": {"ecosystem": "npm", "name": name},
                      "ranges": [{"type": "SEMVER",
                                  "events": [{"introduced": introduced}, {"fixed": fixed}]}]}]})


class TestAdvisorySeverityReader(unittest.TestCase):
    def test_label_is_read_and_normalised_else_medium(self):
        self.assertEqual(advisory_severity({"database_specific": {"severity": "CRITICAL"}}), "critical")
        self.assertEqual(advisory_severity({"database_specific": {"severity": "Moderate"}}), "moderate")
        self.assertEqual(advisory_severity({}), "medium")
        self.assertEqual(advisory_severity({"database_specific": {"severity": "bogus"}}), "medium")


class TestTheFindingSeverityComesFromTheAdvisory(unittest.TestCase):
    def _graded(self, name, version, sev_label):
        corpus = AdvisoryCorpus.from_records([_record(name, sev_label, "19.1.0", "19.1.2")])
        store = AdvisoryStore(by_coordinate={}, corpus=corpus,
                              vulnerability_signature={"id": "vulnerable-dependency",
                                                       "category": "supply-chain-vuln",
                                                       "severity": "medium"})
        advisories = store.vulnerabilities_for(Purl("npm", name, version))
        self.assertTrue(advisories)
        return Severity.parse(advisories[0].severity or "medium")

    def test_a_critical_rce_is_graded_critical_not_medium(self):
        self.assertEqual(self._graded("react-server-dom-webpack", "19.1.1", "CRITICAL"),
                         Severity.CRITICAL)

    def test_a_low_advisory_is_graded_low(self):
        self.assertEqual(self._graded("left-pad", "19.1.1", "LOW"), Severity.LOW)

    def test_an_unlabelled_advisory_falls_back_to_medium(self):
        self.assertEqual(self._graded("plain-pkg", "19.1.1", ""), Severity.MEDIUM)


class _FakeStore:
    def __init__(self, status):
        self._status = status

    def advisory_cache_status(self):
        return self._status


class _FakeTarget:
    def __init__(self):
        self.coverage_notes = []


class TestAStaleCacheIsDisclosed(unittest.TestCase):
    def _notes(self, status):
        target = _FakeTarget()
        _note_stale_advisories(target, _FakeStore(status))
        return target.coverage_notes

    def test_present_but_old_adds_a_note_naming_the_command(self):
        notes = self._notes({"present": True, "age_days": 45})
        self.assertEqual(len(notes), 1)
        self.assertIn("45 days old", notes[0])
        self.assertIn("saw db update", notes[0])

    def test_a_fresh_cache_adds_no_note(self):
        self.assertEqual(self._notes({"present": True, "age_days": 3}), [])

    def test_an_absent_cache_adds_no_note(self):
        self.assertEqual(self._notes({"present": False}), [])

    def test_no_status_adds_no_note(self):
        self.assertEqual(self._notes(None), [])


if __name__ == "__main__":
    unittest.main()
