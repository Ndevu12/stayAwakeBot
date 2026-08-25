#!/usr/bin/env python3
"""The auto-opened issue body is published to someone else's tracker under this tool's name."""
import unittest

from stayawake.bots.security import alerter

RESULT = {
    "target": "acme/web", "source": "remote",
    "summary": {"total": 2, "max_severity": "critical"},
    "findings": [{"severity": "critical", "signature_id": "loader-x",
                  "path": "postcss.config.mjs", "line": 11}],
}


class IssueBody(unittest.TestCase):
    def setUp(self):
        self.body = alerter._issue_body(RESULT)

    def test_it_does_not_tell_the_reader_to_run_a_script_that_does_not_exist(self):
        self.assertNotIn("sec-clean-worm", self.body)

    def test_it_does_not_tell_the_reader_to_clean_a_possibly_compromised_host(self):
        # Cleaning during a live compromise is a documented hazard, and "cleaned" would imply
        # "clean", which the scan cannot establish.
        for phrase in ("Clean with", "clean your host", "cleanup script"):
            with self.subTest(phrase=phrase):
                self.assertNotIn(phrase, self.body)

    def test_it_points_at_remediation_that_exists(self):
        self.assertIn("saw fix --pr", self.body)

    def test_it_does_not_leak_internal_roadmap_language(self):
        self.assertNotIn("Phase 3", self.body)

    def test_closing_is_scoped_to_the_repository_not_the_host(self):
        # The issue really does auto-close on a clean repo scan; the claim must not be read as
        # containment, since a repo scan says nothing about a machine that ran the code.
        self.assertIn("this repository only", self.body)
        self.assertIn("saw audit", self.body)

    def test_it_links_the_versioned_documentation(self):
        # `latest` is the alias a push to main deploys; a bare or version-pinned path goes stale.
        self.assertIn("https://saw-docs.ndevuspace.com/latest/", self.body)
        self.assertIn("how-to/fix-findings/", self.body)

    def test_the_finding_table_still_renders(self):
        self.assertIn("postcss.config.mjs:11", self.body)
        self.assertIn("loader-x", self.body)


if __name__ == "__main__":
    unittest.main()
