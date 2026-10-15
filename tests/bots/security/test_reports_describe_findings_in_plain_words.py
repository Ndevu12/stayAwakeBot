#!/usr/bin/env python3
"""The SARIF log, `saw scan --json` and the written report describe each finding in the words saw
shows a person, and keep a description saw wrote for one finding."""
from __future__ import annotations

import contextlib
import io
import json
import unittest

from stayawake.bots.security import found, sarif
from stayawake.bots.security.models import Finding, ScanReport, ScanResult, Severity
from stayawake.bots.security.signatures import every_signature, load_signatures
from stayawake.bots.security.sinks.json_sink import JsonSink
from stayawake.bots.security.sinks.render import render_markdown

_SIGNATURE = next(s for s in every_signature(load_signatures()) if s["id"] == "loader-fromcharcode-127")


def _report(*findings) -> ScanReport:
    return ScanReport(generated_at="t", results=[
        ScanResult(target="repo", source="local", findings=list(findings))])


def _loader() -> Finding:
    return Finding(signature_id=_SIGNATURE["id"], category=_SIGNATURE["category"],
                   severity=Severity.CRITICAL, path="a.js", description=_SIGNATURE["description"],
                   line=1)


def _written_by_saw() -> Finding:
    return Finding(signature_id="cleanup-residue", category="remediation-residue",
                   severity=Severity.LOW, path="b.js", description="A cleanup left 2 files here.")


class TestEveryReportUsesTheFindingsWords(unittest.TestCase):
    def test_the_sarif_log_describes_a_finding_in_its_words(self):
        log = sarif.build_sarif(_report(_loader()).to_payload())
        rule = log["runs"][0]["tool"]["driver"]["rules"][0]
        for text in (rule["shortDescription"]["text"], rule["fullDescription"]["text"], rule["help"]["text"],
                     log["runs"][0]["results"][0]["message"]["text"]):
            self.assertIn(_SIGNATURE["shown_as"], text)
            self.assertNotIn(_SIGNATURE["description"], text)
        self.assertIn("`saw fix`", rule["help"]["text"])

    def test_json_describes_a_finding_in_its_words(self):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            JsonSink().emit(_report(_loader()))
        finding = json.loads(out.getvalue())["results"][0]["findings"][0]
        self.assertEqual(finding["description"], _SIGNATURE["shown_as"])
        self.assertEqual(finding["signature_id"], _SIGNATURE["id"])

    def test_the_written_report_describes_a_finding_in_its_words(self):
        text = render_markdown(_report(_loader()).to_payload())
        self.assertIn(f"  - {_SIGNATURE['shown_as']}", text)
        self.assertNotIn(_SIGNATURE["description"], text)

    def test_a_description_saw_wrote_for_one_finding_is_kept(self):
        self.assertEqual(found.described("cleanup-residue", "remediation-residue",
                                         "A cleanup left 2 files here."),
                         "A cleanup left 2 files here.")
        text = render_markdown(_report(_written_by_saw()).to_payload())
        self.assertIn("A cleanup left 2 files here.", text)

    def test_no_signature_description_reaches_a_report(self):
        for signature in every_signature(load_signatures()):
            words = found.described(signature["id"], signature["category"], signature["description"])
            self.assertNotEqual(words, signature["description"], signature["id"])

    def test_a_target_that_could_not_be_scanned_reads_as_not_clean(self):
        text = sarif.NOT_SCANNED_RULE["help"]["text"]
        self.assertEqual(text, "A target that could not be scanned is not clean. Scan it again.")


if __name__ == "__main__":
    unittest.main()
