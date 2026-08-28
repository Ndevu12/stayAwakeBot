#!/usr/bin/env python3
"""#239 — the state the vocabulary had no word for.

A tree a cleanup ran in is neither of the two answers `saw` could give. Calling it CLEAN hides that
a remediation was incomplete and that someone has already been inside it; calling it INFECTED starts
an incident the evidence does not support, because nothing there executes."""
from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from stayawake.bots.security.models import (CLEAN, CONFIRMED, HEURISTIC, INFECTED, QUARANTINE_DIR,
                                            RESIDUE, RESIDUE_VERDICT, SUSPICIOUS, CONFIDENCE_LEVELS,
                                            Finding, ScanReport, ScanResult, Severity)
from stayawake.bots.security.scanner import scan_target
from stayawake.bots.security.signatures import load_signatures
from stayawake.bots.security.sinks.render import render_markdown, render_terminal
from stayawake.bots.security.targets import LocalRepoTarget, ScanOptions


def _finding(confidence: str) -> Finding:
    return Finding(signature_id="s", category="c", severity=Severity.LOW, path="p",
                   description="d", confidence=confidence)


def _result(*confidences: str) -> ScanResult:
    result = ScanResult(target="t", source="local")
    result.findings.extend(_finding(c) for c in confidences)
    return result


class TestTheVerdictHasAFourthState(unittest.TestCase):
    def test_nothing_found_is_still_clean(self):
        self.assertEqual(_result().verdict, CLEAN)

    def test_residue_only_is_residue(self):
        self.assertEqual(_result(RESIDUE).verdict, RESIDUE_VERDICT)

    def test_it_is_the_weakest_state_so_it_can_never_mask_another(self):
        self.assertEqual(_result(RESIDUE, HEURISTIC).verdict, SUSPICIOUS)
        self.assertEqual(_result(RESIDUE, CONFIRMED).verdict, INFECTED)
        self.assertEqual(_result(RESIDUE, HEURISTIC, CONFIRMED).verdict, INFECTED)

    def test_it_does_not_inflate_the_gate_either(self):
        # The CI gate reads `infected`. Residue executes nothing, so it must not fire it — and it
        # is not a heuristic match, so it must not claim to be one.
        result = _result(RESIDUE)
        self.assertFalse(result.infected)
        self.assertFalse(result.suspicious)
        self.assertTrue(result.residue)

    def test_a_signature_may_declare_it(self):
        self.assertIn(RESIDUE, CONFIDENCE_LEVELS)


class TestACleanupThatDidNotFinishIsNotClean(unittest.TestCase):
    """The quarantine holds the original of every file a fix rewrote. A quarantined copy identical
    to the live file means the backup happened and the rewrite did not."""

    def _tree(self) -> Path:
        root = Path(tempfile.mkdtemp())
        (root / "package.json").write_text('{"name":"x","version":"1.0.0"}', encoding="utf-8")
        (root / "index.js").write_text("module.exports = 1;\n", encoding="utf-8")
        return root

    def _quarantine(self, root: Path, relative: str, body: str) -> Path:
        backup = root / QUARANTINE_DIR / relative
        backup.parent.mkdir(parents=True, exist_ok=True)
        backup.write_text(body, encoding="utf-8")
        return backup

    def _scan(self, root: Path) -> ScanResult:
        return scan_target(LocalRepoTarget(root, "t", ScanOptions()), load_signatures(), [])

    def test_an_ordinary_tree_is_clean(self):
        self.assertEqual(self._scan(self._tree()).verdict, CLEAN)

    def test_a_cleanup_that_finished_leaves_the_tree_clean(self):
        # The whole point: a successful fix backs the original up and rewrites the file, so the two
        # differ. Reporting every remediated repository as residue would be noise, not honesty.
        root = self._tree()
        self._quarantine(root, "index.js", "module.exports = 1; // the original\n")
        self.assertEqual(self._scan(root).verdict, CLEAN)

    def test_a_backup_taken_with_no_rewrite_after_it_is_residue(self):
        root = self._tree()
        self._quarantine(root, "index.js", (root / "index.js").read_text(encoding="utf-8"))
        result = self._scan(root)
        self.assertEqual(result.verdict, RESIDUE_VERDICT)
        self.assertEqual([f.signature_id for f in result.findings], ["cleanup-residue"])
        self.assertIn("index.js", result.findings[0].description)

    def test_a_quarantined_file_the_cleanup_removed_entirely_is_not_residue(self):
        # Quarantine-and-delete is a complete remediation; there is no live file to compare.
        root = self._tree()
        self._quarantine(root, "dropped.js", "payload\n")
        self.assertEqual(self._scan(root).verdict, CLEAN)

    def test_an_empty_quarantine_directory_is_not_a_finding(self):
        root = self._tree()
        (root / QUARANTINE_DIR).mkdir()
        self.assertEqual(self._scan(root).verdict, CLEAN)

    def test_the_finding_says_what_it_is_rather_than_accusing(self):
        root = self._tree()
        self._quarantine(root, "index.js", (root / "index.js").read_text(encoding="utf-8"))
        finding = self._scan(root).findings[0]
        self.assertIn("Nothing new executes", finding.description)
        self.assertEqual(finding.severity, Severity.LOW)


class TestTheReportShowsIt(unittest.TestCase):
    def _payload(self, *confidences: str) -> dict:
        return ScanReport(generated_at="now", results=[_result(*confidences)]).to_payload()

    def test_the_payload_carries_the_state(self):
        payload = self._payload(RESIDUE)
        self.assertTrue(payload["any_residue"])
        self.assertTrue(payload["results"][0]["residue"])
        self.assertEqual(payload["summary"]["residue"], 1)

    def test_a_residue_target_is_not_collapsed_with_the_clean_ones(self):
        # It has something to say, so it belongs in the list that needs attention.
        report = render_terminal(self._payload(RESIDUE), color=False, detail=True)
        self.assertIn("RESIDUE", report)

    def test_the_markdown_report_names_it_too(self):
        self.assertIn("RESIDUE", render_markdown(self._payload(RESIDUE)))

    def test_a_clean_run_says_nothing_about_residue(self):
        self.assertNotIn("RESIDUE", render_terminal(self._payload(), color=False, detail=True))


if __name__ == "__main__":
    unittest.main()
