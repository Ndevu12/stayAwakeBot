#!/usr/bin/env python3
"""The end of a scan names each note once with the repositories it is about, says in plain words
what SUSPECT means, and points at the full report in a few lines."""
from __future__ import annotations

import contextlib
import io
import re
import shutil
import tempfile
import unittest
from pathlib import Path

from stayawake.bots.security.models import Finding, ScanReport, ScanResult, Severity
from stayawake.bots.security.scanner import scan_target
from stayawake.bots.security.service.report import _print_report_pointer
from stayawake.bots.security.signatures import load_signatures
from stayawake.bots.security.sinks.render import render_markdown, render_terminal
from stayawake.bots.security.targets.base import ScanOptions, Target
from stayawake.utils import scratch

_DEEP = "To also scan every file of the packages installed in node_modules, run `saw scan --deep`."


def _report(n_with_note: int, n_without: int = 1) -> dict:
    results = [ScanResult(target=f"repo{i}", source="local", findings=[], notes=[_DEEP])
               for i in range(n_with_note)]
    results += [ScanResult(target=f"plain{i}", source="local", findings=[])
                for i in range(n_without)]
    return ScanReport(generated_at="t", results=results).to_payload()


class TestEachNoteIsShownOnce(unittest.TestCase):
    def test_a_note_many_repositories_share_is_one_line_naming_them(self):
        out = render_terminal(_report(18), detail=True)
        self.assertEqual(out.count(_DEEP), 1)
        self.assertIn(f"repo0, repo1, repo2 and 15 more — {_DEEP}", out)

    def test_a_note_every_repository_shares_names_none(self):
        out = render_terminal(_report(4, n_without=0), detail=True)
        self.assertIn(f"  • {_DEEP}", out.replace("ℹ", "•"))
        self.assertNotIn("repo0", out.split("Notes:")[1].split("Host note:")[0])

    def test_the_notes_say_what_to_run_without_a_heading_about_gating(self):
        out = render_terminal(_report(2), detail=True)
        self.assertIn("Notes:", out)
        self.assertNotIn("not gating", out.lower())
        markdown = render_markdown(_report(2))
        self.assertIn("## Notes", markdown)
        self.assertNotIn("did not look at", markdown)


class TestInstalledPackagesNameTheCommandThatScansThem(unittest.TestCase):
    def test_a_project_with_installed_packages_names_saw_scan_deep(self):
        project = Path(tempfile.mkdtemp(prefix="installed-"))
        self.addCleanup(shutil.rmtree, project, True)
        (project / "node_modules" / "leftpad").mkdir(parents=True)
        (project / "node_modules" / "leftpad" / "index.js").write_text("module.exports = 1;\n")
        result = scan_target(Target(project, str(project), ScanOptions()), load_signatures(), [])
        self.assertIn(_DEEP, result.notes)


class TestTheSummaryUsesPlainWords(unittest.TestCase):
    def test_suspect_is_said_in_plain_words(self):
        finding = Finding(signature_id="s", category="code-loader", severity=Severity.MEDIUM,
                          path="a.js", description="d", confidence="heuristic")
        payload = ScanReport(generated_at="t", results=[
            ScanResult(target="r", source="local", findings=[finding])]).to_payload()
        out = render_terminal(payload, detail=True)
        self.assertIn("SUSPECT: something to review by hand; saw does not report it as malware.", out)
        self.assertNotIn("heuristic match", out)


class TestTheReportIsPointedAtInAFewLines(unittest.TestCase):
    def setUp(self):
        self.folder = Path(tempfile.mkdtemp(prefix="pointer-"))
        self.addCleanup(shutil.rmtree, self.folder, True)

    def _pointer(self, **kwargs) -> str:
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            _print_report_pointer(self.folder / "latest.md", **kwargs)
        return err.getvalue()

    def test_a_spilled_report_names_the_report_and_its_copy_for_tools(self):
        text = self._pointer(spilled=True, reason="72 repositories")
        self.assertIn("The full report, with everything this scan found in 72 repositories:", text)
        self.assertIn("latest.md", text)
        self.assertIn("for tools:", text)
        self.assertNotIn("folder:", text)
        self.assertNotIn("terminal", text)

    def test_a_saved_copy_says_so(self):
        self.assertIn("A copy of this report is saved:", self._pointer(spilled=False))

    def test_the_report_folder_is_named_by_when_it_was_written(self):
        kept = scratch.kept_dir("the full report")
        self.addCleanup(shutil.rmtree, kept, True)
        self.assertRegex(kept.name, r"^\d{4}-\d{2}-\d{2}-\d{6}-")


if __name__ == "__main__":
    unittest.main()
