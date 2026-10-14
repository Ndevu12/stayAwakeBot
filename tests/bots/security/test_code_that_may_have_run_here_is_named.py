#!/usr/bin/env python3
"""A scan that finds, in a folder on this machine, a code loader or other code that runs when the
folder is installed or built, says it may already have run and to run `saw audit` now."""
from __future__ import annotations

import unittest

from stayawake.bots.security.models import Finding, ScanReport, ScanResult, Severity
from stayawake.bots.security.signatures import every_signature, load_signatures
from stayawake.bots.security.sinks.render import render_terminal

_MAY_HAVE_RUN = "and it may already have run. Run `saw audit` now"
_REPOSITORIES_ONLY = "this scan checked repositories, not this machine"
_RUNS_HERE = ("npm-lifecycle-dropper", "npm-lifecycle-agent-approval-disabled", "malicious-dependency",
              "malicious-installed-package", "installed-entry-loader")
_SEEN_IN_ORDINARY_PROJECTS = ("vscode-task-folderopen-exec", "vscode-allow-automatic-tasks",
                              "vscode-task-runs-font",
                              "claude-hook-runs-payload", "git-exec-payload",
                              "npm-lifecycle-remote-fetch", "installed-lifecycle-hook",
                              "disguised-binary-file", "destructive-home-wipe")
_NOT_RUN_BY_OPENING_IT = ("evil-merge-loader", "exfil-sha1hulud-runner", "runner-registration-content",
                          "camouflage-blockchain-readme", "gitignore-autopush-markers",
                          "exfil-shai-hulud-branding", "symlink-write-redirect")


def _signature(signature_id):
    return next(s for s in every_signature(load_signatures()) if s["id"] == signature_id)


def _scan_output(signature_id, *, source="local", confidence="confirmed") -> str:
    signature = _signature(signature_id)
    finding = Finding(signature_id=signature_id, category=signature["category"],
                      severity=Severity.CRITICAL, path="found/here.js", description="d",
                      confidence=confidence)
    report = ScanReport(generated_at="t", results=[
        ScanResult(target="repo", source=source, findings=[finding])])
    return render_terminal(report.to_payload(), detail=True)


class TestCodeThatRunsHereSaysItMayHaveRun(unittest.TestCase):
    def test_each_signature_of_code_that_runs_here_says_so(self):
        for signature_id in _RUNS_HERE:
            out = _scan_output(signature_id)
            self.assertIn(_MAY_HAVE_RUN, out, signature_id)
            self.assertIn("found/here.js", out.split("Host note:")[1], signature_id)

    def test_every_confirmed_code_loader_says_so(self):
        loaders = [s["id"] for s in every_signature(load_signatures())
                   if s["category"] == "code-loader" and s["confidence"] == "confirmed"]
        self.assertTrue(loaders)
        for signature_id in loaders:
            self.assertIn(_MAY_HAVE_RUN, _scan_output(signature_id), signature_id)


class TestOtherFindingsSayTheScanCoveredRepositories(unittest.TestCase):
    def test_a_signature_also_seen_in_ordinary_projects_says_the_scan_covered_repositories(self):
        for signature_id in _SEEN_IN_ORDINARY_PROJECTS:
            out = _scan_output(signature_id)
            self.assertNotIn(_MAY_HAVE_RUN, out, signature_id)
            self.assertIn(_REPOSITORIES_ONLY, out, signature_id)

    def test_a_finding_in_history_ci_or_markers_says_the_scan_covered_repositories(self):
        for signature_id in _NOT_RUN_BY_OPENING_IT:
            out = _scan_output(signature_id)
            self.assertNotIn(_MAY_HAVE_RUN, out, signature_id)
            self.assertIn(_REPOSITORIES_ONLY, out, signature_id)

    def test_a_repository_on_github_says_the_scan_covered_repositories(self):
        out = _scan_output("npm-lifecycle-dropper", source="remote")
        self.assertNotIn(_MAY_HAVE_RUN, out)
        self.assertIn(_REPOSITORIES_ONLY, out)

    def test_a_finding_to_review_says_the_scan_covered_repositories(self):
        self.assertNotIn(_MAY_HAVE_RUN, _scan_output("npm-lifecycle-dropper", confidence="heuristic"))


if __name__ == "__main__":
    unittest.main()
