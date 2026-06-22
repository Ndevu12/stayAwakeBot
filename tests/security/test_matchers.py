#!/usr/bin/env python3
"""Matcher/scanner tests against inert fixtures (clean vs infected)."""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from stayawakebot.security.signatures import load_signatures          # noqa: E402
from stayawakebot.security.scanner import scan_target                 # noqa: E402
from stayawakebot.security.targets import LocalRepoTarget, ScanOptions  # noqa: E402

FIX = Path(__file__).resolve().parent / "fixtures"
SIGS = load_signatures(ROOT / "config" / "security_signatures.yml")

EXPECTED_IN_INFECTED = {
    "loader-fromcharcode-127", "loader-seed-var", "loader-decoder-fn",
    "loader-global-bang", "loader-require-hijack",
    "fake-font-fa-solid-400", "fake-font-text-woff",
    "camouflage-blockchain-readme", "oversized-config-line",
    "vscode-task-folderopen-exec", "vscode-task-runs-font",
    "vscode-allow-automatic-tasks", "gitignore-autopush-markers",
}


class TestScanner(unittest.TestCase):
    def _scan(self, name, allow=None):
        t = LocalRepoTarget(FIX / name, name, ScanOptions())
        return scan_target(t, SIGS, allow or [])

    def test_infected_fixture_triggers_all_vectors(self):
        ids = {f.signature_id for f in self._scan("infected").findings}
        missing = EXPECTED_IN_INFECTED - ids
        self.assertFalse(missing, f"signatures not detected: {sorted(missing)}")

    def test_clean_fixture_has_no_findings(self):
        res = self._scan("clean")
        self.assertEqual([f.signature_id for f in res.findings], [])
        self.assertFalse(res.infected)

    def test_allowlist_suppresses_by_path(self):
        res = self._scan("infected", allow=[{"path_glob": "**/fa-solid-400.woff2"}])
        self.assertFalse(
            any(f.path.endswith("fa-solid-400.woff2") for f in res.findings),
            "allowlisted path should be suppressed",
        )

    def test_findings_sorted_by_severity_desc(self):
        sev = [int(f.severity) for f in self._scan("infected").findings]
        self.assertEqual(sev, sorted(sev, reverse=True))


if __name__ == "__main__":
    unittest.main()
