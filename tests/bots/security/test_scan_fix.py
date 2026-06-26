#!/usr/bin/env python3
"""`saw scan --fix` and the config-optional remediator (#1054).

Covers: the scan→fix fold (one analysis pass remediates the scanned local repos with
no re-scan), dry-run safety (no writes without --apply), and that a missing config never
crashes — None falls back to the current repo, an explicit missing path is a clean exit-2.
"""
from __future__ import annotations

import os
import subprocess
import tempfile
import unittest
from pathlib import Path

from stayawake.bots.security import service, remediator
from stayawake.bots.security.scanner import scan_target
from stayawake.bots.security.signatures import load_signatures
from stayawake.bots.security.targets import LocalRepoTarget, ScanOptions

# A CONFIRMED, auto-fixable finding: the worm's .gitignore auto-push markers.
INFECTED_FILES = {".gitignore": "node_modules\ntemp_auto_push.bat\nbranch_structure.json\n"}


def _git_repo(files: dict[str, str]) -> Path:
    d = Path(tempfile.mkdtemp())
    subprocess.run(["git", "init", "-q", str(d)], check=True)
    for rel, content in files.items():
        p = d / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content, encoding="utf-8")
    return d


class TestConfigOptional(unittest.TestCase):
    def test_no_config_falls_back_to_current_repo_no_crash(self):
        # #1054: `saw fix` with no config must not raise FileNotFoundError; it falls back
        # to the enclosing repo and exits cleanly.
        d = _git_repo(INFECTED_FILES)
        cwd = os.getcwd()
        try:
            os.chdir(d)
            rc = remediator.remediate(None)          # dry-run, no config
        finally:
            os.chdir(cwd)
        self.assertEqual(rc, 0)

    def test_missing_explicit_config_is_clean_exit_2(self):
        # An explicitly-passed --config that doesn't exist → exit 2 + message, not a traceback.
        self.assertEqual(remediator.remediate("definitely-not-here.yml"), 2)

    def test_submit_org_prs_missing_config_returns_zero(self):
        # The --remote path stays supported and config-optional: clean 0, no crash.
        self.assertEqual(remediator.submit_org_prs("definitely-not-here.yml"), 0)


class TestScanFix(unittest.TestCase):
    def test_scan_fix_dry_run_plans_without_writing(self):
        d = _git_repo(INFECTED_FILES)
        before = (d / ".gitignore").read_text()
        reports = Path(tempfile.mkdtemp())
        rc = service.scan(None, local_only=True, paths=[str(d)],
                          reports_dir=str(reports), fix=True)     # dry-run (no --apply)
        self.assertEqual((d / ".gitignore").read_text(), before)  # unchanged
        self.assertIsInstance(rc, int)

    def test_remediate_scanned_reuses_result_no_rescan(self):
        # The shared engine plans from an already-computed ScanResult (the scan→fix fold).
        d = _git_repo(INFECTED_FILES)
        opts = ScanOptions()
        sigs = load_signatures()
        result = scan_target(LocalRepoTarget(d, str(d), opts), sigs, [])
        self.assertTrue(result.findings)
        changes = remediator.remediate_scanned(d, result, sigs=sigs, allowlist=[], opts=opts)
        self.assertGreaterEqual(changes, 1)                       # the gitignore strip is planned
        self.assertEqual((d / ".gitignore").read_text(),
                         INFECTED_FILES[".gitignore"])            # dry-run: still unchanged


if __name__ == "__main__":
    unittest.main()
