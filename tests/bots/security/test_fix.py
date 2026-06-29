#!/usr/bin/env python3
"""`saw fix` — PR-per-repo remediation, config-optional, and `scan` is read-only (#1054/#1069).

The redesign (#1069): cleanup is always delivered as a pull request (the review gate), never
an in-place edit — so `fix` routes every discovered repo through `submit_fix_pr` and the
working tree is never touched. `scan` lost all remediation flags. A missing config never
crashes: None → the current repo, an explicit missing path → a clean exit-2.
"""
from __future__ import annotations

import inspect
import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from stayawake.bots.security import service, remediator

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
        # #1054: `saw fix` with no config must not raise; it falls back to the enclosing repo.
        d = _git_repo(INFECTED_FILES)
        cwd = os.getcwd()
        try:
            os.chdir(d)
            with mock.patch.object(remediator.auth, "resolve_token", return_value=(None, None)), \
                 mock.patch.object(remediator.pr_submit, "submit_fix_pr",
                                   return_value="no GitHub origin remote — skipped") as m_pr:
                rc = remediator.fix(None, no_stream=True)
        finally:
            os.chdir(cwd)
        self.assertEqual(rc, 0)               # "skipped" (no origin) is not "needs review"
        m_pr.assert_called()                  # the current repo was processed

    def test_missing_explicit_config_is_clean_exit_2(self):
        # An explicitly-passed --config that doesn't exist → exit 2 + message, not a traceback.
        self.assertEqual(remediator.fix("definitely-not-here.yml"), 2)


class TestFixLocal(unittest.TestCase):
    def test_fix_routes_each_repo_through_a_pr_and_never_writes(self):
        d = _git_repo(INFECTED_FILES)
        before = (d / ".gitignore").read_text()
        with mock.patch.object(remediator.auth, "resolve_token", return_value=("t", "env")), \
             mock.patch.object(remediator.pr_submit, "submit_fix_pr",
                               return_value="repo: opened PR #1 (url)") as m_pr:
            rc = remediator.fix(None, paths=[str(d)], no_stream=True)
        self.assertEqual(rc, 0)
        m_pr.assert_called_once()                               # the one repo got a PR attempt
        self.assertEqual((d / ".gitignore").read_text(), before)  # working tree UNTOUCHED

    def test_aborted_repo_makes_exit_one(self):
        d = _git_repo(INFECTED_FILES)
        with mock.patch.object(remediator.auth, "resolve_token", return_value=("t", "env")), \
             mock.patch.object(remediator.pr_submit, "submit_fix_pr",
                               return_value="repo: ABORTED — 1 finding still present"):
            # A repo that couldn't be auto-cleaned → exit 1 (needs manual review).
            self.assertEqual(remediator.fix(None, paths=[str(d)], no_stream=True), 1)


class TestScanIsReadOnly(unittest.TestCase):
    def test_scan_signature_has_no_remediation_params(self):
        params = inspect.signature(service.scan).parameters
        for gone in ("fix", "apply", "open_pr", "local_only"):
            self.assertNotIn(gone, params, f"scan must not expose {gone!r} anymore")
        self.assertIn("remote", params)

    def test_bare_scan_never_writes(self):
        d = _git_repo(INFECTED_FILES)
        before = (d / ".gitignore").read_text()
        rc = service.scan(None, paths=[str(d)], no_stream=True)     # read-only
        self.assertEqual((d / ".gitignore").read_text(), before)   # unchanged
        self.assertEqual(rc, 1)                                     # infected → exit 1


if __name__ == "__main__":
    unittest.main()
