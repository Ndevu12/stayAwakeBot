#!/usr/bin/env python3
"""Fail-closed guard: a scan that ERRORED — or a config it cannot apply — must never read as clean.

A per-target scan error used to be caught into an empty, clean-looking result while the run exited
0 — a fail-OPEN: a malformed `allowlist` (or an unreadable target) silently passed a CI gate. These
tests pin the fixed contract:

  * a malformed `allowlist` (not a list of mappings) exits 2 with a clear message, up front;
  * a target that errored during the scan exits 2 (not 0), because it carries no verdict;
  * valid scans keep their normal 0 (clean) / 1 (infected) verdict.
"""
from __future__ import annotations

import io
import os
import subprocess
import tempfile
import unittest
from contextlib import redirect_stdout, redirect_stderr
from pathlib import Path
from unittest import mock

from stayawake.bots.security import service
from stayawake.bots.security.models import ScanReport, ScanResult


def _scan(cfg_text, target_dir, **kw):
    """Run service.scan with a written config against target_dir, silenced; return the exit code."""
    with tempfile.TemporaryDirectory() as d:
        cfg = os.path.join(d, "security.yml")
        Path(cfg).write_text(cfg_text)
        with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            return service.scan(cfg, paths=[target_dir], no_stream=True, **kw)


class TestScanFailClosed(unittest.TestCase):
    def test_allowlist_scalar_fails_closed(self):
        with tempfile.TemporaryDirectory() as d:
            self.assertEqual(_scan("allowlist: not-a-list\n", d), 2)

    def test_allowlist_non_mapping_item_fails_closed(self):
        with tempfile.TemporaryDirectory() as d:
            self.assertEqual(_scan("allowlist:\n  - just-a-string\n", d), 2)

    def test_errored_target_fails_closed_not_clean(self):
        # A target the scanner could not process (error set, no findings) must fail CLOSED (2),
        # never be folded into a clean, exit-0 verdict.
        with tempfile.TemporaryDirectory() as d:
            subprocess.run(["git", "init", "-q", d], check=True)
            cfg = os.path.join(d, "c.yml")
            Path(cfg).write_text("allowlist: []\n")
            errored = ScanResult(target=d, source="local", error="Boom: unreadable target")
            with mock.patch.object(service, "scan_target", return_value=errored), \
                 redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
                rc = service.scan(cfg, paths=[d], no_stream=True)
            self.assertEqual(rc, 2)

    def test_valid_empty_allowlist_still_detects(self):
        with tempfile.TemporaryDirectory() as d:
            subprocess.run(["git", "init", "-q", d], check=True)
            (Path(d) / ".gitignore").write_text("temp_auto_push.bat\n")
            self.assertEqual(_scan("allowlist: []\n", d), 1)   # infected fixture -> 1, not swallowed

    def test_any_error_property(self):
        clean = ScanResult(target="a", source="local")
        errd = ScanResult(target="b", source="local", error="x")
        self.assertFalse(ScanReport(generated_at="t", results=[clean]).any_error)
        self.assertTrue(ScanReport(generated_at="t", results=[clean, errd]).any_error)


if __name__ == "__main__":
    unittest.main()
