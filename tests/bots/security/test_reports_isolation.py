#!/usr/bin/env python3
"""Report-output isolation: running a scan/check with reports_dir must write ONLY
there and never touch the repo's committed reports/ — so tests and ad-hoc runs
can't clobber real reports."""
from __future__ import annotations

import os
import stat
import tempfile
import unittest
from pathlib import Path

from stayawake.bots.security import service as sec_service
from stayawake.bots.health import service as health_service


def _snapshot(d: Path) -> dict:
    return {str(p): p.stat().st_mtime_ns for p in d.rglob("*") if p.is_file()} if d.exists() else {}


class TestReportsIsolation(unittest.TestCase):
    def test_security_scan_writes_only_to_reports_dir(self):
        work = Path(tempfile.mkdtemp())
        cfg = work / "security.yml"
        cfg.write_text("settings: {}\ntargets: { local: [] }\n", encoding="utf-8")
        out = work / "out"
        before = _snapshot(sec_service.REPORTS_DIR)        # the real default dir
        sec_service.scan(str(cfg), local_only=True, reports_dir=str(out))
        self.assertTrue((out / "latest.json").is_file())
        self.assertTrue((out / "latest.md").is_file())
        self.assertEqual(before, _snapshot(sec_service.REPORTS_DIR),
                         "scan must not touch the default reports/security dir")

    def test_security_scan_survives_unwritable_reports_dir(self):
        """An unwritable reports dir (read-only container mount / non-root user) must not
        crash the scan — detection already succeeded; reports fall back to a temp dir."""
        if os.geteuid() == 0:
            self.skipTest("root bypasses directory permissions")
        work = Path(tempfile.mkdtemp())
        cfg = work / "security.yml"
        cfg.write_text("settings: {}\ntargets: { local: [] }\n", encoding="utf-8")
        ro = work / "ro"
        ro.mkdir()
        os.chmod(ro, stat.S_IREAD | stat.S_IEXEC)            # r-x: cannot create files
        try:
            rc = sec_service.scan(str(cfg), local_only=True,
                                  fail_on_findings=True, reports_dir=str(ro / "security"))
            self.assertEqual(rc, 0, "no findings ⇒ exit 0 even when reports can't be written")
            self.assertEqual([], list(ro.rglob("*")), "nothing should land in the read-only dir")
        finally:
            os.chmod(ro, stat.S_IRWXU)                        # restore so cleanup can rm it

    def test_health_check_writes_only_to_reports_dir(self):
        work = Path(tempfile.mkdtemp())
        cfg = work / "urls.yml"
        cfg.write_text("settings: {}\nurls: []\n", encoding="utf-8")
        out = work / "out"
        before = _snapshot(health_service.REPORTS_DIR)
        health_service.run_check(str(cfg), reports_dir=str(out))
        self.assertTrue((out / "latest.json").is_file())
        self.assertEqual(before, _snapshot(health_service.REPORTS_DIR),
                         "check must not touch the default reports dir")


if __name__ == "__main__":
    unittest.main()
