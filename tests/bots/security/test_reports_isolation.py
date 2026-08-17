#!/usr/bin/env python3
"""Report-output isolation: running a scan/check with reports_dir must write ONLY
there and never touch the repo's committed reports/ — so tests and ad-hoc runs
can't clobber real reports."""
from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from stayawake.bots.security import service as sec_service


def _snapshot(d: Path) -> dict:
    return {str(p): p.stat().st_mtime_ns for p in d.rglob("*") if p.is_file()} if d.exists() else {}


class TestReportsIsolation(unittest.TestCase):
    # (The health check no longer writes ANY files — its status lives in one GitHub issue, #1149 —
    # so only the security scan's report-dir isolation remains to guard.)
    def test_security_scan_writes_only_to_reports_dir(self):
        work = Path(tempfile.mkdtemp())
        cfg = work / "security.yml"
        cfg.write_text("settings: {}\ntargets: { local: [] }\n", encoding="utf-8")
        out = work / "out"
        before = _snapshot(sec_service.run.REPORTS_DIR)        # the real default dir
        sec_service.scan(str(cfg), reports_dir=str(out))
        self.assertTrue((out / "latest.json").is_file())
        self.assertTrue((out / "latest.md").is_file())
        self.assertEqual(before, _snapshot(sec_service.run.REPORTS_DIR),
                         "scan must not touch the default reports/security dir")

    def test_settings_reports_dir_writes_the_bundle_without_a_flag(self):
        # #1454: config `reports_dir` used to be inert — the sink was gated on `-d`, which also sat
        # ahead of it in the same precedence chain, so it could never be reached.
        work = Path(tempfile.mkdtemp())
        out = work / "from-config"
        cfg = work / "security.yml"
        cfg.write_text(f"settings: {{ reports_dir: {out} }}\ntargets: {{ local: [] }}\n",
                       encoding="utf-8")
        before = _snapshot(sec_service.run.REPORTS_DIR)
        sec_service.scan(str(cfg))                              # no reports_dir argument
        self.assertTrue((out / "latest.json").is_file())
        self.assertTrue((out / "latest.md").is_file())
        self.assertEqual(before, _snapshot(sec_service.run.REPORTS_DIR))

    def test_nothing_is_written_when_no_source_asks(self):
        # The other half of the contract: persisting stays OPT-IN. With no flag, no env and no
        # setting, a scan must write nothing at all — not a default-path bundle.
        work = Path(tempfile.mkdtemp())
        cfg = work / "security.yml"
        cfg.write_text("settings: {}\ntargets: { local: [] }\n", encoding="utf-8")
        before = _snapshot(sec_service.run.REPORTS_DIR)
        sec_service.scan(str(cfg))
        self.assertEqual(before, _snapshot(sec_service.run.REPORTS_DIR))


if __name__ == "__main__":
    unittest.main()
