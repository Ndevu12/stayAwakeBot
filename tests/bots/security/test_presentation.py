#!/usr/bin/env python3
"""Large-fleet result presentation: the pager, clean-row collapse, and the large-run
temp-report pointer — so a big sweep's full result is never lost to terminal scrollback.
"""
from __future__ import annotations

import io
import unittest
from pathlib import Path
from unittest import mock
from contextlib import redirect_stderr, redirect_stdout

from stayawake.core import pager
from stayawake.bots.security import service
from stayawake.bots.security.models import Finding, ScanReport, ScanResult, Severity
from stayawake.bots.security.sinks.render import render_terminal


def _clean(name: str) -> ScanResult:
    return ScanResult(target=name, source="local")


def _infected(name: str) -> ScanResult:
    r = ScanResult(target=name, source="local")
    r.findings.append(Finding("loader-seed-var", "code-loader", Severity.CRITICAL, "x.js", "loader"))
    return r


def _payload(results):
    return ScanReport(generated_at="2026-06-30T00:00:00Z", results=results).to_payload()


class TestPager(unittest.TestCase):
    def test_disabled_writes_directly(self):
        buf = io.StringIO()
        pager.page("hello\n", enabled=False, out=buf)
        self.assertEqual(buf.getvalue(), "hello\n")

    def test_short_text_not_paged(self):
        buf = io.StringIO()
        pager.page("one line\n", enabled=True, out=buf)     # fits a screen → direct, no subprocess
        self.assertEqual(buf.getvalue(), "one line\n")

    def test_pager_failure_falls_back_to_direct_write(self):
        buf, big = io.StringIO(), "x\n" * 1000              # taller than any terminal
        with mock.patch.object(pager.subprocess, "Popen", side_effect=OSError("no pager")):
            pager.page(big, enabled=True, out=buf)
        self.assertEqual(buf.getvalue(), big)               # never lost when the pager can't run


class TestCollapseClean(unittest.TestCase):
    def test_collapse_when_over_threshold(self):
        out = render_terminal(_payload([_infected("o/bad")] + [_clean(f"o/c{i}") for i in range(50)]),
                              collapse_clean_over=40)
        self.assertIn("o/bad", out)                         # infected always shown
        self.assertNotIn("o/c0", out)                       # clean rows collapsed
        self.assertIn("50 clean", out)                      # …to a count

    def test_no_collapse_under_threshold(self):
        out = render_terminal(_payload([_infected("o/bad")] + [_clean(f"o/c{i}") for i in range(5)]),
                              collapse_clean_over=40)
        self.assertIn("o/c0", out)                          # small fleet → clean listed in full

    def test_default_never_collapses(self):
        out = render_terminal(_payload([_clean(f"o/c{i}") for i in range(100)]))  # over=0
        self.assertIn("o/c0", out)


class TestLargeFleetPointer(unittest.TestCase):
    def test_writes_temp_report_and_points_at_it(self):
        repos = [Path(f"/x/r{i}") for i in range(service.LARGE_FLEET + 5)]
        with mock.patch.object(service, "discover_local_repos", return_value=repos), \
             mock.patch.object(service, "LocalRepoTarget"), \
             mock.patch.object(service, "scan_target", return_value=ScanResult("r", "local")), \
             redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()) as err:
            rc = service.scan(None, no_stream=True)          # local, no -d / --json
        self.assertEqual(rc, 0)
        self.assertIn("Full report", err.getvalue())         # pointer printed for a big sweep

    def test_small_fleet_writes_no_pointer(self):
        repos = [Path("/x/r0")]
        with mock.patch.object(service, "discover_local_repos", return_value=repos), \
             mock.patch.object(service, "LocalRepoTarget"), \
             mock.patch.object(service, "scan_target", return_value=ScanResult("r", "local")), \
             redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()) as err:
            service.scan(None, no_stream=True)
        self.assertNotIn("Full report", err.getvalue())


if __name__ == "__main__":
    unittest.main()
