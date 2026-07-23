#!/usr/bin/env python3
"""Large-fleet result presentation: the pager, clean-row collapse, and the large-run
temp-report pointer — so a big sweep's full result is never lost to terminal scrollback.
"""
from __future__ import annotations

import io
import os
import signal
import tempfile
import unittest
from pathlib import Path
from unittest import mock
from contextlib import redirect_stderr, redirect_stdout

from stayawake.utils import pager
from stayawake.bots.security import service
from stayawake.bots.security.models import Finding, ScanReport, ScanResult, Severity
from stayawake.bots.security.sinks.render import render_terminal


def _clean(name: str) -> ScanResult:
    return ScanResult(target=name, source="local")


def _infected(name: str) -> ScanResult:
    r = ScanResult(target=name, source="local")
    r.findings.append(Finding("loader-seed-var", "code-loader", Severity.CRITICAL, "x.js", "loader"))
    return r


def _infected_many(name: str, n: int) -> ScanResult:
    """One repo with `n` findings — few repos, but a report far too tall for a terminal (#1203)."""
    r = ScanResult(target=name, source="local")
    for i in range(n):
        r.findings.append(Finding(f"sig-{i}", "code-loader", Severity.CRITICAL,
                                  f"f{i}.js", "loader", evidence="snippet"))
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

    def test_default_command_drops_F_and_X(self):
        # `-F`/`-X` are the garble footgun on multi-screen piped input — the default must not
        # use them; plain `less -R` pages cleanly on the alternate screen.
        captured, big = {}, "x\n" * 1000
        without_pager = {k: v for k, v in os.environ.items() if k != "PAGER"}
        with mock.patch.dict("os.environ", without_pager, clear=True), \
             mock.patch.object(pager.subprocess, "Popen",
                               side_effect=lambda cmd, **kw: captured.update(cmd=cmd)
                               or mock.Mock(communicate=lambda text: None)):
            pager.page(big, enabled=True, out=io.StringIO())
        self.assertIn("less", captured["cmd"])
        self.assertIn("-R", captured["cmd"])
        self.assertNotIn("-F", captured["cmd"])
        self.assertNotIn("-X", captured["cmd"])

    def test_sigint_shielded_during_pager_then_restored(self):
        # Ctrl+C must quit the pager, not kill us mid-run (or the post-report pointer is lost).
        before, seen = signal.getsignal(signal.SIGINT), {}
        def fake_popen(cmd, **kw):
            return mock.Mock(communicate=lambda text:
                             seen.__setitem__("during", signal.getsignal(signal.SIGINT)))
        with mock.patch.object(pager.subprocess, "Popen", side_effect=fake_popen):
            pager.page("x\n" * 1000, enabled=True, out=io.StringIO())
        self.assertEqual(seen["during"], signal.SIG_IGN)            # shielded while paging
        self.assertEqual(signal.getsignal(signal.SIGINT), before)   # restored afterward


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


class TestDetailSuppression(unittest.TestCase):
    def test_detail_false_omits_findings_and_points_at_file(self):
        out = render_terminal(_payload([_infected("o/bad")]), detail=False)
        self.assertIn("o/bad", out)                # table still names the infected repo
        self.assertNotIn("loader-seed-var", out)   # per-finding detail is gone from the terminal
        self.assertIn("full report", out)          # …and we point at where it lives

    def test_detail_true_keeps_findings(self):
        out = render_terminal(_payload([_infected("o/bad")]), detail=True)
        self.assertIn("loader-seed-var", out)      # small fleet → full detail inline


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

    def test_large_fleet_moves_detail_off_terminal(self):
        repos = [Path(f"/x/r{i}") for i in range(service.LARGE_FLEET + 5)]
        with mock.patch.object(service, "discover_local_repos", return_value=repos), \
             mock.patch.object(service, "LocalRepoTarget"), \
             mock.patch.object(service, "scan_target", return_value=_infected("o/bad")), \
             redirect_stdout(io.StringIO()) as out, redirect_stderr(io.StringIO()) as err:
            rc = service.scan(None, no_stream=True)
        self.assertEqual(rc, 1)                                       # infected → exit 1
        self.assertNotIn("loader-seed-var", out.getvalue())          # detail off the terminal
        self.assertIn("per-finding detail", err.getvalue().lower())  # …pointed to the file

    def test_small_fleet_writes_no_pointer(self):
        repos = [Path("/x/r0")]
        with mock.patch.object(service, "discover_local_repos", return_value=repos), \
             mock.patch.object(service, "LocalRepoTarget"), \
             mock.patch.object(service, "scan_target", return_value=ScanResult("r", "local")), \
             redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()) as err:
            service.scan(None, no_stream=True)
        self.assertNotIn("Full report", err.getvalue())


def _remote_scan(results, **kw):
    """Drive service.scan down the REMOTE path with `results` as the per-repo scan outcomes,
    stubbing resolution + clone + scan so no network/FS is touched. Returns (rc, stdout, stderr)."""
    slugs = [r.target for r in results]
    it = iter(results)
    with mock.patch.object(service, "_resolve_remote", return_value=(slugs, None, "test")), \
         mock.patch.object(service, "RemoteRepoTarget") as RT, \
         mock.patch.object(service, "scan_target", side_effect=lambda *a, **k: next(it)), \
         redirect_stdout(io.StringIO()) as out, redirect_stderr(io.StringIO()) as err:
        RT.return_value.clone.return_value = True
        rc = service.scan(None, remote=True, slugs=slugs, no_stream=True, **kw)
    return rc, out.getvalue(), err.getvalue()


def _local_scan(result, **kw):
    """Drive service.scan down the LOCAL path with one mocked repo. Returns (rc, stdout, stderr)."""
    with mock.patch.object(service, "discover_local_repos", return_value=[Path("/x/r0")]), \
         mock.patch.object(service, "LocalRepoTarget"), \
         mock.patch.object(service, "scan_target", return_value=result), \
         redirect_stdout(io.StringIO()) as out, redirect_stderr(io.StringIO()) as err:
        rc = service.scan(None, no_stream=True, **kw)
    return rc, out.getvalue(), err.getvalue()


class TestManyFindingsSpills(unittest.TestCase):
    """#1203: a wall of findings (local OR remote) uses the SAME board the large-fleet path uses —
    dashboard on-screen, full detail in a highlighted file — even at few repos."""

    def test_local_wall_of_findings_shows_board_and_spills(self):
        rc, out, err = _local_scan(_infected_many("o/huge", service.MANY_FINDINGS + 10))
        self.assertEqual(rc, 1)
        self.assertIn("o/huge", out)                            # board still names the target
        self.assertNotIn("sig-0", out)                          # per-finding detail OFF the terminal
        self.assertIn("full report", out.lower())               # dashboard points at the file
        self.assertIn("Full report", err)                       # highlighted path on stderr
        self.assertIn("larger than a terminal", err)
        self.assertIn("latest.md", err)
        self.assertIn("folder:", err)                           # folder line for easy navigation

    def test_remote_wall_of_findings_shows_board_and_spills(self):
        rc, out, err = _remote_scan([_infected_many("o/huge", service.MANY_FINDINGS + 10)])
        self.assertEqual(rc, 1)
        self.assertIn("o/huge", out)                            # same board as local
        self.assertNotIn("sig-0", out)
        self.assertIn("Full report", err)
        self.assertIn("latest.md", err)

    def test_small_local_keeps_detail_inline_no_pointer(self):
        rc, out, err = _local_scan(_infected("o/bad"))
        self.assertIn("loader-seed-var", out)                   # detail stays inline
        self.assertNotIn("Full report", err)
        self.assertNotIn("Report written", err)

    def test_small_remote_keeps_detail_inline_no_pointer(self):
        # Small remote is still terminal-first — no auto-persist unless spilled or -d.
        rc, out, err = _remote_scan([_infected("o/bad")])
        self.assertIn("loader-seed-var", out)
        self.assertNotIn("Full report", err)
        self.assertNotIn("Report written", err)

    def test_local_with_reports_dir_highlights_path(self):
        d = tempfile.mkdtemp()
        rc, out, err = _local_scan(_infected("o/bad"), reports_dir=d)
        self.assertIn("loader-seed-var", out)                   # small → detail still inline
        self.assertIn("Report written", err)                    # -d → highlighted path
        self.assertIn(os.path.basename(d), err)


if __name__ == "__main__":
    unittest.main()
