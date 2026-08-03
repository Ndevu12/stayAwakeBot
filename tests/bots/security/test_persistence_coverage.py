#!/usr/bin/env python3
"""#1332 — the persistence-surface VERDICT contract. A clean `saw audit` must imply the persistence
surface was ENUMERATED; a surface that could not be read is UNKNOWN, not clean; and the run states,
as a run-level property, whether credential rotation is safe. Exit `3` encodes rotation-unsafe.
Offline, stdlib-only."""
from __future__ import annotations

import os
import tempfile
import threading
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from stayawake.bots.security import hygiene
from stayawake.bots.security.hygiene import coverage
from stayawake.bots.security.hygiene.models import (
    HygieneIssue, rotation_safety, ROTATION_SAFE, ROTATION_UNSAFE_PERSISTENCE, ROTATION_UNSAFE_UNKNOWN)
from stayawake.cli.commands import audit as audit_cmd
from stayawake.bots.security.sinks import render as sink_render


def _issue(id_, severity="warning"):
    return HygieneIssue(id=id_, severity=severity, title=id_,
                        detail=f"{id_} detail — a location could not be read", remediation="fix it")


class TestCoverageState(unittest.TestCase):
    def test_absent_path_is_clean(self):
        self.assertEqual(coverage._coverage(Path("/no/such/persistence/location")), "absent")

    def test_readable_dir_is_ok(self):
        d = Path(tempfile.mkdtemp(prefix="cov-ok-"))
        self.addCleanup(lambda: __import__("shutil").rmtree(d, ignore_errors=True))
        (d / "a").write_text("x")
        self.assertEqual(coverage._coverage(d), "ok")

    @unittest.skipIf(os.getuid() == 0, "root bypasses permission bits")
    def test_unreadable_dir_is_unverified(self):
        d = Path(tempfile.mkdtemp(prefix="cov-perm-"))
        self.addCleanup(lambda: (os.chmod(d, 0o700), __import__("shutil").rmtree(d, ignore_errors=True)))
        os.chmod(d, 0o000)                       # exists, but we cannot enumerate it
        self.assertEqual(coverage._coverage(d), "unverified")

    @unittest.skipUnless(hasattr(os, "mkfifo"), "no mkfifo on this platform")
    def test_fifo_at_a_location_is_unverified_and_never_hangs(self):
        # A FIFO planted where a regular file is expected (a replaced authorized_keys) must be caught
        # WITHOUT opening it — opening a FIFO for read blocks forever (#1226), a DoS on the auditor.
        d = Path(tempfile.mkdtemp(prefix="cov-fifo-"))
        self.addCleanup(lambda: __import__("shutil").rmtree(d, ignore_errors=True))
        fifo = d / "authorized_keys"
        os.mkfifo(fifo)
        box: dict = {}
        t = threading.Thread(target=lambda: box.__setitem__("r", coverage._coverage(fifo)),
                             daemon=True)
        t.start()
        t.join(5)
        self.assertFalse(t.is_alive(), "_coverage hung on a FIFO — it must never open a non-regular file")
        self.assertEqual(box["r"], "unverified")


class TestCoverageProbe(unittest.TestCase):
    def test_unreadable_location_yields_unverified_issue(self):
        d = Path(tempfile.mkdtemp(prefix="cov-probe-"))
        self.addCleanup(lambda: (os.chmod(d, 0o700), __import__("shutil").rmtree(d, ignore_errors=True)))
        if os.getuid() == 0:
            self.skipTest("root bypasses permission bits")
        os.chmod(d, 0o000)
        with mock.patch.object(coverage, "_must_verify_locations", return_value=[("launch dir", d)]):
            issues = coverage.check_persistence_coverage()
        self.assertEqual([i.id for i in issues], ["persistence-surface-unverified"])
        self.assertEqual(issues[0].severity, "unknown")

    def test_all_absent_or_readable_is_clean(self):
        readable = Path(tempfile.mkdtemp(prefix="cov-clean-"))
        self.addCleanup(lambda: __import__("shutil").rmtree(readable, ignore_errors=True))
        locs = [("absent", Path("/no/such/x")), ("readable", readable)]
        with mock.patch.object(coverage, "_must_verify_locations", return_value=locs):
            self.assertEqual(coverage.check_persistence_coverage(), [])

    def test_probe_is_in_the_single_composition_site(self):
        # audit_checks() is the ONE place probes are registered; the coverage probe must be there.
        labels = [lbl for lbl, _ in hygiene.audit_checks()]
        self.assertIn("persistence surface readable", labels)

    def test_surface_covers_the_active_plant_locations(self):
        # The certified surface must include the deterministic user-owned PLANT locations (the wiper
        # dirs, runner dirs, SSH authorized_keys, shell rc) — the ones whose silent skip was the hole.
        labels = {lbl for lbl, _ in coverage._must_verify_locations()}
        self.assertIn("launch-agent / service dir", labels)
        self.assertIn("self-hosted-runner dir", labels)
        self.assertTrue(any("SSH" in l for l in labels))
        self.assertTrue(any("shell" in l for l in labels))


class TestRotationSafetyVerdict(unittest.TestCase):
    def test_states(self):
        self.assertEqual(rotation_safety(set()), ROTATION_SAFE)
        self.assertEqual(rotation_safety({"os-service-persistence"}), ROTATION_UNSAFE_PERSISTENCE)
        self.assertEqual(rotation_safety({"persistence-surface-unverified"}), ROTATION_UNSAFE_UNKNOWN)

    def test_active_persistence_dominates_unknown(self):
        self.assertEqual(
            rotation_safety({"os-service-persistence", "persistence-surface-unverified"}),
            ROTATION_UNSAFE_PERSISTENCE)


class TestAuditRender(unittest.TestCase):
    def test_clean_run_states_rotation_safe(self):
        r = hygiene.render([])
        self.assertIn("no issues found", r)
        self.assertIn("Rotation safety", r)
        self.assertIn("safe", r.lower())

    def test_unverified_surface_reads_as_unknown_not_clean(self):
        r = hygiene.render([_issue("persistence-surface-unverified", "unknown")])
        self.assertNotIn("no issues found", r)      # never a false all-clear
        self.assertIn("UNKNOWN", r)
        self.assertIn("UNSAFE", r)

    def test_active_persistence_is_rotation_unsafe(self):
        r = hygiene.render([_issue("os-service-persistence")])
        self.assertIn("UNSAFE", r)
        self.assertIn("rotate", r.lower())


class TestAuditExitCode(unittest.TestCase):
    def _run(self, issues, *, fail=False):
        args = SimpleNamespace(repo=None, branch="main", fail=fail, no_stream=True,
                               verify_artifacts=False)
        with mock.patch.object(audit_cmd.auth, "resolve_token", return_value=(None, None)), \
             mock.patch.object(audit_cmd.hygiene, "audit_checks",
                               return_value=[("x", lambda: issues)]):
            return audit_cmd.run(args)

    def test_active_persistence_exits_3_even_without_fail(self):
        self.assertEqual(self._run([_issue("os-service-persistence")]), 3)

    def test_unverified_surface_exits_3(self):
        self.assertEqual(self._run([_issue("persistence-surface-unverified", "unknown")]), 3)

    def test_clean_exits_0(self):
        self.assertEqual(self._run([]), 0)

    def test_weaker_warning_keeps_optin_gate(self):
        # a non-persistence warning is the opt-in axis: 0 by default, 1 with -f — unchanged.
        self.assertEqual(self._run([_issue("git-credentials-plaintext")], fail=False), 0)
        self.assertEqual(self._run([_issue("git-credentials-plaintext")], fail=True), 1)


class TestScanHostNote(unittest.TestCase):
    def _payload(self, *, infected: int):
        r = {"target": "repo", "source": "local", "infected": bool(infected),
             "suspicious": False, "error": None,
             "summary": {"total": 0, "max_severity": None}, "findings": [], "advisories": [],
             "notes": []}
        return {"summary": {"targets": 1, "infected": infected, "suspicious": 0, "findings": 0,
                            "critical": 0, "high": 0},
                "generated_at": "t", "results": [r]}

    def test_clean_scan_points_at_saw_audit(self):
        out = sink_render.render_terminal(self._payload(infected=0))
        self.assertIn("Host note", out)
        self.assertIn("saw audit", out)

    def test_infected_scan_omits_the_host_note(self):
        out = sink_render.render_terminal(self._payload(infected=1))
        self.assertNotIn("Host note", out)


if __name__ == "__main__":
    unittest.main()
