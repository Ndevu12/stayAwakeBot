#!/usr/bin/env python3
"""`saw guard` tracks the gate's pinned scanner version, not only its action pin: setup bumps a
stale `version:` even when the action SHA is current, check grades it, and drift reports it."""
from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from stayawake.bots.security.guard import detect, pindrift
from stayawake.bots.security.guard.constants import SAW_GUARD_FILE
from stayawake.bots.security.guard.detect import LatestSawGuard
from stayawake.bots.security.guard.provision import Pin, plan_setup, render_workflow

_SHA = "a" * 40
_PIN = Pin(_SHA, "v0.2.0")


def _workflows(scanner: str | None) -> dict:
    return {SAW_GUARD_FILE: render_workflow(_PIN, "main", scanner)}


class TestSetupBumpsStaleScanner(unittest.TestCase):
    def test_a_current_action_pin_with_a_stale_scanner_is_revised_not_a_noop(self):
        plan = plan_setup(_workflows("0.15.0"), "main", _PIN, scanner="0.16.0")
        self.assertEqual(plan.action, "revise")
        self.assertEqual((plan.scanner_from, plan.scanner_to), ("0.15.0", "0.16.0"))
        self.assertIn("version: '0.16.0'", plan.content)
        self.assertIn("stayawakebot==0.16.0", plan.content)
        self.assertIn(f"@{_SHA}", plan.content)          # the action pin is preserved
        self.assertNotIn("0.15.0", plan.content)

    def test_a_current_action_pin_with_a_current_scanner_is_still_a_noop(self):
        self.assertEqual(plan_setup(_workflows("0.15.0"), "main", _PIN, scanner="0.15.0").action, "noop")

    def test_an_action_repin_also_bumps_a_stale_scanner(self):
        newer = Pin("b" * 40, "v0.3.0")
        plan = plan_setup(_workflows("0.15.0"), "main", newer, scanner="0.16.0")
        self.assertEqual(plan.action, "repin")
        self.assertIn("@" + "b" * 40, plan.content)
        self.assertIn("version: '0.16.0'", plan.content)


class TestScannerFreshness(unittest.TestCase):
    def _ref(self, scanner):
        return detect.find_worm_gate(_workflows(scanner)).saw_guard

    def test_it_grades_behind_fresh_and_floating(self):
        self.assertEqual(detect.scanner_freshness(self._ref("0.15.0"), latest_version="0.16.0").state,
                         "behind")
        self.assertEqual(detect.scanner_freshness(self._ref("0.15.0"), latest_version="0.15.0").state,
                         "fresh")
        self.assertEqual(detect.scanner_freshness(self._ref(None), latest_version="0.16.0").state,
                         "floating")


class TestCheckAndDriftSeeTheScanner(unittest.TestCase):
    def _status(self, scanner, latest_scanner):
        d = Path(tempfile.mkdtemp())
        (d / ".github/workflows").mkdir(parents=True)
        (d / SAW_GUARD_FILE).write_text(render_workflow(_PIN, "main", scanner), encoding="utf-8")
        return detect.check(repo=d, latest=LatestSawGuard("v0.2.0", _SHA),
                            latest_scanner=latest_scanner)

    def test_check_grades_a_stale_scanner_even_with_a_current_action_pin(self):
        st = self._status("0.15.0", "0.16.0")
        self.assertEqual(st.fresh.state, "fresh")        # action pin current
        self.assertEqual(st.scanner.state, "behind")     # scanner behind
        self.assertFalse(st.healthy)

    def test_drift_reports_a_stale_scanner_as_a_deficiency(self):
        state, reason = pindrift._classify(self._status("0.15.0", "0.16.0"))
        self.assertEqual(state, "behind")
        self.assertIn("0.16.0", reason)
        self.assertIn("saw", reason)

    def test_a_current_scanner_and_action_is_healthy(self):
        self.assertTrue(self._status("0.16.0", "0.16.0").healthy)


if __name__ == "__main__":
    unittest.main()
