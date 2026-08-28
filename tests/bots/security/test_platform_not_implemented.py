#!/usr/bin/env python3
"""A probe with no implementation for the running platform returns nothing for the same reason it
returns nothing on a clean host. Grading the two alike gave a Windows run per-check clean results,
and exit 0, over a start-up surface no code in this project enumerates."""
from __future__ import annotations

import io
import unittest
from contextlib import redirect_stdout
from unittest import mock

from stayawake.bots.security import hygiene
from stayawake.bots.security.hygiene.models import (ROTATION_UNSAFE_IDS, SURFACE_NOT_IMPLEMENTED_ID,
                                                    persistence_surface_is_enumerable)
from stayawake.bots.security.hygiene.outcome import CHECKED_CLEAN, NOT_IMPLEMENTED


class TestAPlatformWithNoImplementationIsNotClean(unittest.TestCase):
    def _states(self, platform):
        with mock.patch("sys.platform", platform):
            return {o.label: o.state for o in hygiene.audit_outcomes()}

    def test_the_posix_only_probes_say_so_rather_than_clean(self):
        states = self._states("win32")
        for label in hygiene._POSIX_ONLY_PROBES:
            with self.subTest(probe=label):
                self.assertEqual(states[label], NOT_IMPLEMENTED)

    def test_a_cross_platform_probe_still_runs_there(self):
        self.assertEqual(self._states("win32")["git exec config"], CHECKED_CLEAN)

    def test_on_posix_they_run_normally(self):
        states = self._states("darwin")
        for label in hygiene._POSIX_ONLY_PROBES:
            with self.subTest(probe=label):
                self.assertNotEqual(states[label], NOT_IMPLEMENTED)

    def test_every_posix_only_probe_names_a_registered_one(self):
        labels = {label for label, _c in hygiene.audit_checks()}
        self.assertEqual(set(hygiene._POSIX_ONLY_PROBES) - labels, set())


class TestTheRunSaysItAndGates(unittest.TestCase):
    def test_the_gap_is_reported_once_not_per_probe(self):
        with mock.patch("sys.platform", "win32"):
            ids = [i.id for i in hygiene.audit()]
        self.assertEqual(ids.count(SURFACE_NOT_IMPLEMENTED_ID), 1)

    def test_it_withholds_the_rotation_all_clear(self):
        self.assertIn(SURFACE_NOT_IMPLEMENTED_ID, ROTATION_UNSAFE_IDS)
        with mock.patch("sys.platform", "win32"):
            report = hygiene.render(hygiene.audit(), color=False, width=90)
        self.assertNotIn("persistence surface enumerated and clean", report)
        self.assertIn("UNKNOWN", report)

    def test_the_audit_does_not_exit_zero_there(self):
        # Asserted through the real exit gate, but with the probe list fabricated rather than the
        # platform faked: patching `sys.platform` for a whole CLI run reaches libraries that key
        # certificate loading off it, and the test then fails for a reason of its own making.
        from stayawake.bots.security.hygiene import HygieneIssue
        gap = HygieneIssue(id=SURFACE_NOT_IMPLEMENTED_ID, severity="unknown", title="t",
                           detail="d", remediation="r")
        buf = io.StringIO()
        with mock.patch("stayawake.bots.security.hygiene.audit_checks",
                        return_value=[("persistence surface coverage", lambda: [gap])]), \
             mock.patch("stayawake.lib.auth.resolve_token", return_value=(None, None)), \
             redirect_stdout(buf):
            from stayawake import cli
            rc = cli.main(["audit", "--no-stream"])
        self.assertEqual(rc, 3, "a platform nothing enumerates reported a clean run")

    def test_the_platform_question_still_has_one_authority(self):
        with mock.patch("sys.platform", "win32"):
            self.assertFalse(persistence_surface_is_enumerable())
        with mock.patch("sys.platform", "linux"):
            self.assertTrue(persistence_surface_is_enumerable())


if __name__ == "__main__":
    unittest.main()
