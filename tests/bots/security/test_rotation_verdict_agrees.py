#!/usr/bin/env python3
"""The run-level verdict may not contradict a finding printed six lines below it.

`saw audit` reported "rotating credentials is safe" while a finding underneath said "isolate the
host and rotate credentials LAST". `--verify` repeated it after content-scanning the directory and
finding nothing. Two places were deciding whether rotation is safe — `rotation_safety()` and the
finding's own prose — and they disagreed, which is the derived-proxy shape: a second answer to a
question that already had an authority.

The weak signal must NOT raise the alarm (it fires on any machine with `~/.node_modules`), so the
exit code is unchanged. What changes is the CLAIM: unconditional safety becomes conditional, which
is what the finding already said.
"""
from __future__ import annotations

import unittest

from stayawake.bots.security import hygiene
from stayawake.bots.security.hygiene.models import (
    HygieneIssue, ROTATION_SAFE, ROTATION_SAFE_PENDING_CHECK, ROTATION_UNSAFE_PERSISTENCE,
    ROTATION_UNSAFE_UNKNOWN, VERIFY_BEFORE_ROTATE_IDS, rotation_safety)


def _issue(issue_id, severity="info"):
    return HygieneIssue(id=issue_id, severity=severity, title=issue_id,
                        detail="Found something.",
                        remediation="Check whether it is yours. If not, isolate the host and "
                                    "rotate credentials LAST.")


class TestTheVerdictAgreesWithTheFinding(unittest.TestCase):
    def test_a_weak_artifact_makes_safety_conditional(self):
        for issue_id in sorted(VERIFY_BEFORE_ROTATE_IDS):
            with self.subTest(finding=issue_id):
                self.assertEqual(rotation_safety({issue_id}), ROTATION_SAFE_PENDING_CHECK)

    def test_the_report_never_claims_plain_safety_beside_rotate_last(self):
        for issue_id in sorted(VERIFY_BEFORE_ROTATE_IDS):
            with self.subTest(finding=issue_id):
                report = hygiene.render([_issue(issue_id)], color=False, width=100)
                flowed = " ".join(report.split())
                self.assertIn("rotate credentials LAST", flowed)          # the fix still says it
                self.assertNotIn("rotating credentials is safe", flowed)  # the verdict no longer contradicts it
                self.assertIn("safe once you confirm", flowed)

    def test_a_clean_run_still_says_plainly_that_rotation_is_safe(self):
        # The conditional must not leak onto a run with nothing to verify.
        self.assertEqual(rotation_safety(set()), ROTATION_SAFE)
        self.assertIn("rotating credentials is safe", hygiene.render([], color=False))

    def test_a_real_incident_still_dominates(self):
        # A live foothold outranks the conditional — the priority order is unchanged.
        self.assertEqual(rotation_safety({"os-service-persistence", "host-drop-artifact-weak"}),
                         ROTATION_UNSAFE_PERSISTENCE)
        self.assertEqual(rotation_safety({"persistence-surface-unverified",
                                          "host-drop-artifact-weak"}), ROTATION_UNSAFE_UNKNOWN)


class TestItDoesNotRaiseTheAlarm(unittest.TestCase):
    """A weak, unattributed signal that fires on ordinary machines must not gate the exit code —
    #1337: weak context adds context, it never modulates the verdict."""

    def test_the_exit_gate_is_untouched(self):
        for issue_id in sorted(VERIFY_BEFORE_ROTATE_IDS):
            with self.subTest(finding=issue_id):
                self.assertNotIn(issue_id, hygiene.ROTATION_UNSAFE_IDS)

    def test_the_finding_stays_a_review_item(self):
        report = hygiene.render([_issue("host-drop-artifact-weak")], color=False, width=100)
        self.assertIn("to review", report)
        self.assertNotIn("WARNINGS", report)


if __name__ == "__main__":
    unittest.main()
