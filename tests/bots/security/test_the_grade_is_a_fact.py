#!/usr/bin/env python3
"""The grade a run reports is carried from where it is known."""
from __future__ import annotations

import unittest

import io
from contextlib import redirect_stderr, redirect_stdout
from unittest import mock

from stayawake.bots.security import remediator
from stayawake.bots.security.pr import fix as fixmod
from stayawake.bots.security.pr.fix import FixReport, _Fix, _graded
from stayawake.bots.security.remediation import live
from stayawake.bots.security.signatures import load_signatures
from stayawake.bots.security.targets.base import ScanOptions
from tests.support.gitrepo import GitSandbox


class TestThePreparedFixKnowsItsGrade(unittest.TestCase):
    def _fix(self, **kw):
        return _Fix("main", "b", [], **kw)

    def test_a_complete_fix_needs_no_review(self):
        self.assertFalse(self._fix().needs_review)

    def test_a_partial_fix_needs_review(self):
        self.assertTrue(self._fix(manual=("a",)).needs_review)

    def test_a_checkout_it_could_not_finish_needs_review(self):
        self.assertTrue(self._fix(live_incomplete=True).needs_review)


class TestTheGradeSurvivesTheSummary(unittest.TestCase):
    def test_the_summary_carries_it(self):
        report = _graded(_Fix("main", "b", [], live_incomplete=True), "owner/repo: fixed 2 file(s)")
        self.assertTrue(report.needs_review)
        self.assertEqual("owner/repo: fixed 2 file(s)", str(report))

    def test_no_fix_at_all_carries_review(self):
        self.assertTrue(_graded(None, "owner/repo: error").needs_review)

    def test_a_summary_with_no_marker_still_grades_non_zero(self):
        report = _graded(_Fix("main", "b", [], live_incomplete=True), "owner/repo: fixed 2 file(s)")
        outcome = remediator._reviewed(lambda: report, "owner/repo")
        self.assertTrue(outcome.needs_review)

    def test_a_plain_string_still_grades_by_its_markers(self):
        outcome = remediator._reviewed(lambda: "owner/repo: ABORTED — dirty", "owner/repo")
        self.assertTrue(outcome.needs_review)

    def test_a_clean_plain_string_grades_zero(self):
        outcome = remediator._reviewed(lambda: "owner/repo: fixed 2 file(s)", "owner/repo")
        self.assertFalse(outcome.needs_review)


class TestTheRunExitsOnTheFact(unittest.TestCase):
    def test_a_checkout_it_could_not_finish_exits_non_zero(self):
        report = _graded(_Fix("main", "b", [], live_incomplete=True), "owner/repo: fixed 2 file(s)")
        self.assertNotEqual(0, 1 if remediator._reviewed(lambda: report, "o").needs_review else 0)


class TestTheLiveResultReachesTheGrade(GitSandbox):
    """Check what a run reports when the checkout could not be finished."""

    def setUp(self):
        super().setUp()
        self.d = self.new_repo("project", user__name="Tester")
        (self.d / "public" / "fonts").mkdir(parents=True)
        (self.d / "public" / "fonts" / "text.woff").write_text(
            "var _0x=String.fromCharCode(118,97,114);eval(_0x+\" x=1\");\n")
        self.commit(self.d, "project and payload")

    def _prepare(self, result):
        with mock.patch.object(fixmod.live, "clean", return_value=result), \
             redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            return fixmod.prepare_fix(self.d, ScanOptions(), load_signatures(), [])

    def test_a_finished_checkout_needs_no_review(self):
        report = self._prepare(live.LiveResult(removed=["public/fonts/text.woff"]))
        self.assertFalse(report.needs_review)

    def test_a_checkout_it_could_not_read_needs_review(self):
        report = self._prepare(live.LiveResult(unread=["public/fonts/text.woff"]))
        self.assertTrue(report.needs_review)


if __name__ == "__main__":
    unittest.main()
