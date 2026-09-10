#!/usr/bin/env python3
"""The check this machine makes of itself has to survive a restart, and its absence has to be seen.

A login item is only worth placing if what it names will still be there afterwards, and a machine
that was checking itself and stopped should say so rather than read as one that never was."""
from __future__ import annotations

import pathlib
import tempfile
import unittest
from unittest import mock

from stayawake.bots.security import schedule
from stayawake.bots.security.hygiene import watching

DURABLE = ["/opt/pipx/venvs/stayawakebot/bin/python", "-E", "-P", "-m", "stayawake"]
TEMPORARY = ["/private/tmp/build-xyz/venv/bin/python", "-E", "-P", "-m", "stayawake"]


class TestItRefusesToPlaceOneThatCannotSurvive(unittest.TestCase):
    def test_a_program_under_a_temp_directory_is_refused(self):
        for argv in (TEMPORARY, ["/tmp/v/bin/python"], ["/var/tmp/v/bin/python"]):
            with self.subTest(argv=argv[0]):
                self.assertFalse(schedule.survives_a_restart(argv))

    def test_an_installed_one_is_not(self):
        for argv in (DURABLE, ["/usr/local/bin/python3"], ["/opt/homebrew/bin/python3"]):
            with self.subTest(argv=argv[0]):
                self.assertTrue(schedule.survives_a_restart(argv))

    def test_settle_refuses_rather_than_placing_one_that_will_break(self):
        d = pathlib.Path(tempfile.mkdtemp())
        out = schedule.settle(d / "item", TEMPORARY, record=d / "r.json")
        self.assertFalse(out.settled)
        self.assertIsNotNone(out.problem)
        self.assertFalse((d / "item").exists())

    def test_and_places_one_that_will_not(self):
        d = pathlib.Path(tempfile.mkdtemp())
        out = schedule.settle(d / "item", DURABLE, record=d / "r.json",
                              activate=lambda w: True, running=lambda: False)
        self.assertTrue(out.settled)


class TestTakingItBackForgetsIt(unittest.TestCase):
    def test_the_record_does_not_outlive_what_it_records(self):
        d = pathlib.Path(tempfile.mkdtemp())
        item, record = d / "item", d / "r.json"
        schedule.settle(item, DURABLE, record=record, activate=lambda w: True,
                        running=lambda: False)
        self.assertTrue(schedule.was_placed(record))
        self.assertEqual(schedule.take_back(item, DURABLE, deactivate=lambda w: None,
                                            record=record), schedule.REMOVED)
        self.assertFalse(schedule.was_placed(record))


class TestAMachineThatStoppedCheckingItselfSaysSo(unittest.TestCase):
    def _check(self, *, placed=True, state=schedule.PRISTINE, loaded=True, supported=True):
        return watching.check_self_check(placed=lambda: placed, verdict=lambda: state,
                                         running=lambda: loaded, supported=lambda: supported)

    def test_checking_and_running_reports_nothing(self):
        self.assertEqual(self._check(), [])

    def test_one_never_set_up_is_not_a_finding(self):
        self.assertEqual(self._check(placed=False, state=schedule.ABSENT, loaded=False), [])

    def test_set_up_and_gone_is_reported(self):
        issues = self._check(state=schedule.ABSENT, loaded=False)
        self.assertEqual([i.id for i in issues], [watching.STOPPED_ID])
        self.assertEqual(issues[0].severity, "warning")

    def test_in_place_but_not_running_is_reported_too(self):
        # One unprivileged command stops the job without touching a byte.
        issues = self._check(state=schedule.PRISTINE, loaded=False)
        self.assertEqual([i.id for i in issues], [watching.STOPPED_ID])

    def test_a_platform_without_one_reports_nothing(self):
        self.assertEqual(self._check(supported=False, state=schedule.ABSENT, loaded=False), [])

    def test_it_names_no_location(self):
        for issue in self._check(state=schedule.ABSENT, loaded=False):
            self.assertNotIn("/", f"{issue.title} {issue.detail}")


if __name__ == "__main__":
    unittest.main()
