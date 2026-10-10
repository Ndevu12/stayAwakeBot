#!/usr/bin/env python3
"""What the watcher tells the user and when: what matters is told, repeated until dealt with,
reported once a day, and never flooded or held back."""
from __future__ import annotations

import unittest

from stayawake.bots.security import watchack, watchalerts as A, watchstate
from stayawake.bots.security.watchevents import (
    ENDED, LEFT, NOT_READ, NOT_REMEMBERED, PASS_FAILED, QUIET, RETURNED, SENTENCE_FOR, UNNAMED)
from stayawake.bots.security.watchstate import CAME_BACK, NOT_STOPPED
from stayawake.utils import notify

DAY = 86400
HUGE = 10 ** 400


def _run(passes, start=0.0, every=30.0, record=None, shown=lambda alert: True):
    """Feed passes through `decide` and `delivered`, local clock = UTC from `start`."""
    record, sent = dict(record or {}), []
    for i, kinds in enumerate(passes):
        now = start + i * every
        today, hour = f"d{int(now // DAY)}", int(now % DAY // 3600)
        record, alerts = A.decide(record, kinds, now, today, hour)
        record = A.delivered(record, [a for a in alerts if shown(a)], now, today)
        sent += [(now, a) for a in alerts]
    return record, sent


def _urgent(sent):
    return [(t, a.about) for t, a in sent if a.urgent and a.about != A.DAILY]


class TestWhatMattersIsTold(unittest.TestCase):
    def test_code_that_came_back_is_urgent_and_says_what_to_do(self):
        _, sent = _run([(ENDED, RETURNED)], start=36000)
        self.assertEqual([about for _, about in _urgent(sent)], [CAME_BACK])
        self.assertIn("saw harden", [a for _, a in sent if a.about == CAME_BACK][0].body)

    def test_a_return_is_reminded_hourly_until_dealt_with(self):
        record, _ = _run([(ENDED, RETURNED)], start=36000)
        _, sent = _run([(QUIET,)] * 240, start=36030, record=record)          # two hours, quiet
        self.assertEqual(len(_urgent(sent)), 2)
        settled = watchack.settled(record, watchack.returns_so_far(record))
        _, sent = _run([(QUIET,)] * 240, start=43200, record=settled)
        self.assertFalse(_urgent(sent))

    def test_a_return_soon_after_another_is_told_within_the_urgent_interval(self):
        record, _ = _run([(ENDED, RETURNED)], start=36000)
        _, sent = _run([(QUIET,)] * 3 + [(ENDED, RETURNED)] + [(QUIET,)] * 60, start=36030,
                       record=record)
        first = [t for t, _ in _urgent(sent)]
        self.assertTrue(first and first[0] - 36000 <= A.URGENT_EVERY_SECONDS + 30)

    def test_a_return_after_it_was_dealt_with_is_told_at_once(self):
        record, _ = _run([(ENDED, RETURNED)], start=36000)
        record = watchack.settled(record, watchack.returns_so_far(record))
        _, sent = _run([(ENDED, RETURNED)], start=36400, record=record)
        self.assertEqual([about for _, about in _urgent(sent)], [CAME_BACK])

    def test_a_return_counted_after_harden_started_stays_open(self):
        record, _ = _run([(ENDED, RETURNED)], start=36000)
        started_with = watchack.returns_so_far(record)
        record, _ = _run([(ENDED, RETURNED)], start=36300, record=record)    # during harden
        self.assertEqual(record["returns_seen"], 2)
        self.assertIn("unacknowledged", watchack.settled(record, started_with))
        self.assertNotIn("unacknowledged",
                         watchack.settled(record, watchack.returns_so_far(record)))

    def test_code_that_could_not_be_stopped_is_told_even_in_one_pass_and_then_cleared(self):
        record, _ = _run([(ENDED, RETURNED)], start=36000)
        record, sent = _run([(QUIET,), (LEFT,)] + [(QUIET,)] * 40, start=36030, record=record)
        self.assertIn(NOT_STOPPED, [about for _, about in _urgent(sent)])
        self.assertNotIn("not_stopped", record, "a pass without it did not clear it")

    def test_one_open_matter_never_masks_the_others_reminder(self):
        record, _ = _run([(ENDED, RETURNED)], start=0)
        _, sent = _run([(LEFT,)] * 480, start=30, record=record)               # four hours
        told = [about for _, about in _urgent(sent)]
        self.assertGreaterEqual(told.count(CAME_BACK), 3, "the came-back reminder was masked")
        self.assertGreaterEqual(told.count(NOT_STOPPED), 3)

    def test_a_machine_it_cannot_check_is_told_after_a_while_not_at_once(self):
        _, first = _run([(NOT_READ,)] * 9, start=36000)
        self.assertFalse([a for _, a in first if a.about == NOT_READ])
        _, sent = _run([(PASS_FAILED,)] * 10, start=36000)
        self.assertTrue([a for _, a in sent if a.about == NOT_READ])

    def test_a_record_that_could_not_be_kept_is_told(self):
        _, sent = _run([(QUIET, NOT_REMEMBERED)], start=36000)
        self.assertIn(NOT_REMEMBERED, [a.about for _, a in sent])

    def test_the_stopped_alert_reads_as_a_sentence(self):
        _, sent = _run([(ENDED,)], start=36000)
        body = [a for _, a in sent if a.about == ENDED][0].body
        self.assertEqual(body, SENTENCE_FOR[ENDED] + " Run `saw watch status`.")


class TestItCannotBeFloodedOrHeldBack(unittest.TestCase):
    def test_many_events_change_counts_not_the_number_of_notifications(self):
        _, sent = _run([(ENDED, RETURNED, LEFT)] * 240, start=36000)            # two hours
        per_hour = {}
        for now, a in sent:
            if a.about != A.DAILY:
                per_hour[int(now // 3600)] = per_hour.get(int(now // 3600), 0) + 1
        self.assertLessEqual(max(per_hour.values()), 6)

    def test_times_dated_in_the_future_never_hold_an_alert_back(self):
        planted = {"told": {CAME_BACK: 1e12, ENDED: 1e12}, "urgent_at": 1e12,
                   "backoff_until": 1e12, "unacknowledged": 1.0, "last_good": 1e12}
        _, sent = _run([(ENDED, RETURNED)], start=36000, record=planted)
        self.assertEqual({a.about for _, a in sent} & {CAME_BACK, ENDED}, {CAME_BACK, ENDED})

    def test_a_clock_stepped_back_holds_back_neither_a_return_nor_a_reminder(self):
        record, _ = _run([(ENDED, RETURNED)], start=90000)
        _, sent = _run([(ENDED, RETURNED)], start=36000, record=record)
        self.assertEqual([about for _, about in _urgent(sent)], [CAME_BACK])
        _, sent = _run([(QUIET,)] * 3, start=50000, record=record)
        self.assertEqual([about for _, about in _urgent(sent)], [CAME_BACK])

    def test_numbers_too_large_to_use_never_stop_a_return_being_told(self):
        odd = {"told": {CAME_BACK: HUGE}, "since": {ENDED: 10 ** 4300}, "failures": HUGE,
               "urgent_at": HUGE}
        _, sent = _run([(ENDED, RETURNED)], start=36000, record=odd)
        self.assertEqual([about for _, about in _urgent(sent)], [CAME_BACK])

    def test_any_well_formed_record_reaches_decide_without_raising(self):
        for junk in ({"since": {"x": 1}, "told": {"y": 2.0}}, {"pending": {"came-back": True}},
                     {"failures": 10 ** 9}, {"daily_for": "d0"}, {"urgent_at": -1e300},
                     {"since": [1], "told": "x", "pending": [1], "failures": "x",
                      "returns_seen": "x", "urgent_at": "x"}, [1, 2]):
            with self.subTest(junk=junk):
                A.decide(junk, (ENDED, RETURNED, NOT_READ), 36000.0, "d0", 10)


class TestOneReportADay(unittest.TestCase):
    def test_exactly_one_report_per_day_and_on_quiet_days_too(self):
        _, sent = _run([(QUIET,)] * (3 * 2880), start=0)                         # three days
        daily = [a for _, a in sent if a.about == A.DAILY]
        self.assertEqual(len(daily), 3)
        self.assertIn(watchstate.QUIET_DAY, daily[0].body)

    def test_a_report_after_a_restart_is_not_repeated(self):
        record, sent = _run([(QUIET,)] * 10, start=36000)
        _, again = _run([(QUIET,)] * 10, start=36300, record=record)
        self.assertEqual(len([a for _, a in sent + again if a.about == A.DAILY]), 1)

    def test_a_day_with_events_counts_them_and_says_what_to_run(self):
        record, _ = _run([(ENDED,)] * 3, start=0)
        _, sent = _run([(QUIET,)], start=32400, record=record)
        body = [a for _, a in sent if a.about == A.DAILY][0].body
        self.assertIn("stopped 3 times", body)
        self.assertIn("saw watch status", body)

    def test_the_report_on_a_bad_day_fits_and_keeps_what_to_do(self):
        since = {k: 10 ** 6 for k in (ENDED, RETURNED, LEFT, NOT_READ, PASS_FAILED,
                                      NOT_REMEMBERED, UNNAMED)}
        alert = A.daily_report({"since": since, "unacknowledged": 1.0})
        self.assertLessEqual(len(alert.body), notify.TEXT_LIMIT)
        self.assertIn("saw harden", alert.body)
        self.assertTrue(alert.urgent)

    def test_what_is_still_open_leads_the_report(self):
        for record, expected in (({"unacknowledged": 1.0}, "came back"),
                                 ({"not_stopped": 1.0}, "could not be stopped")):
            with self.subTest(expected=expected):
                alert = A.daily_report(record)
                self.assertNotIn(watchstate.QUIET_DAY, alert.body)
                self.assertIn(expected, alert.body)
                self.assertTrue(alert.urgent)

    def test_a_day_with_only_unidentified_code_is_not_called_quiet(self):
        alert = A.daily_report({"since": {UNNAMED: 4}})
        self.assertNotIn(watchstate.QUIET_DAY, alert.body)
        self.assertIn("could not identify 4 times", alert.body)

    def test_nothing_from_the_machine_reaches_a_notification(self):
        _, sent = _run([(ENDED, RETURNED, LEFT, NOT_READ)] * 20 + [(QUIET,)] * 2900, start=0)
        for _, a in sent:
            self.assertNotIn("/", a.body.replace("`saw watch status`", ""))


if __name__ == "__main__":
    unittest.main()
