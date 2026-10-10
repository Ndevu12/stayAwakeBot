#!/usr/bin/env python3
"""Telling the user after each pass: delivery is recorded only when it happens, a failing notifier
is paused rather than slowing every pass, and a record that cannot be kept is never lost."""
from __future__ import annotations

import time
import unittest

from stayawake.bots.security import watch, watchstatus, watchteller as T
from stayawake.bots.security.watchevents import ENDED, LEFT, QUIET, RETURNED
from stayawake.utils import notify


class _Notifier:
    def __init__(self, state=notify.SENT):
        self.state, self.got = state, []

    def send(self, title, body, *, urgent=False, replaces=0):
        self.got.append((body, urgent))
        return notify.Delivery(self.state)


def _teller(notifier, store, *, now, saves=True):
    def save(record):
        if saves:
            store["r"] = record
        return saves
    return T.teller(notifier, load=lambda: dict(store.get("r", {})), save=save,
                    clock=lambda: now, local=time.gmtime)


class TestDeliveryIsRecordedOnlyWhenItHappens(unittest.TestCase):
    def test_what_is_decided_is_sent_and_the_record_kept(self):
        store, notifier = {}, _Notifier()
        _teller(notifier, store, now=36000.0)((ENDED, RETURNED))
        self.assertTrue(any(urgent for _, urgent in notifier.got))
        self.assertTrue(store["r"]["unacknowledged"])

    def test_a_failed_notification_is_retried_and_the_user_is_told_elsewhere(self):
        store, failing = {}, _Notifier(notify.FAILED)
        _teller(failing, store, now=36000.0)((ENDED, LEFT))
        self.assertTrue(store["r"].get("undelivered"))
        line = watchstatus.foreground_notice(record=lambda: store["r"], placed=lambda: True,
                                             clock=lambda: 36010.0, placed_since=lambda: 0.0,
                                             acknowledged=lambda: None)
        self.assertIn("could not show you notifications", line)
        self.assertIn("could not be stopped", line)
        working = _Notifier()
        _teller(working, store, now=36000.0 + T.FIRST_BACKOFF_SECONDS + 1)((LEFT,))
        self.assertTrue(working.got, "not retried once the pause was over")
        self.assertNotIn("undelivered", store["r"])

    def test_a_notifier_that_fails_is_paused_not_called_every_pass(self):
        store, failing = {}, _Notifier(notify.FAILED)
        for i in range(20):                                                    # ten minutes
            _teller(failing, store, now=36000.0 + 30 * i)((ENDED, RETURNED, LEFT))
        self.assertLessEqual(len(failing.got), 4, "a failing notifier was called every pass")

    def test_no_more_than_a_few_alerts_go_out_in_one_pass(self):
        store, notifier = {}, _Notifier()
        _teller(notifier, store, now=36000.0)((ENDED, RETURNED, LEFT))
        self.assertLessEqual(len(notifier.got), T.MOST_SENT_PER_PASS)

    def test_a_notifier_that_raises_is_a_failed_delivery(self):
        class Raising:
            def send(self, *a, **k):
                raise UnicodeDecodeError("utf-8", b"\xff", 0, 1, "bad")
        store = {}
        _teller(Raising(), store, now=36000.0)((ENDED, RETURNED))
        self.assertTrue(store["r"].get("pending", {}).get("came-back"))
        self.assertTrue(store["r"].get("undelivered"))


class TestARecordThatCannotBeKeptIsNeverLost(unittest.TestCase):
    def test_it_is_raised_and_kept_in_memory(self):
        store, notifier = {}, _Notifier()
        tell = _teller(notifier, store, now=36000.0, saves=False)
        for _ in range(2):
            with self.assertRaises(OSError):
                tell((QUIET,))
        self.assertEqual(sum(1 for body, _ in notifier.got if body.startswith("Daily")), 1,
                         "a daily report on every pass")
        said = []
        watch.keep_going(once=lambda: (0, (QUIET,)), sleep=lambda n: None, passes=1,
                         report=said.append, tell=tell)
        self.assertEqual(said, [watch._NOT_TOLD])

    def test_a_record_it_cannot_read_still_lets_it_tell(self):
        notifier = _Notifier()

        def broken():
            raise OverflowError("x")
        T.teller(notifier, load=broken, save=lambda r: True, clock=lambda: 36000.0,
                 local=time.gmtime)((ENDED, RETURNED))
        self.assertTrue(any(urgent for _, urgent in notifier.got))


class TestTheWatchKeepsGoing(unittest.TestCase):
    def test_a_watch_whose_output_breaks_keeps_going(self):
        made = []

        def report(text):
            raise BrokenPipeError()
        watch.keep_going(once=lambda: made.append(1) or (1, (ENDED,)), sleep=lambda n: None,
                         passes=3, report=report)
        self.assertEqual(len(made), 3)


if __name__ == "__main__":
    unittest.main()
