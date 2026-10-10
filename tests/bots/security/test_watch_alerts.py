#!/usr/bin/env python3
"""The watcher tells the user what matters, repeats it until it is dealt with, reports once a day,
and cannot be flooded into silence."""
from __future__ import annotations

import time
import unittest

from stayawake.bots.security import watch, watchalerts as A, watchrecord
from stayawake.bots.security.watch import ENDED, LEFT, NOT_READ, PASS_FAILED, QUIET, RETURNED

DAY = 86400


def _run(passes, start=0.0, every=30.0, record=None):
    """Feed passes through `decide`, hour by local clock from `start` (09:00 = 32400)."""
    record, sent = dict(record or {}), []
    for i, kinds in enumerate(passes):
        now = start + i * every
        day = int(now // DAY)
        hour = int(now % DAY // 3600)
        record, alerts = A.decide(record, kinds, now, f"d{day}", hour)
        sent += [(now, a) for a in alerts]
    return record, sent


class TestWhatMattersIsTold(unittest.TestCase):
    def test_code_that_came_back_is_urgent_and_says_what_to_do(self):
        _, sent = _run([(ENDED, RETURNED)], start=36000)
        urgent = [a for _, a in sent if a.about == RETURNED]
        self.assertTrue(urgent and urgent[0].urgent)
        self.assertIn("saw harden", urgent[0].body)

    def test_a_return_is_reminded_hourly_until_acknowledged(self):
        record, _ = _run([(ENDED, RETURNED)], start=36000)
        _, sent = _run([(QUIET,)] * 240, start=36030, record=record)          # two hours, quiet
        self.assertEqual(sum(1 for _, a in sent if a.about == "reminder"), 2)
        record["unacknowledged"] = None
        _, sent = _run([(QUIET,)] * 240, start=43200, record=record)
        self.assertFalse([a for _, a in sent if a.about == "reminder"])

    def test_a_machine_it_cannot_check_is_told_after_a_while_not_at_once(self):
        _, first = _run([(NOT_READ,)] * 9, start=36000)
        self.assertFalse([a for _, a in first if a.about == NOT_READ])
        _, sent = _run([(PASS_FAILED,)] * 10, start=36000)
        self.assertTrue([a for _, a in sent if a.about == NOT_READ])


class TestItCannotBeFloodedIntoSilence(unittest.TestCase):
    def test_many_events_change_counts_not_the_number_of_notifications(self):
        _, sent = _run([(ENDED, RETURNED, LEFT)] * 240, start=36000)            # two hours
        per_hour = {}
        for now, a in sent:
            if a.about != "daily":
                per_hour[int(now // 3600)] = per_hour.get(int(now // 3600), 0) + 1
        self.assertTrue(per_hour)
        self.assertLessEqual(max(per_hour.values()), A.MOST_PER_HOUR)
        self.assertTrue(any(a.about == RETURNED for _, a in sent))


class TestOneReportADay(unittest.TestCase):
    def test_exactly_one_report_per_day_and_on_quiet_days_too(self):
        _, sent = _run([(QUIET,)] * (3 * 2880), start=0)                         # three days
        daily = [a for _, a in sent if a.about == "daily"]
        self.assertEqual(len(daily), 3)
        self.assertIn("Nothing was running that should not be", daily[0].body)

    def test_a_report_after_a_restart_is_not_repeated(self):
        record, sent = _run([(QUIET,)] * 10, start=36000)
        _, again = _run([(QUIET,)] * 10, start=36300, record=record)
        self.assertEqual(len([a for _, a in sent + again if a.about == "daily"]), 1)

    def test_a_day_with_events_counts_them_and_says_what_to_run(self):
        record, _ = _run([(ENDED,)] * 3, start=0)
        _, sent = _run([(QUIET,)], start=32400, record=record)
        body = [a for _, a in sent if a.about == "daily"][0].body
        self.assertIn("stopped 3 times", body)
        self.assertIn("saw watch status", body)

    def test_nothing_from_the_machine_reaches_a_notification(self):
        _, sent = _run([(ENDED, RETURNED, LEFT, NOT_READ)] * 20 + [(QUIET,)] * 2900, start=0)
        for _, a in sent:
            self.assertNotIn("/", a.body.replace("`saw watch status`", ""))


class TestTheTeller(unittest.TestCase):
    def test_it_sends_what_was_decided_and_keeps_the_record(self):
        store, got = {}, []

        class Notifier:
            def send(self, title, body, *, urgent=False, replaces=0):
                got.append((body, urgent))

        tell = A.teller(Notifier(), load=lambda: dict(store.get("r", {})),
                        save=lambda r: store.__setitem__("r", r) or True,
                        clock=lambda: 36000.0, local=time.gmtime)
        tell((ENDED, RETURNED))
        self.assertTrue(any(urgent for _, urgent in got))
        self.assertTrue(store["r"]["unacknowledged"])

    def test_a_record_it_cannot_write_is_raised_to_the_pass(self):
        class Notifier:
            def send(self, *a, **k):
                pass
        tell = A.teller(Notifier(), load=dict, save=lambda r: False, clock=lambda: 36000.0,
                        local=time.gmtime)
        with self.assertRaises(OSError):
            tell((ENDED,))
        said = []
        watch.keep_going(once=lambda: (0, (QUIET,)), sleep=lambda n: None, passes=1,
                         report=said.append, tell=tell)
        self.assertEqual(said, [watch._NOT_TOLD])


class TestTheRecordHoldsOnlyCountsAndTimes(unittest.TestCase):
    def test_acknowledge_clears_a_return(self):
        import tempfile
        from pathlib import Path
        where = Path(tempfile.mkdtemp()) / "w.json"
        self.assertTrue(watchrecord.save({"unacknowledged": 5.0, "reminded": 6.0}, where))
        self.assertTrue(watchrecord.acknowledge(where, now=lambda: 7.0))
        self.assertIsNone(watchrecord.load(where)["unacknowledged"])

    def test_a_heartbeat_too_old_is_stale(self):
        self.assertTrue(watchrecord.stale({}, 1000.0))
        self.assertTrue(watchrecord.stale({"last_good": 0.0}, 1000.0))
        self.assertFalse(watchrecord.stale({"last_good": 900.0}, 1000.0))


if __name__ == "__main__":
    unittest.main()
