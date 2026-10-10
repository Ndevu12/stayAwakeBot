#!/usr/bin/env python3
"""The watcher tells the user what matters, repeats it until it is dealt with, reports once a day,
and nothing on the machine can silence it, hang it, or make it run something else."""
from __future__ import annotations

import argparse
import contextlib
import io
import os
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest import mock

from stayawake.bots.security import liveledger, schedule, watch, watchalerts as A, watchrecord
from stayawake.bots.security.watchevents import (
    ENDED, LEFT, NOT_READ, NOT_REMEMBERED, PASS_FAILED, QUIET, RETURNED)
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
    return [(t, a) for t, a in sent if a.urgent and a.about != A.DAILY]


class _Notifier:
    def __init__(self, state=notify.SENT):
        self.state, self.got = state, []

    def send(self, title, body, *, urgent=False, replaces=0):
        self.got.append((body, urgent))
        return notify.Delivery(self.state)


def _teller(notifier, store, *, now=36000.0, saves=True):
    def save(r):
        if saves:
            store["r"] = r
        return saves
    return A.teller(notifier, load=lambda: dict(store.get("r", {})), save=save,
                    clock=lambda: now, local=time.gmtime)


class TestWhatMattersIsTold(unittest.TestCase):
    def test_code_that_came_back_is_urgent_and_says_what_to_do(self):
        _, sent = _run([(ENDED, RETURNED)], start=36000)
        self.assertEqual([a.about for _, a in _urgent(sent)], [RETURNED])
        self.assertIn("saw harden", _urgent(sent)[0][1].body)

    def test_a_return_is_reminded_hourly_until_acknowledged(self):
        record, _ = _run([(ENDED, RETURNED)], start=36000)
        _, sent = _run([(QUIET,)] * 240, start=36030, record=record)          # two hours, quiet
        self.assertEqual(sum(1 for _, a in sent if a.about == A.REMINDER), 2)
        record.pop("unacknowledged")
        _, sent = _run([(QUIET,)] * 240, start=43200, record=record)
        self.assertFalse([a for _, a in sent if a.about == A.REMINDER])

    def test_a_return_soon_after_another_is_told_within_the_urgent_interval_not_an_hour(self):
        record, _ = _run([(ENDED, RETURNED)], start=36000)
        record, sent = _run([(QUIET,)] * 3 + [(ENDED, RETURNED)] + [(QUIET,)] * 60,
                            start=36030, record=record)
        first = [t for t, a in _urgent(sent)]
        self.assertTrue(first and first[0] - 36000 <= A.URGENT_EVERY_SECONDS + 30)

    def test_a_return_after_it_was_dealt_with_is_told_at_once(self):
        record, _ = _run([(ENDED, RETURNED)], start=36000)
        with tempfile.TemporaryDirectory() as d:
            where = Path(d) / "w.json"
            watchrecord.save(record, where)
            self.assertTrue(watchrecord.acknowledge(where, now=lambda: 36100.0))
            record = watchrecord.load(where)
        _, sent = _run([(ENDED, RETURNED)], start=36400, record=record)
        self.assertEqual([a.about for _, a in _urgent(sent)], [RETURNED])

    def test_something_that_could_not_be_stopped_is_told_even_in_one_pass(self):
        record, _ = _run([(ENDED, RETURNED)], start=36000)
        _, sent = _run([(QUIET,)] + [(ENDED, LEFT)] + [(QUIET,)] * 40, start=36030, record=record)
        self.assertIn(LEFT, [a.about for _, a in _urgent(sent)])

    def test_a_machine_it_cannot_check_is_told_after_a_while_not_at_once(self):
        _, first = _run([(NOT_READ,)] * 9, start=36000)
        self.assertFalse([a for _, a in first if a.about == NOT_READ])
        _, sent = _run([(PASS_FAILED,)] * 10, start=36000)
        self.assertTrue([a for _, a in sent if a.about == NOT_READ])

    def test_a_record_that_could_not_be_kept_is_told(self):
        _, sent = _run([(QUIET, NOT_REMEMBERED)], start=36000)
        self.assertIn(NOT_REMEMBERED, [a.about for _, a in sent])


class TestItCannotBeFloodedOrHeldBack(unittest.TestCase):
    def test_many_events_change_counts_not_the_number_of_notifications(self):
        _, sent = _run([(ENDED, RETURNED, LEFT)] * 240, start=36000)            # two hours
        per_hour = {}
        for now, a in sent:
            if a.about != A.DAILY:
                per_hour[int(now // 3600)] = per_hour.get(int(now // 3600), 0) + 1
        self.assertLessEqual(max(per_hour.values()), 6)
        self.assertTrue(any(a.about == RETURNED for _, a in sent))

    def test_times_dated_in_the_future_never_hold_an_alert_back(self):
        planted = {"sent": {"urgent": 1e12, ENDED: 1e12}, "reminded": 1e12, "unacknowledged": 1e12,
                   "acknowledged": 1e12, "last_good": 1e12}
        _, sent = _run([(ENDED, RETURNED)], start=36000, record=planted)
        self.assertEqual({a.about for _, a in sent} & {RETURNED, ENDED}, {RETURNED, ENDED})
        _, sent = _run([(QUIET,)] * 130, start=36000, record=planted)
        self.assertTrue([a for _, a in sent if a.about == A.REMINDER])

    def test_a_clock_stepped_back_does_not_hold_back_a_return(self):
        record, _ = _run([(ENDED, RETURNED)], start=90000)
        _, sent = _run([(ENDED, RETURNED)], start=36000, record=record)
        self.assertEqual([a.about for _, a in _urgent(sent)], [RETURNED])

    def test_numbers_too_large_to_use_are_dropped_not_fatal(self):
        for field in ("last_good", "unacknowledged", "reminded", "saved"):
            with self.subTest(field=field):
                self.assertNotIn(field, watchrecord.well_formed({field: HUGE}))
        odd = {"sent": {RETURNED: HUGE}, "since": {ENDED: 10 ** 4300}, "failures": HUGE,
               "recent": [HUGE]}
        self.assertEqual(watchrecord.well_formed(odd), {"sent": {}, "since": {}, "recent": []})
        _, sent = _run([(ENDED, RETURNED)], start=36000, record=odd)
        self.assertEqual([a.about for _, a in _urgent(sent)], [RETURNED])


class TestDeliveryIsRecordedOnlyWhenItHappens(unittest.TestCase):
    def test_a_failed_notification_is_retried_and_the_user_is_told_elsewhere(self):
        store = {}
        failing = _Notifier(notify.FAILED)
        _teller(failing, store)((ENDED, LEFT))
        _teller(failing, store, now=36030.0)((QUIET,))
        self.assertEqual(sum(1 for body, urgent in failing.got if urgent), 2, "not retried")
        self.assertTrue(store["r"].get("undelivered"))
        placed = dict(placed=lambda: True, clock=lambda: 36040.0, placed_since=lambda: 0.0)
        self.assertEqual(watch.foreground_notice(record=lambda: store["r"], **placed),
                         watch._NOT_SHOWN)
        code, text = watch.status_of(supported=lambda: True, verdict=lambda: schedule.PRISTINE,
                                     running=lambda: True, record=lambda: store["r"],
                                     clock=lambda: 36040.0, placed_since=lambda: 0.0)
        self.assertNotEqual(code, 0)
        self.assertIn("could not be stopped", text)
        working = _Notifier()
        _teller(working, store, now=36060.0)((QUIET,))
        self.assertTrue(working.got)
        self.assertNotIn("undelivered", store["r"])

    def test_a_notifier_that_raises_is_a_failed_delivery(self):
        class Raising:
            def send(self, *a, **k):
                raise UnicodeDecodeError("utf-8", b"\xff", 0, 1, "bad")
        store = {}
        _teller(Raising(), store)((ENDED, RETURNED))
        self.assertTrue(store["r"].get("returned_unsent"))

    def test_a_record_it_cannot_write_is_raised_and_kept_in_memory(self):
        store, notifier = {}, _Notifier()
        tell = _teller(notifier, store, saves=False)
        with self.assertRaises(OSError):
            tell((QUIET,))
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
        A.teller(notifier, load=broken, save=lambda r: True, clock=lambda: 36000.0,
                 local=time.gmtime)((ENDED, RETURNED))
        self.assertTrue(any(urgent for _, urgent in notifier.got))


class TestOneReportADay(unittest.TestCase):
    def test_exactly_one_report_per_day_and_on_quiet_days_too(self):
        _, sent = _run([(QUIET,)] * (3 * 2880), start=0)                         # three days
        daily = [a for _, a in sent if a.about == A.DAILY]
        self.assertEqual(len(daily), 3)
        self.assertIn(A.QUIET_DAY, daily[0].body)

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
        since = {k: 10 ** 6 for k in (ENDED, RETURNED, LEFT, NOT_READ, PASS_FAILED, NOT_REMEMBERED)}
        alert = A.daily_report(since, unacknowledged=1.0)
        self.assertLessEqual(len(alert.body), notify.TEXT_LIMIT)
        self.assertIn("saw harden", alert.body)
        self.assertTrue(alert.urgent)

    def test_a_return_not_dealt_with_is_never_reported_as_a_quiet_day(self):
        alert = A.daily_report({}, unacknowledged=1.0)
        self.assertNotIn(A.QUIET_DAY, alert.body)
        self.assertIn("saw harden", alert.body)

    def test_nothing_from_the_machine_reaches_a_notification(self):
        _, sent = _run([(ENDED, RETURNED, LEFT, NOT_READ)] * 20 + [(QUIET,)] * 2900, start=0)
        for _, a in sent:
            self.assertNotIn("/", a.body.replace("`saw watch status`", ""))


class TestNothingOnDiskCanHangOrStopIt(unittest.TestCase):
    def _within(self, call, seconds=3.0):
        out = []
        t = threading.Thread(target=lambda: out.append(call()), daemon=True)
        t.start()
        t.join(seconds)
        self.assertFalse(t.is_alive(), "it waited on something that is not a file")
        return out[0]

    def test_a_pipe_in_place_of_any_state_file_is_not_waited_on(self):
        with tempfile.TemporaryDirectory() as d:
            for name in ("watch-events.json", "watch-install.json", "live-code.json", "item"):
                os.mkfifo(Path(d) / name)
            self.assertEqual(self._within(lambda: watchrecord.load(Path(d) / "watch-events.json")),
                             {})
            self.assertIsNone(self._within(lambda: schedule.recorded(Path(d) / "watch-install.json")))
            self.assertEqual(self._within(lambda: liveledger.load(Path(d) / "live-code.json")).status,
                             liveledger.CORRUPT)
            self.assertEqual(self._within(lambda: schedule.verdict(Path(d) / "item", saw=["saw"])),
                             schedule.UNREADABLE)

    def test_a_record_that_cannot_be_parsed_is_an_empty_one(self):
        with tempfile.TemporaryDirectory() as d:
            where = Path(d) / "w.json"
            for text in ("{not json", '{"last_good": ' + "9" * 5000 + "}", "\xff\xfe",
                         "[" * 50_000 + "]" * 50_000):
                with self.subTest(text=text[:12]):
                    where.write_text(text, encoding="utf-8", errors="surrogateescape")
                    self.assertEqual(watchrecord.load(where), {})

    def test_a_ledger_row_of_the_wrong_type_is_corrupt_not_fatal(self):
        with tempfile.TemporaryDirectory() as d:
            where = Path(d) / "live.json"
            where.write_text('{"entries": {"k": {"times": "x"}}, "self_hash": ""}')
            self.assertEqual(liveledger.load(where).status, liveledger.CORRUPT)

    def test_a_huge_number_in_the_record_does_not_stop_harden_status_or_the_notice(self):
        with tempfile.TemporaryDirectory() as d:
            where = Path(d) / "w.json"
            where.write_text('{"last_good": %d, "unacknowledged": 5}' % HUGE)
            record = watchrecord.load(where)
            self.assertEqual(record, {"unacknowledged": 5})
            self.assertTrue(watchrecord.acknowledge(where, now=lambda: 6.0))


class TestEveryCommandSaysWhenTheWatcherNeedsYou(unittest.TestCase):
    def test_the_line_any_command_prints(self):
        def notice(record, *, placed=True, since=9_990.0):
            return watch.foreground_notice(record=lambda: record, placed=lambda: placed,
                                           clock=lambda: 10_000.0, placed_since=lambda: since)
        self.assertEqual(notice({}), "", "a watcher placed seconds ago has not missed a pass")
        self.assertEqual(notice({"last_good": 9_990.0}), "")
        self.assertIn("saw harden", notice({"unacknowledged": 1.0, "last_good": 9_990.0}))
        self.assertEqual(notice({"last_good": 0.0}), watch._STALLED)
        self.assertEqual(notice({}, since=0.0), watch._STALLED)
        self.assertEqual(notice({}, since=None), watch._STALLED)
        self.assertEqual(notice({"last_good": 0.0}, placed=False), "")

    def test_every_command_but_watch_prints_it_on_stderr(self):
        from stayawake.cli import dispatch
        for argv, expected in ((["search", "scan"], 1), (["watch", "status"], 0)):
            with self.subTest(argv=argv):
                err = io.StringIO()
                with mock.patch.object(watch, "foreground_notice", return_value=watch._STALLED), \
                     mock.patch.object(watch, "status_of", return_value=(0, "")), \
                     contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(err):
                    dispatch.main(argv)
                self.assertEqual(err.getvalue().count(watch._STALLED), expected)

    def test_the_line_never_reaches_stdout_or_stops_the_command(self):
        from stayawake.cli import dispatch

        class Broken(io.StringIO):
            def write(self, s):
                raise BrokenPipeError()
        for stderr in (None, Broken()):
            with self.subTest(stderr=stderr):
                out, ran = io.StringIO(), []
                with mock.patch.object(watch, "foreground_notice", return_value=watch._STALLED), \
                     mock.patch("stayawake.cli.commands.search.run",
                                lambda a: ran.append(1) or 0), \
                     mock.patch.object(dispatch.sys, "stderr", stderr), \
                     contextlib.redirect_stdout(out):
                    dispatch.main(["search", "scan"])
                self.assertEqual(ran, [1])
                self.assertNotIn(watch._STALLED, out.getvalue())

    def test_a_watch_whose_output_breaks_keeps_going(self):
        made = []

        def report(text):
            raise BrokenPipeError()
        watch.keep_going(once=lambda: made.append(1) or (1, (ENDED,)), sleep=lambda n: None,
                         passes=3, report=report)
        self.assertEqual(len(made), 3)

    def test_a_protected_harden_run_marks_a_return_dealt_with(self):
        from stayawake.cli.commands import harden as cli_harden
        acked, said = [], []

        def run_harden(code, ack):
            with mock.patch.object(cli_harden.harden, "run", return_value=(code, "done")), \
                 mock.patch.object(cli_harden, "acknowledge_came_back", ack), \
                 mock.patch.object(cli_harden, "say", lambda text, **k: said.append(text)):
                return cli_harden.run(argparse.Namespace(take_back=False, no_stream=True))
        self.assertEqual(run_harden(0, lambda: acked.append(1) or True), 0)
        self.assertEqual(run_harden(3, lambda: acked.append(2) or True), 3)
        self.assertEqual(acked, [1])

        def raising():
            raise OverflowError("x")
        self.assertEqual(run_harden(0, raising), 0, "acknowledging failed the harden run")
        self.assertEqual(said[-1], cli_harden._NOT_ACKNOWLEDGED)


class TestTheRecordHoldsOnlyCountsAndTimes(unittest.TestCase):
    def test_acknowledge_clears_a_return(self):
        where = Path(tempfile.mkdtemp()) / "w.json"
        self.assertTrue(watchrecord.save({"unacknowledged": 5.0, "reminded": 6.0}, where))
        self.assertTrue(watchrecord.acknowledge(where, now=lambda: 7.0))
        self.assertIsNone(watchrecord.load(where).get("unacknowledged"))

    def test_a_heartbeat_too_old_or_dated_ahead_is_stale(self):
        self.assertTrue(watchrecord.stale({}, 1000.0))
        self.assertTrue(watchrecord.stale({"last_good": 0.0}, 1000.0))
        self.assertTrue(watchrecord.stale({"last_good": 5000.0}, 1000.0))
        self.assertTrue(watchrecord.stale({"last_good": "900"}, 1000.0))
        self.assertFalse(watchrecord.stale({"last_good": 900.0}, 1000.0))
        self.assertFalse(watchrecord.stale({}, 1000.0, placed_since=990.0))
        self.assertTrue(watchrecord.stale({}, 1000.0, placed_since=0.0))

    def test_a_record_of_the_wrong_shape_is_read_as_far_as_it_is_right(self):
        odd = {"last_good": "x", "failures": -5, "since": [1], "sent": {"returned": float("inf")},
               "recent": "abc", "unacknowledged": True, "daily_for": 7, "reminded": 3.0,
               "returned_unsent": "yes"}
        self.assertEqual(watchrecord.well_formed(odd), {"reminded": 3.0, "sent": {}})
        self.assertEqual(watchrecord.well_formed([1, 2]), {})

    def test_any_well_formed_record_reaches_decide_without_raising(self):
        for junk in ({"since": {"x": 1}, "sent": {"y": 2.0}}, {"recent": [1e300, -1e300]},
                     {"failures": 10 ** 9}, {"daily_for": "d0"}, {"sent": {"urgent": -1e300}}):
            with self.subTest(junk=junk):
                A.decide(junk, (ENDED, RETURNED, NOT_READ), 36000.0, "d0", 10)


if __name__ == "__main__":
    unittest.main()
