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
        record = watchrecord.settled(record, watchrecord.returns_so_far(record))
        self.assertNotIn("unacknowledged", record)
        _, sent = _run([(ENDED, RETURNED)], start=36400, record=record)
        self.assertEqual([a.about for _, a in _urgent(sent)], [RETURNED])

    def test_a_return_seen_while_harden_ran_is_not_dealt_with_by_it(self):
        record, _ = _run([(ENDED, RETURNED)], start=36000)
        record, sent = _run([(ENDED, RETURNED)], start=36300, record=record)    # window busy
        self.assertEqual(record["returns_seen"], 2)
        self.assertFalse(_urgent(sent))
        record = watchrecord.settled(record, (record["epoch"], 1))             # harden began first
        self.assertTrue(record.get("unacknowledged"))
        _, sent = _run([(QUIET,)] * 30, start=36330, record=record)
        told = [(t, a.about) for t, a in _urgent(sent)]
        self.assertEqual([about for _, about in told], [RETURNED], "the second return was lost")
        self.assertLessEqual(told[0][0] - 36000, A.URGENT_EVERY_SECONDS + 30)

    def test_an_acknowledgement_is_written_apart_from_the_record_and_read_back(self):
        with tempfile.TemporaryDirectory() as d:
            where = Path(d) / "ack.json"
            self.assertTrue(watchrecord.acknowledge(("ab12", 3), where))
            self.assertEqual(watchrecord.load_acknowledgement(where), ("ab12", 3))
            for bad in ('{"epoch": "../x", "through": 3}', '{"epoch": "ab", "through": -1}',
                        '{"epoch": "ab", "through": %d}' % HUGE, "[1]", "{"):
                with self.subTest(bad=bad[:24]):
                    where.write_text(bad)
                    self.assertIsNone(watchrecord.load_acknowledgement(where))

    def test_no_clock_step_lets_an_acknowledgement_clear_a_later_return(self):
        record, _ = _run([(ENDED, RETURNED)], start=10_000)
        acknowledged = watchrecord.returns_so_far(record)                      # harden starts
        for step_back in (30, 3600, DAY):
            with self.subTest(step_back=step_back):
                later, _ = _run([(ENDED, RETURNED)], start=10_060 - step_back, record=record)
                self.assertTrue(watchrecord.settled(later, acknowledged).get("unacknowledged"))

    def test_an_acknowledgement_for_another_record_never_applies(self):
        record, _ = _run([(ENDED, RETURNED)], start=36000)
        self.assertTrue(watchrecord.settled(record, ("0" * 16, 10 ** 6)).get("unacknowledged"))

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

    def test_a_clock_stepped_back_does_not_hold_back_a_reminder(self):
        record, _ = _run([(ENDED, RETURNED)], start=90000)
        _, sent = _run([(QUIET,)] * 3, start=50000, record=record)
        self.assertEqual([a.about for _, a in _urgent(sent)], [A.REMINDER])

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
        self.assertEqual(watch.foreground_notice(record=lambda: store["r"],
                                                 acknowledged=lambda: None, **placed),
                         watch._NOT_SHOWN)
        code, text = watch.status_of(supported=lambda: True, verdict=lambda: schedule.PRISTINE,
                                     running=lambda: True, record=lambda: store["r"],
                                     clock=lambda: 36040.0, placed_since=lambda: 0.0,
                                     acknowledged=lambda: None)
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

    def test_a_day_with_only_unidentified_code_is_not_called_quiet(self):
        alert = A.daily_report({"unnamed": 4}, unacknowledged=None)
        self.assertNotIn(A.QUIET_DAY, alert.body)
        self.assertIn("could not identify 4 times", alert.body)

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
            where.write_text('{"last_good": %d, "unacknowledged": 5, "epoch": "ab", '
                             '"returns_seen": 1}' % HUGE)
            record = watchrecord.load(where)
            self.assertEqual(record, {"unacknowledged": 5, "epoch": "ab", "returns_seen": 1})
            self.assertNotIn("unacknowledged", watchrecord.settled(record, ("ab", 1)))

    def test_a_ledger_nested_deep_enough_to_break_a_reader_still_lets_the_pass_stop_code(self):
        deep = "[" * 100_000 + "]" * 100_000
        with tempfile.TemporaryDirectory() as d:
            where = Path(d) / "live.json"
            where.write_text('{"entries": {"k": {"times": 1, "first": %s}}, "self_hash": "x"}' % deep)
            self.assertEqual(liveledger.load(where).status, liveledger.CORRUPT)

        def boom():
            raise RecursionError("deep")
        stopped = []
        from stayawake.bots.security.livecode import LiveCode
        from stayawake.utils.procsnap import Process, Snapshot
        bad = LiveCode(Process(pid=7, argv=("node", "-e", "x")), "x", "shape", True)
        watch.examine(find=lambda: [bad], load=boom, save=lambda ledger: True,
                      stop=lambda **k: stopped.append(1) or mock.Mock(ended=True, finished=True),
                      look=lambda: Snapshot(processes=[Process(pid=1, argv=("launchd",))]))
        self.assertEqual(stopped, [1], "a ledger that could not be read kept the pass from stopping")

    def test_an_install_record_nested_too_deep_is_no_record_and_fast(self):
        deep = "[" * 100_000 + "]" * 100_000
        with tempfile.TemporaryDirectory() as d:
            where = Path(d) / "watch-install.json"
            where.write_text('{"argv": [%s]}' % deep)
            began = time.monotonic()
            self.assertIsNone(schedule.recorded(where))
            self.assertLess(time.monotonic() - began, 1.0)
            self.assertTrue(schedule.was_placed(where), "a record that is there was not counted")
            where.write_bytes(b'{"argv": ["saw\xff"]}')
            self.assertIsNone(schedule.recorded(where), "a record with an invalid byte was used")

    def test_an_item_too_large_to_be_saws_is_altered_and_one_not_utf8_too(self):
        with tempfile.TemporaryDirectory() as d:
            big, odd = Path(d) / "big", Path(d) / "odd"
            big.write_text("x" * (300 << 10))
            odd.write_bytes(b"\xff\xfe")
            self.assertEqual(schedule.verdict(big, saw=["saw"]), schedule.ALTERED)
            self.assertEqual(schedule.verdict(odd, saw=["saw"]), schedule.ALTERED)

    def test_a_ledger_reached_through_a_link_is_still_read(self):
        with tempfile.TemporaryDirectory() as d:
            real, link = Path(d) / "real.json", Path(d) / "live.json"
            liveledger.save(liveledger.Ledger(status=liveledger.LOADED), real)
            link.symlink_to(real)
            self.assertEqual(liveledger.load(link).status, liveledger.LOADED)

    def test_a_placement_dated_ahead_or_a_linked_record_is_not_a_recent_one(self):
        self.assertTrue(watchrecord.stale({}, 1000.0, placed_since=1000.0 + 30 * DAY))
        with tempfile.TemporaryDirectory() as d:
            real, link = Path(d) / "real", Path(d) / "watch-install.json"
            real.write_text("{}")
            link.symlink_to(real)
            self.assertIsNone(schedule.placed_since(link))

    def test_the_service_manager_reaches_only_this_users_own_bus_on_linux(self):
        seen = []
        bus = {"XDG_RUNTIME_DIR": "/run/user/1000",
               "DBUS_SESSION_BUS_ADDRESS": "unix:path=/run/user/1000/bus"}
        with mock.patch.object(schedule, "_linux", return_value=True), \
             mock.patch.object(schedule.sessionbus, "user_manager_env", return_value=bus), \
             mock.patch.dict(os.environ, {"DBUS_SESSION_BUS_ADDRESS": "unixexec:path=/bin/sh"}):
            schedule.is_running(run=lambda argv, **k: seen.append(k.get("env"))
                                or mock.Mock(returncode=0), binary="/usr/bin/systemctl")
        self.assertEqual(seen, [bus])

    def test_a_user_manager_without_a_session_bus_is_still_reached(self):
        import stat as st
        from types import SimpleNamespace
        from stayawake.utils import sessionbus

        def lstat(path):
            if path == "/run/user/1000":
                return SimpleNamespace(st_mode=st.S_IFDIR | 0o700, st_uid=1000)
            raise FileNotFoundError(path)
        self.assertEqual(sessionbus.user_manager_env(uid=lambda: 1000, lstat=lstat),
                         {"XDG_RUNTIME_DIR": "/run/user/1000"})

        def foreign(path):
            return SimpleNamespace(st_mode=st.S_IFDIR | 0o700, st_uid=0)
        self.assertEqual(sessionbus.user_manager_env(uid=lambda: 1000, lstat=foreign), {})


class TestEveryCommandSaysWhenTheWatcherNeedsYou(unittest.TestCase):
    def test_the_line_any_command_prints(self):
        def notice(record, *, placed=True, since=9_990.0):
            return watch.foreground_notice(record=lambda: record, placed=lambda: placed,
                                           clock=lambda: 10_000.0, placed_since=lambda: since,
                                           acknowledged=lambda: None)
        self.assertEqual(notice({}), "", "a watcher placed seconds ago has not missed a pass")
        self.assertEqual(notice({"last_good": 9_990.0}), "")
        self.assertIn("saw harden", notice({"unacknowledged": 1.0, "last_good": 9_990.0}))
        self.assertEqual(notice({"last_good": 0.0}), watch._STALLED)
        self.assertEqual(notice({}, since=0.0), watch._STALLED)
        self.assertEqual(notice({}, since=None), watch._STALLED)
        self.assertEqual(notice({"last_good": 0.0}, placed=False), "")
        both = notice({"unacknowledged": 1.0, "last_good": 0.0})
        self.assertIn("saw harden", both)
        self.assertIn(watch._STALLED, both, "a stalled watcher hidden behind a return")

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

        open_return = {"unacknowledged": 1.0, "epoch": "ab", "returns_seen": 1}

        def run_harden(code, ack, before=open_return, after=None):
            reads = [dict(before), dict(after if after is not None else before)]
            with mock.patch.object(cli_harden.harden, "run", return_value=(code, "done")), \
                 mock.patch.object(cli_harden, "acknowledge_came_back", ack), \
                 mock.patch.object(cli_harden.watchrecord, "load", lambda: reads.pop(0)), \
                 mock.patch.object(cli_harden.watchrecord, "load_acknowledgement",
                                   lambda: acked[-1] if acked else None), \
                 mock.patch.object(cli_harden, "say", lambda text, **k: said.append(text)):
                return cli_harden.run(argparse.Namespace(take_back=False, no_stream=True))
        self.assertEqual(run_harden(0, lambda through: acked.append(through) or True), 0)
        self.assertEqual(acked, [("ab", 1)], "harden did not acknowledge what it saw at its start")
        self.assertEqual(run_harden(3, lambda through: acked.append(("x", 0)) or True), 3)
        self.assertEqual(acked, [("ab", 1)])
        self.assertEqual(said, ["done", "done"])

        def raising(through):
            raise OverflowError("x")
        self.assertEqual(run_harden(0, raising), 0, "acknowledging failed the harden run")
        self.assertEqual(said[-1], cli_harden._NOT_ACKNOWLEDGED)
        self.assertIn("saw watch status", cli_harden._NOT_ACKNOWLEDGED)
        returned_during = dict(open_return, returns_seen=2)
        run_harden(0, lambda through: acked.append(through) or True, after=returned_during)
        self.assertEqual(said[-1], cli_harden._CAME_BACK_DURING)
        said.clear()
        run_harden(0, lambda through: acked.append(through) or True, before={})
        self.assertEqual(said, ["done"], "a machine without a watcher record got a watcher line")


class TestTheRecordHoldsOnlyCountsAndTimes(unittest.TestCase):
    def test_an_acknowledgement_settles_only_returns_counted_before_harden_started(self):
        before = {"unacknowledged": 5.0, "epoch": "ab", "returns_seen": 2, "reminded": 6.0,
                  "returned_unsent": True}
        self.assertEqual(watchrecord.settled(before, ("ab", 2)),
                         {"epoch": "ab", "returns_seen": 2, "window_reopened": True})
        self.assertEqual(watchrecord.settled(before, ("ab", 1)), before)
        self.assertEqual(watchrecord.settled(before, ("cd", 9)), before)
        self.assertEqual(watchrecord.settled(before, None), before)

    def test_the_watcher_and_the_users_commands_share_one_folder_whatever_the_state_setting(self):
        with tempfile.TemporaryDirectory() as home:
            with mock.patch.dict(os.environ, {"HOME": home, "XDG_STATE_HOME": "/elsewhere"}):
                self.assertEqual(watchrecord.record_path().parent,
                                 Path(home) / ".local" / "state" / "saw")
                self.assertEqual(watchrecord.acknowledgement_path().parent,
                                 watchrecord.record_path().parent)

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
