#!/usr/bin/env python3
"""The watcher's state files: read as far as they are right, never waited on, shared by the
scheduled watcher and the user's commands, and settled only by `saw harden`'s exact count."""
from __future__ import annotations

import os
import tempfile
import threading
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from stayawake.bots.security import liveledger, schedule, watchack, watchrecord, watchstate

HUGE = 10 ** 400
DAY = 86400


class TestStateFilesAreReadSafely(unittest.TestCase):
    def _within(self, call, seconds=3.0):
        out = []
        t = threading.Thread(target=lambda: out.append(call()), daemon=True)
        t.start()
        t.join(seconds)
        self.assertFalse(t.is_alive(), "it waited on something that is not a file")
        return out[0]

    def test_a_pipe_in_place_of_any_state_file_is_not_waited_on(self):
        with tempfile.TemporaryDirectory() as d:
            for name in ("events", "ack", "install", "live", "item"):
                os.mkfifo(Path(d) / name)
            self.assertEqual(self._within(lambda: watchrecord.load(Path(d) / "events")), {})
            self.assertIsNone(self._within(lambda: watchack.load_acknowledgement(Path(d) / "ack")))
            self.assertIsNone(self._within(lambda: schedule.recorded(Path(d) / "install")))
            self.assertEqual(self._within(lambda: liveledger.load(Path(d) / "live")).status,
                             liveledger.CORRUPT)
            self.assertEqual(self._within(lambda: schedule.verdict(Path(d) / "item", saw=["saw"])),
                             schedule.UNREADABLE)

    def test_a_pipe_raced_in_after_a_write_is_not_waited_on(self):
        from stayawake.utils import atomicwrite
        real_replace = os.replace

        def replace_then_race(staged, where):
            real_replace(staged, where)
            os.unlink(where)
            os.mkfifo(where)
        with tempfile.TemporaryDirectory() as d, \
                mock.patch.object(atomicwrite.os, "replace", replace_then_race):
            where = Path(d) / "w.json"
            self.assertFalse(self._within(lambda: watchrecord.save({"a": 1}, where)))

    def test_a_record_that_cannot_be_parsed_is_an_empty_one(self):
        with tempfile.TemporaryDirectory() as d:
            where = Path(d) / "w.json"
            for text in ("{not json", '{"last_good": ' + "9" * 5000 + "}", "[" * 50_000 + "]" * 50_000):
                with self.subTest(text=text[:12]):
                    where.write_text(text)
                    self.assertEqual(watchrecord.load(where), {})
            where.write_bytes(b"\xff\xfe")
            self.assertEqual(watchrecord.load(where), {})

    def test_a_record_of_the_wrong_shape_is_read_as_far_as_it_is_right(self):
        odd = {"last_good": "x", "failures": -5, "since": [1], "told": {"came-back": float("inf")},
               "pending": {"came-back": "yes", "x" * 40: True}, "unacknowledged": True,
               "daily_for": 7, "urgent_at": 3.0, "returns_seen": HUGE, "epoch": "../x"}
        self.assertEqual(watchrecord.well_formed(odd), {"urgent_at": 3.0, "told": {},
                                                        "pending": {}})
        self.assertEqual(watchrecord.well_formed([1, 2]), {})

    def test_a_huge_number_is_dropped_not_fatal(self):
        with tempfile.TemporaryDirectory() as d:
            where = Path(d) / "w.json"
            where.write_text('{"last_good": %d, "unacknowledged": 5, "epoch": "ab", '
                             '"returns_seen": 1}' % HUGE)
            self.assertEqual(watchrecord.load(where),
                             {"unacknowledged": 5, "epoch": "ab", "returns_seen": 1})

    def test_under_sudo_it_reads_the_folder_of_the_user_who_ran_it(self):
        invoker = SimpleNamespace(raised=True, home=Path("/accounts/me"))
        with mock.patch.object(watchrecord.operator, "resolve", return_value=invoker):
            self.assertEqual(watchrecord.shared_folder(), Path("/accounts/me/.local/state/saw"))

    def test_root_never_writes_under_a_folder_another_account_owns(self):
        with tempfile.TemporaryDirectory() as d, \
             mock.patch.object(watchrecord.os, "geteuid", return_value=0), \
             mock.patch.object(watchrecord.atomicwrite, "replace") as write:
            self.assertNotEqual(os.lstat(d).st_uid, 0)
            self.assertFalse(watchrecord.write_state(Path(d) / "ack.json", {"a": 1}))
            self.assertFalse(watchrecord.write_state(Path(d) / "missing" / "ack.json", {"a": 1}))
            write.assert_not_called()
            self.assertEqual(list(Path(d).iterdir()), [], "root wrote into the user's folder")

    def test_root_keeps_its_own_watchers_record(self):
        real_lstat = os.lstat
        with tempfile.TemporaryDirectory() as d, \
             mock.patch.object(watchrecord.os, "geteuid", return_value=0), \
             mock.patch.object(watchrecord.os, "lstat",
                               lambda p: SimpleNamespace(st_uid=0, st_mode=real_lstat(p).st_mode)):
            self.assertTrue(watchrecord.write_state(Path(d) / "events.json", {"a": 1}))

    def test_the_watcher_and_the_users_commands_share_one_folder_whatever_the_environment(self):
        account = SimpleNamespace(pw_dir="/accounts/me")
        with mock.patch.object(watchrecord.pwd, "getpwuid", return_value=account), \
             mock.patch.object(watchrecord.operator, "resolve", return_value=None), \
             mock.patch.dict(os.environ, {"HOME": "/elsewhere", "XDG_STATE_HOME": "/other"}):
            self.assertEqual(watchrecord.record_path().parent,
                             Path("/accounts/me/.local/state/saw"))
            self.assertEqual(watchack.acknowledgement_path().parent,
                             watchrecord.record_path().parent)


class TestHardenSettlesOnlyWhatItCounted(unittest.TestCase):
    def test_an_acknowledgement_is_written_apart_from_the_record_and_read_back(self):
        with tempfile.TemporaryDirectory() as d:
            where = Path(d) / "ack.json"
            self.assertTrue(watchack.acknowledge(watchack.Counted("ab12", 3, 5.0), where))
            self.assertEqual(watchack.load_acknowledgement(where), watchack.Counted("ab12", 3, 5.0))
            self.assertTrue(watchack.acknowledge(watchack.Counted("ab12", 3), where))
            self.assertEqual(watchack.load_acknowledgement(where), watchack.Counted("ab12", 3))
            for bad in ('{"epoch": "../x", "through": 3}', '{"epoch": "ab", "through": -1}',
                        '{"epoch": "ab", "through": %d}' % HUGE, "[1]", "{"):
                with self.subTest(bad=bad[:24]):
                    where.write_text(bad)
                    self.assertIsNone(watchack.load_acknowledgement(where))

    def test_it_settles_the_exact_count_only(self):
        C = watchack.Counted
        open_ = {"unacknowledged": 5.0, "epoch": "ab", "returns_seen": 2,
                 "pending": {"came-back": True}}
        self.assertEqual(watchack.settled(open_, C("ab", 2)),
                         {"epoch": "ab", "returns_seen": 2, "pending": {},
                          "window_reopened": True})
        self.assertEqual(watchack.settled(open_, C("ab", 1)), open_, "a later return was settled")
        self.assertEqual(watchack.settled(open_, C("ab", 10 ** 9)), open_,
                         "a count past the record's settled it forever")
        self.assertEqual(watchack.settled(open_, C("cd", 2)), open_)
        self.assertEqual(watchack.settled(open_, None), open_)

    def test_it_settles_the_streak_of_code_that_could_not_be_stopped_it_saw(self):
        C = watchack.Counted
        open_ = {"not_stopped": 100.0, "epoch": "ab", "returns_seen": 0,
                 "pending": {"not-stopped": True}}
        self.assertNotIn("not_stopped", watchack.settled(open_, C("ab", 0, 100.0)))
        self.assertIn("not_stopped", watchack.settled(open_, C("ab", 0, 50.0)),
                      "a newer streak was settled by an older acknowledgement")
        self.assertIn("not_stopped", watchack.settled(open_, C("ab", 0)))

    def test_harden_counts_what_the_record_holds_when_it_starts(self):
        self.assertEqual(watchack.counted_so_far({"epoch": "ab", "returns_seen": 4,
                                                  "not_stopped": 9.0}),
                         watchack.Counted("ab", 4, 9.0))
        self.assertIsNone(watchack.counted_so_far({}))


class TestCameBackMeansItWasGone(unittest.TestCase):
    def _seen(self, *passes):
        from stayawake.bots.security.livecode import LiveCode
        from stayawake.utils.procsnap import Process
        from datetime import datetime, timezone, timedelta
        led = liveledger.Ledger(status=liveledger.LOADED)
        t0 = datetime(2026, 10, 10, tzinfo=timezone.utc)
        for i, (present, ended) in enumerate(passes):
            seen = [LiveCode(Process(pid=1, argv=("node", "-e", "x")), "x", "shape", True)]
            led = liveledger.record(led, seen if present else [],
                                    ended_keys={"k"} if ended else (), now=t0 + timedelta(seconds=30 * i))
            led = liveledger.Ledger(entries=led.entries, status=liveledger.LOADED,
                                    last_pass=led.last_pass)
        return led

    def test_code_running_on_without_a_break_has_not_come_back(self):
        from stayawake.bots.security.livecode import fingerprint
        led = self._seen((True, False), (True, False))
        self.assertFalse(led.came_back(fingerprint("x")))

    def test_code_gone_for_a_pass_or_ended_has_come_back(self):
        from stayawake.bots.security.livecode import fingerprint
        self.assertTrue(self._seen((True, False), (False, False)).came_back(fingerprint("x")))

    def test_an_older_ledger_keeps_what_it_knew_and_invents_nothing(self):
        from stayawake.bots.security.livecode import fingerprint
        with tempfile.TemporaryDirectory() as d:
            where = Path(d) / "live.json"
            rows = {fingerprint("x"): {"first": "a", "last": "b", "times": 3,
                                       "identified": True, "ended": 2},
                    fingerprint("y"): {"first": "a", "last": "b", "times": 3,
                                       "identified": True, "ended": 0}}
            import json
            where.write_text(json.dumps({"version": 1, "entries": rows,
                                         "self_hash": liveledger._self_hash(rows)}))
            old = liveledger.load(where)
            self.assertEqual(old.status, liveledger.LOADED)
            self.assertTrue(old.came_back(fingerprint("x")), "an ended row lost its return")
            self.assertFalse(old.came_back(fingerprint("y")), "a return was invented")
            liveledger.save(old, where)
            self.assertEqual(liveledger.load(where).status, liveledger.LOADED)


class TestStaleness(unittest.TestCase):
    def test_a_heartbeat_too_old_or_dated_ahead_is_stale(self):
        self.assertTrue(watchstate.stale({}, 1000.0))
        self.assertTrue(watchstate.stale({"last_good": 0.0}, 1000.0))
        self.assertTrue(watchstate.stale({"last_good": 5000.0}, 1000.0))
        self.assertTrue(watchstate.stale({"last_good": "900"}, 1000.0))
        self.assertFalse(watchstate.stale({"last_good": 900.0}, 1000.0))
        self.assertFalse(watchstate.stale({}, 1000.0, placed_since=990.0))
        self.assertTrue(watchstate.stale({}, 1000.0, placed_since=0.0))
        self.assertTrue(watchstate.stale({}, 1000.0, placed_since=1000.0 + 30 * DAY))


class TestTheScheduleAndTheLedgerReadSafely(unittest.TestCase):
    def test_a_ledger_nested_deep_enough_to_break_a_reader_is_corrupt(self):
        deep = "[" * 100_000 + "]" * 100_000
        with tempfile.TemporaryDirectory() as d:
            where = Path(d) / "live.json"
            where.write_text('{"entries": {"k": {"times": 1, "first": %s}}, "self_hash": "x"}' % deep)
            self.assertEqual(liveledger.load(where).status, liveledger.CORRUPT)
            where.write_text('{"entries": {"k": {"times": "x"}}, "self_hash": ""}')
            self.assertEqual(liveledger.load(where).status, liveledger.CORRUPT)

    def test_a_ledger_reached_through_a_link_is_still_read(self):
        with tempfile.TemporaryDirectory() as d:
            real, link = Path(d) / "real.json", Path(d) / "live.json"
            liveledger.save(liveledger.Ledger(status=liveledger.LOADED), real)
            link.symlink_to(real)
            self.assertEqual(liveledger.load(link).status, liveledger.LOADED)

    def test_an_install_record_nested_too_deep_or_mis_encoded_is_no_record(self):
        deep = "[" * 100_000 + "]" * 100_000
        with tempfile.TemporaryDirectory() as d:
            where = Path(d) / "watch-install.json"
            where.write_text('{"argv": [%s]}' % deep)
            began = time.monotonic()
            self.assertIsNone(schedule.recorded(where))
            self.assertLess(time.monotonic() - began, 1.0)
            self.assertTrue(schedule.was_placed(where), "a record that is there was not counted")
            where.write_bytes(b'{"argv": ["saw\xff"]}')
            self.assertIsNone(schedule.recorded(where))

    def test_an_item_too_large_to_be_saws_or_not_utf8_is_altered(self):
        with tempfile.TemporaryDirectory() as d:
            big, odd = Path(d) / "big", Path(d) / "odd"
            big.write_text("x" * (300 << 10))
            odd.write_bytes(b"\xff\xfe")
            self.assertEqual(schedule.verdict(big, saw=["saw"]), schedule.ALTERED)
            self.assertEqual(schedule.verdict(odd, saw=["saw"]), schedule.ALTERED)

    def test_a_linked_install_record_is_not_a_placement_time(self):
        with tempfile.TemporaryDirectory() as d:
            real, link = Path(d) / "real", Path(d) / "watch-install.json"
            real.write_text("{}")
            link.symlink_to(real)
            self.assertIsNone(schedule.placed_since(link))


if __name__ == "__main__":
    unittest.main()
