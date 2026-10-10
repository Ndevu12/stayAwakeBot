#!/usr/bin/env python3
"""What the user reads about the watcher: every other command's line says everything still open,
on stderr only and never in the way; `saw harden` settles only what it counted; and the service
manager is reached only through the user's own runtime folder."""
from __future__ import annotations

import argparse
import contextlib
import io
import os
import stat as st
import unittest
from types import SimpleNamespace
from unittest import mock

from stayawake.bots.security import schedule, watchack, watchstate, watchstatus
from stayawake.bots.security.watchstate import CAME_BACK, NOT_CHECKING, NOT_SHOWN, NOT_STOPPED
from stayawake.utils import sessionbus

_LINE = watchstate.LINE_FOR


def _notice(record, *, placed=True, since=9_990.0, now=10_000.0):
    return watchstatus.foreground_notice(record=lambda: record, placed=lambda: placed,
                                         clock=lambda: now, placed_since=lambda: since,
                                         acknowledged=lambda: None)


class TestEveryCommandSaysWhatIsStillOpen(unittest.TestCase):
    def test_the_line_any_command_prints(self):
        self.assertEqual(_notice({}), "", "a watcher placed seconds ago has not missed a pass")
        self.assertEqual(_notice({"last_good": 9_990.0}), "")
        self.assertEqual(_notice({"last_good": 0.0}), _LINE[NOT_CHECKING])
        self.assertEqual(_notice({}, since=None), _LINE[NOT_CHECKING])
        both = _notice({"unacknowledged": 1.0, "last_good": 0.0})
        self.assertIn(_LINE[CAME_BACK], both)
        self.assertIn(_LINE[NOT_CHECKING], both, "a stalled watcher hidden behind a return")

    def test_what_could_not_be_stopped_stays_on_every_command_whatever_was_shown(self):
        line = _notice({"last_good": 9_990.0, "not_stopped": 9_000.0})
        self.assertEqual(line, _LINE[NOT_STOPPED])

    def test_what_was_found_is_still_said_after_the_watcher_stops_or_stalls(self):
        for placed, last_good in ((False, 9_990.0), (True, 0.0)):
            with self.subTest(placed=placed, last_good=last_good):
                line = _notice({"unacknowledged": 1.0, "not_stopped": 2.0, "undelivered": 3.0,
                                "last_good": last_good}, placed=placed)
                self.assertIn(_LINE[CAME_BACK], line)
                self.assertIn(_LINE[NOT_STOPPED], line, "code that survived hid by stopping it")
                self.assertNotIn(_LINE[NOT_SHOWN], line)

    def test_failed_notifications_are_said_in_status_not_on_every_command(self):
        record = {"last_good": 9_990.0, "undelivered": 9_000.0}
        self.assertEqual(_notice(record), "")
        code, text = watchstatus.status_of(
            supported=lambda: True, verdict=lambda: schedule.PRISTINE, running=lambda: True,
            record=lambda: record, clock=lambda: 10_000.0, placed_since=lambda: 9_990.0,
            acknowledged=lambda: None)
        self.assertIn(_LINE[NOT_SHOWN], text)
        self.assertEqual(code, 0, "a machine without notifications is not a finding")

    def test_the_line_and_status_agree_for_a_watcher_that_starts_at_next_login(self):
        line = _notice({}, since=0.0)
        self.assertIn("saw watch status", line)
        code, text = watchstatus.status_of(
            supported=lambda: True, verdict=lambda: schedule.PRISTINE, running=lambda: False,
            record=lambda: {}, clock=lambda: 10_000.0, placed_since=lambda: 0.0,
            acknowledged=lambda: None)
        self.assertIn("next login", text)
        self.assertNotIn("saw watch stop", text)

    def test_every_command_but_watch_prints_it_on_stderr(self):
        from stayawake.cli import dispatch
        line = _LINE[NOT_CHECKING]
        for argv, expected in ((["search", "scan"], 1), (["watch", "status"], 0)):
            with self.subTest(argv=argv):
                err = io.StringIO()
                with mock.patch.object(watchstatus, "foreground_notice", return_value=line), \
                     mock.patch.object(watchstatus, "status_of", return_value=(0, "")), \
                     contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(err):
                    dispatch.main(argv)
                self.assertEqual(err.getvalue().count(line), expected)

    def test_the_line_never_reaches_stdout_or_stops_the_command(self):
        from stayawake.cli import dispatch

        class Broken(io.StringIO):
            def write(self, s):
                raise BrokenPipeError()
        for stderr in (None, Broken()):
            with self.subTest(stderr=stderr):
                out, ran = io.StringIO(), []
                with mock.patch.object(watchstatus, "foreground_notice",
                                       return_value=_LINE[NOT_CHECKING]), \
                     mock.patch("stayawake.cli.commands.search.run",
                                lambda a: ran.append(1) or 0), \
                     mock.patch.object(dispatch.sys, "stderr", stderr), \
                     contextlib.redirect_stdout(out):
                    dispatch.main(["search", "scan"])
                self.assertEqual(ran, [1])
                self.assertNotIn(_LINE[NOT_CHECKING], out.getvalue())


class TestHardenSettlesWhatItCountedWhenItStarted(unittest.TestCase):
    def test_harden_acknowledges_its_start_and_says_what_came_back_during_it(self):
        from stayawake.cli.commands import harden as cli_harden
        acked, said = [], []
        open_return = {"unacknowledged": 1.0, "epoch": "ab", "returns_seen": 1}

        def run_harden(code, ack, before=open_return, after=None):
            reads = [dict(before), dict(after if after is not None else before)]
            with mock.patch.object(cli_harden.harden, "run", return_value=(code, "done")), \
                 mock.patch.object(cli_harden, "acknowledge_came_back", ack), \
                 mock.patch.object(cli_harden.watchrecord, "load", lambda: reads.pop(0)), \
                 mock.patch.object(cli_harden.watchack, "load_acknowledgement",
                                   lambda: acked[-1] if acked else None), \
                 mock.patch.object(cli_harden, "say", lambda text, **k: said.append(text)):
                return cli_harden.run(argparse.Namespace(take_back=False, no_stream=True))
        self.assertEqual(run_harden(0, lambda through: acked.append(through) or True), 0)
        self.assertEqual(acked, [watchack.Counted("ab", 1)],
                         "harden did not acknowledge what it saw at its start")
        self.assertEqual(run_harden(3, lambda through: acked.append(through) or True), 3)
        self.assertEqual(len(acked), 2, "live code was dealt with; other controls are not the watcher's")
        self.assertEqual(run_harden(1, lambda through: acked.append(through) or True), 1)
        self.assertEqual(len(acked), 2, "harden left live code running and still settled the alarm")
        self.assertEqual(said, ["done", "done", "done"])

        def raising(through):
            raise OverflowError("x")
        self.assertEqual(run_harden(0, raising), 0, "acknowledging failed the harden run")
        self.assertEqual(said[-1], cli_harden._NOT_ACKNOWLEDGED)
        self.assertIn("saw watch status", cli_harden._NOT_ACKNOWLEDGED)
        run_harden(0, lambda through: acked.append(through) or True,
                   after=dict(open_return, returns_seen=2))
        self.assertEqual(said[-1], cli_harden._CAME_BACK_DURING)
        said.clear()
        run_harden(0, lambda through: acked.append(through) or True, before={})
        self.assertEqual(said, ["done"], "a machine without a watcher record got a watcher line")
        said.clear()
        before_root = len(acked)
        with mock.patch.object(cli_harden.watchrecord, "owned_by_another_account",
                               return_value=True):
            run_harden(0, lambda through: acked.append(through) or True)
        self.assertEqual(len(acked), before_root, "harden under sudo wrote the user's record")
        self.assertEqual(said[-1], cli_harden._SETTLE_WITHOUT_SUDO)


class TestTheServiceManagerIsReachedOnlyThroughTheUsersOwnFolder(unittest.TestCase):
    def _lstat(self, owned):
        def lstat(path):
            if path in owned:
                kind = st.S_IFSOCK if path.endswith("/bus") else st.S_IFDIR
                return SimpleNamespace(st_mode=kind | 0o700, st_uid=owned[path])
            raise FileNotFoundError(path)
        return lstat

    def test_the_runtime_folder_and_bus_are_used_only_when_the_user_owns_them(self):
        env = sessionbus.user_manager_env(
            uid=lambda: 1000, environ={},
            lstat=self._lstat({"/run/user/1000": 1000, "/run/user/1000/bus": 1000}))
        self.assertEqual(env, {"XDG_RUNTIME_DIR": "/run/user/1000",
                               "DBUS_SESSION_BUS_ADDRESS": "unix:path=/run/user/1000/bus"})
        env = sessionbus.user_manager_env(uid=lambda: 1000, environ={},
                                          lstat=self._lstat({"/run/user/1000": 1000}))
        self.assertEqual(env, {"XDG_RUNTIME_DIR": "/run/user/1000"})
        self.assertEqual(sessionbus.user_manager_env(
            uid=lambda: 1000, environ={}, lstat=self._lstat({"/run/user/1000": 0})), {})

    def test_without_one_the_callers_own_runtime_folder_is_used_as_before(self):
        env = sessionbus.user_manager_env(uid=lambda: 1000,
                                          environ={"XDG_RUNTIME_DIR": "/tmp/rt-me"},
                                          lstat=self._lstat({"/tmp/rt-me": 1000}))
        self.assertEqual(env, {"XDG_RUNTIME_DIR": "/tmp/rt-me"})
        env = sessionbus.user_manager_env(uid=lambda: 1000,
                                          environ={"XDG_RUNTIME_DIR": "/tmp/rt-other"},
                                          lstat=self._lstat({"/tmp/rt-other": 0}))
        self.assertEqual(env, {})

    def test_systemctl_gets_that_environment_and_nothing_inherited(self):
        seen = []
        bus = {"XDG_RUNTIME_DIR": "/run/user/1000"}
        with mock.patch.object(schedule, "_linux", return_value=True), \
             mock.patch.object(schedule.sessionbus, "user_manager_env", return_value=bus), \
             mock.patch.dict(os.environ, {"DBUS_SESSION_BUS_ADDRESS": "unixexec:path=/bin/sh"}):
            schedule.is_running(run=lambda argv, **k: seen.append(k.get("env"))
                                or mock.Mock(returncode=0), binary="/usr/bin/systemctl")
        self.assertEqual(seen, [bus])


if __name__ == "__main__":
    unittest.main()
