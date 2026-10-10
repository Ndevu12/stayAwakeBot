#!/usr/bin/env python3
"""Desktop notifications reach the user as data, through the system's own programs, never PATH."""
from __future__ import annotations

import stat
import subprocess
import unittest
from types import SimpleNamespace
from unittest import mock

from stayawake.utils import notify
from stayawake.utils.systembin import system_binary


class _Capture:
    def __init__(self, returncode=0, stdout=""):
        self.calls = []
        self.returncode, self.stdout = returncode, stdout

    def __call__(self, argv, **kw):
        self.calls.append((argv, kw))
        return SimpleNamespace(returncode=self.returncode, stdout=self.stdout, stderr="")


_HOSTILE = '"; do shell script "rm -rf ~" --\x1b]0;x\x07 <a href="x">end run</a>\n-e'


class TestMacOS(unittest.TestCase):
    def test_text_travels_as_arguments_to_a_fixed_script(self):
        run = _Capture()
        got = notify.OsascriptNotifier(run=run, binary="/usr/bin/osascript").send("saw", _HOSTILE)
        argv, kw = run.calls[0]
        self.assertEqual(argv[:7], ["/usr/bin/osascript", "-e", "on run argv", "-e",
                                    "display notification (item 1 of argv) with title "
                                    "(item 2 of argv)", "-e", "end run"])
        body = argv[7]
        self.assertNotIn("\x1b", body)
        self.assertNotIn("\n", body)
        self.assertFalse(body.startswith("-"))
        self.assertEqual(kw["env"], {})
        self.assertEqual(got.state, notify.UNCONFIRMED)

    def test_a_runner_that_refuses_is_a_failure(self):
        got = notify.OsascriptNotifier(run=_Capture(returncode=1), binary="/x").send("t", "b")
        self.assertEqual(got.state, notify.FAILED)

    def test_no_trusted_runner_is_unavailable(self):
        with mock.patch.object(notify, "system_binary", return_value=None):
            got = notify.OsascriptNotifier(run=_Capture()).send("t", "b")
        self.assertEqual(got.state, notify.UNAVAILABLE)


def _bus(mode=stat.S_IFSOCK | 0o600, uid=1000):
    def lstat(path):
        if path != "/run/user/1000/bus":
            raise FileNotFoundError(path)
        return SimpleNamespace(st_mode=mode, st_uid=uid)
    return lstat


def _linux(run, **kw):
    kw.setdefault("lstat", _bus())
    return notify.FreedesktopNotifier(run=run, binary="/usr/bin/busctl", uid=lambda: 1000, **kw)


class TestLinux(unittest.TestCase):
    def test_typed_arguments_escaped_markup_and_only_the_session_bus_environment(self):
        run = _Capture(stdout="u 42\n")
        with mock.patch.dict("os.environ", {"DBUS_SESSION_BUS_ADDRESS":
                                            "unixexec:path=/bin/sh,argv1=-c,argv2=id",
                                            "XDG_RUNTIME_DIR": "/tmp/evil", "PATH": "/tmp/evil"}):
            got = _linux(run).send("saw", _HOSTILE, urgent=True, replaces=7)
        argv, kw = run.calls[0]
        self.assertEqual(argv[:5], ["/usr/bin/busctl", "--user", "--timeout=10", "--", "call"])
        self.assertIn("susssasa{sv}i", argv)
        body = argv[argv.index("susssasa{sv}i") + 5]
        self.assertNotIn("<", body)
        self.assertNotIn("\x1b", body)
        self.assertEqual(argv[argv.index("susssasa{sv}i") + 2], "7")
        self.assertEqual(argv[-2:], ["2", "0"])
        self.assertEqual(kw["env"], {"XDG_RUNTIME_DIR": "/run/user/1000",
                                     "DBUS_SESSION_BUS_ADDRESS": "unix:path=/run/user/1000/bus"})
        self.assertEqual(got, notify.Delivery(notify.SENT, 42))

    def test_a_bus_that_is_not_this_users_own_socket_is_not_used(self):
        for lstat in (_bus(uid=0), _bus(mode=stat.S_IFREG | 0o600), _bus(mode=stat.S_IFIFO),
                      lambda p: (_ for _ in ()).throw(FileNotFoundError(p))):
            with self.subTest(lstat=lstat):
                run = _Capture()
                self.assertEqual(_linux(run, lstat=lstat).send("t", "b").state, notify.UNAVAILABLE)
                self.assertEqual(run.calls, [])

    def test_no_notification_service_is_a_failure(self):
        self.assertEqual(_linux(_Capture(returncode=1)).send("t", "b").state, notify.FAILED)

    def test_a_runner_that_hangs_is_a_failure(self):
        def hang(argv, **kw):
            raise subprocess.TimeoutExpired(argv, 1)
        self.assertEqual(_linux(hang).send("t", "b").state, notify.FAILED)

    def test_an_answer_it_cannot_read_never_raises(self):
        def undecodable(argv, **kw):
            raise UnicodeDecodeError("utf-8", b"\xff", 0, 1, "invalid start byte")
        for answer in ("u \u00b2", "u 99999999999999999999", "x"):
            with self.subTest(answer=answer):
                self.assertEqual(_linux(_Capture(stdout=answer)).send("t", "b").state, notify.SENT,
                                 "a notification that was shown must not be shown again")
        self.assertEqual(_linux(undecodable).send("t", "b").state, notify.FAILED)
        self.assertEqual(notify.OsascriptNotifier(run=undecodable, binary="/x").send("t", "b").state,
                         notify.FAILED)


class TestNothingIsSentWhereNothingIsSupported(unittest.TestCase):
    def test_other_platforms_send_nothing(self):
        self.assertIsInstance(notify.platform_notifier("win32"), notify.NoNotifier)
        self.assertEqual(notify.NoNotifier().send("t", "b").state, notify.UNAVAILABLE)


class TestSystemBinary(unittest.TestCase):
    @staticmethod
    def _st(uid=0, mode=0o100755):
        return lambda path: SimpleNamespace(st_uid=uid, st_mode=mode)

    def test_a_root_owned_program_no_one_else_can_write_is_taken(self):
        self.assertEqual(system_binary(["/usr/bin/x"], stat=self._st(),
                                       access=lambda p, m: True), "/usr/bin/x")

    def test_a_program_another_user_owns_or_can_write_is_refused(self):
        for st in (self._st(uid=501), self._st(mode=0o100775), self._st(mode=0o100757)):
            self.assertIsNone(system_binary(["/usr/bin/x"], stat=st, access=lambda p, m: True))

    def test_a_relative_name_is_never_looked_up(self):
        self.assertIsNone(system_binary(["osascript"], stat=self._st(),
                                        access=lambda p, m: True))

    def test_a_directory_is_not_a_program(self):
        self.assertIsNone(system_binary(["/usr/bin"], stat=self._st(mode=stat.S_IFDIR | 0o755),
                                        access=lambda p, m: True))


if __name__ == "__main__":
    unittest.main()
