#!/usr/bin/env python3
"""Signalling a process by identity, and proving it stopped.

Every claim here was measured on a real process before it was written down. The one that matters
most: after SIGKILL and before the parent reaps it, `os.kill(pid, 0)` reports the process ALIVE.
A caller using that check reports a dead implant as still running, and a caller trusting the
opposite mistake kills a stranger that inherited the pid.
"""
from __future__ import annotations

import os
import signal
import subprocess
import time
import unittest

from stayawake.utils import procstop
from stayawake.utils.procsnap import Identity, identify


@unittest.skipUnless(os.name == "posix", "needs POSIX signals")
class TestItActsOnTheProcessItMeant(unittest.TestCase):
    def setUp(self):
        self.proc = subprocess.Popen(["/bin/sleep", "60"])
        self.addCleanup(self._reap)
        for _ in range(50):
            who, _state = identify(self.proc.pid)
            if who is not None:
                self.who = who
                return
            time.sleep(0.02)
        self.skipTest("the child never became readable")

    def _reap(self):
        try:
            os.kill(self.proc.pid, signal.SIGKILL)
        except OSError:
            pass
        try:
            self.proc.wait(timeout=5)
        except Exception:
            pass

    def test_a_frozen_process_is_still_running(self):
        self.assertEqual(procstop.freeze(self.who), procstop.SIGNALLED)
        self.assertFalse(procstop.has_ended(self.who, settle=0.1))

    def test_an_ended_process_is_proven_ended_before_it_is_reaped(self):
        # The whole point: the parent has not called wait(), so the kernel still holds the pid.
        procstop.end(self.who)
        self.assertTrue(procstop.has_ended(self.who),
                        "a killed, unreaped process was reported as still running")

    def test_the_naive_check_disagrees_with_the_truth(self):
        # Pinned so nobody 'simplifies' has_ended into os.kill(pid, 0) later.
        procstop.end(self.who)
        time.sleep(0.3)
        os.kill(self.proc.pid, 0)                     # raises only once reaped — it does not here
        self.assertTrue(procstop.has_ended(self.who))

    def test_a_recycled_pid_is_never_signalled(self):
        import dataclasses
        stale = dataclasses.replace(self.who, start_time=self.who.start_time + 9999)
        self.assertIn(procstop.end(stale), (procstop.RECYCLED, procstop.ALREADY_GONE))
        self.assertIsNotNone(identify(self.proc.pid)[0], "it killed the wrong process")

    def test_the_same_pid_and_second_under_another_uid_is_not_the_same_process(self):
        # macOS reports a start time in whole seconds, so a pid and a start time alone can be
        # shared. The uid is part of the identity for that reason.
        import dataclasses
        stranger = dataclasses.replace(self.who, uid=self.who.uid + 1)
        self.assertEqual(procstop.end(stranger), procstop.RECYCLED)
        self.assertIsNotNone(identify(self.proc.pid)[0], "it signalled a different process")

    def test_a_frozen_process_can_be_let_go(self):
        procstop.freeze(self.who)
        self.assertEqual(procstop.resume(self.who), procstop.SIGNALLED)


@unittest.skipUnless(os.name == "posix", "needs POSIX signals")
class TestItSaysWhatItCouldNotDo(unittest.TestCase):
    def test_another_users_process_is_something_to_ask_about_not_to_give_up_on(self):
        # This used to answer "refused", and refusing is what left another user's implant running
        # on a machine the operator does own.
        who, _state = identify(1)
        if who is not None:
            self.skipTest("running as a user that can read pid 1")
        self.assertEqual(procstop.end(Identity(pid=1, ppid=0, uid=0, start_time=1)),
                         procstop.NEEDS_PRIVILEGE)

    def test_a_signal_refused_by_the_kernel_is_also_something_to_ask_about(self):
        # The other way in, and the one Linux takes: `/proc/<pid>/stat` is world-readable, so the
        # identity reads fine for another user's process and it is the SIGNAL that is refused.
        import os as _os
        from unittest import mock
        who = Identity(pid=_os.getpid(), ppid=1, uid=_os.getuid(), start_time=1)
        with mock.patch.object(procstop, "_still", return_value=("running", who)), \
             mock.patch.object(procstop.os, "kill", side_effect=PermissionError(1, "denied")):
            self.assertEqual(procstop.end(who), procstop.NEEDS_PRIVILEGE)

    def test_it_never_asks_root_to_end_a_pid_that_moved(self):
        # A pid this user cannot read can still be recycled, and asking root to kill a stale one is
        # the same mistake with worse consequences.
        asked = []
        outcome, ended = procstop.end_as_root(
            [4242], signatures={4242: "an old signature"},
            signature=lambda pid: "something else now",
            run_as_root=lambda argv: asked.append(argv) or ("granted", ""))
        self.assertEqual(asked, [], "it asked root to kill a pid that had changed underneath it")
        self.assertEqual(ended, [])

    def test_it_asks_once_for_the_whole_group(self):
        calls = []
        procstop.end_as_root([11, 12, 13], signatures={11: "s", 12: "s", 13: "s"},
                             signature=lambda pid: "s" if calls.count("check") < 3 else None,
                             run_as_root=lambda argv: calls.append(argv) or ("granted", ""))
        self.assertEqual(len(calls), 2, "one freeze and one end for the group, not one per process")
        self.assertIn("-STOP", calls[0])
        self.assertIn("-KILL", calls[1])

    def test_privilege_that_is_not_granted_ends_nothing(self):
        outcome, ended = procstop.end_as_root(
            [11], signatures={11: "s"}, signature=lambda pid: "s",
            run_as_root=lambda argv: ("declined", "not granted"))
        self.assertEqual(outcome, "declined")
        self.assertEqual(ended, [])

    def test_a_pid_that_does_not_exist_is_already_gone(self):
        absent = Identity(pid=999_999, ppid=1, uid=501, start_time=1)
        self.assertEqual(procstop.end(absent), procstop.ALREADY_GONE)
        self.assertTrue(procstop.has_ended(absent, settle=0.05))



if __name__ == "__main__":
    unittest.main()
