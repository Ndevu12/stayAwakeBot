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
from stayawake.utils.procsnap import identify


@unittest.skipUnless(os.name == "posix", "needs POSIX signals")
class TestItActsOnTheProcessItMeant(unittest.TestCase):
    def setUp(self):
        self.proc = subprocess.Popen(["/bin/sleep", "60"])
        self.addCleanup(self._reap)
        for _ in range(50):
            who, _state = identify(self.proc.pid)
            if who is not None:
                self.start = who.start_time
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
        self.assertEqual(procstop.freeze(self.proc.pid, self.start), procstop.SIGNALLED)
        self.assertFalse(procstop.has_ended(self.proc.pid, self.start, settle=0.1))

    def test_an_ended_process_is_proven_ended_before_it_is_reaped(self):
        # The whole point: the parent has not called wait(), so the kernel still holds the pid.
        procstop.end(self.proc.pid, self.start)
        self.assertTrue(procstop.has_ended(self.proc.pid, self.start),
                        "a killed, unreaped process was reported as still running")

    def test_the_naive_check_disagrees_with_the_truth(self):
        # Pinned so nobody 'simplifies' has_ended into os.kill(pid, 0) later.
        procstop.end(self.proc.pid, self.start)
        time.sleep(0.3)
        os.kill(self.proc.pid, 0)                     # raises only once reaped — it does not here
        self.assertTrue(procstop.has_ended(self.proc.pid, self.start))

    def test_a_recycled_pid_is_never_signalled(self):
        stale = self.start + 9999
        self.assertIn(procstop.end(self.proc.pid, stale), (procstop.RECYCLED,
                                                           procstop.ALREADY_GONE))
        self.assertIsNotNone(identify(self.proc.pid)[0], "it killed the wrong process")

    def test_a_frozen_process_can_be_let_go(self):
        procstop.freeze(self.proc.pid, self.start)
        self.assertEqual(procstop.resume(self.proc.pid, self.start), procstop.SIGNALLED)


@unittest.skipUnless(os.name == "posix", "needs POSIX signals")
class TestItSaysWhatItCouldNotDo(unittest.TestCase):
    def test_another_users_process_is_refused_not_missed(self):
        who, state = identify(1)
        if who is not None:
            self.skipTest("running as a user that can read pid 1")
        self.assertEqual(procstop.end(1, 1), procstop.REFUSED)

    def test_a_pid_that_does_not_exist_is_already_gone(self):
        self.assertEqual(procstop.end(999_999, 1), procstop.ALREADY_GONE)
        self.assertTrue(procstop.has_ended(999_999, 1, settle=0.05))


if __name__ == "__main__":
    unittest.main()
