#!/usr/bin/env python3
"""A run says how long it expects to take, shows it is alive, and stops itself at its deadline."""
from __future__ import annotations

import signal
import time
import unittest
from unittest import mock

from stayawake.utils import pace


class _Events:
    enabled = True

    def __init__(self):
        self.seen = []

    def plan(self, target, **work):
        self.seen.append(("plan", target, work))

    def progress(self, target, **counts):
        self.seen.append(("progress", target, counts))


class TheEstimate(unittest.TestCase):

    def test_more_work_takes_longer_and_more_workers_take_less(self):
        small = pace.estimate_seconds(100, 10**6, 0, 2)
        self.assertLess(small, pace.estimate_seconds(40_000, 10**6, 0, 2))
        self.assertLess(small, pace.estimate_seconds(100, 3 * 10**9, 0, 2))
        self.assertLess(small, pace.estimate_seconds(100, 10**6, 5_000, 2))
        self.assertLess(pace.estimate_seconds(40_000, 10**9, 0, 8), pace.estimate_seconds(40_000, 10**9, 0, 1))

    def test_the_budget_is_generous_and_never_short(self):
        self.assertEqual(pace.budget_seconds(1), pace.MINIMUM_BUDGET_SECONDS)
        self.assertEqual(pace.budget_seconds(100), 300)


class TheHeartbeat(unittest.TestCase):

    def test_a_run_says_how_far_it_has_come_while_it_works(self):
        events = _Events()
        with mock.patch.object(pace, "HEARTBEAT_SECONDS", 0.05):
            with pace.Pace(events) as running:
                running.begin("repo", "files", 10)
                running.advance(4)
                time.sleep(0.3)
        beats = [counts for kind, _target, counts in events.seen if kind == "progress"]
        self.assertTrue(beats)
        self.assertEqual(beats[-1], {"phase": "files", "done": 4, "total": 10})

    def test_a_phase_whose_progress_is_not_counted_says_so(self):
        events = _Events()
        running = pace.Pace(events)
        running.begin("repo", "history", 0, counted=False)
        running.beat()
        self.assertEqual(events.seen[-1][2], {"phase": "history", "done": None, "total": 0})


class TheDeadline(unittest.TestCase):

    def test_a_run_past_its_deadline_is_stopped(self):
        before = signal.getsignal(signal.SIGALRM)
        with self.assertRaises(pace.DeadlineReached):
            with pace.Pace(_Events(), deadline=0.2) as running:
                time.sleep(5)
        self.assertTrue(running.expired)
        self.assertIs(signal.getsignal(signal.SIGALRM), before)

    def test_a_run_inside_its_deadline_is_left_alone(self):
        with pace.Pace(_Events(), deadline=5) as running:
            time.sleep(0.1)
        self.assertFalse(running.expired)
        self.assertEqual(signal.getitimer(signal.ITIMER_REAL), (0.0, 0.0))


if __name__ == "__main__":
    unittest.main()
