#!/usr/bin/env python3
"""utils.parallel — the ordered, error-isolated concurrency seam behind `saw scan -j` (#1205).

The worker functions are module-level because the PROCESS backend uses a spawn context, which
re-imports this module in each child and requires picklable, importable callables.
"""
from __future__ import annotations

import multiprocessing as mp
import os
import signal
import threading
import time
import unittest

from stayawake.utils import parallel


def _square(x):
    return x * x


def _sleep_long(x):
    time.sleep(5)          # a long in-flight task, so a prompt Ctrl-C is visibly < this
    return x


def _boom(x):
    if x == 3:
        raise ValueError(f"boom-{x}")
    return x * 10


def _die_on_two(x):
    if x == 2:
        os._exit(1)          # abrupt worker death → BrokenProcessPool
    return x


def _slow_first(x):
    # Item 0 sleeps so completions arrive OUT of submission order; results must still be ordered.
    import time
    if x == 0:
        time.sleep(0.2)
    return x * x


class TestOrdering(unittest.TestCase):
    def test_process_backend_preserves_submission_order(self):
        out = parallel.run_ordered(_square, list(range(8)), jobs=4, backend=parallel.PROCESS)
        self.assertEqual([o.value for o in out], [x * x for x in range(8)])
        self.assertEqual([o.index for o in out], list(range(8)))

    def test_order_holds_when_completions_arrive_out_of_order(self):
        out = parallel.run_ordered(_slow_first, list(range(6)), jobs=4, backend=parallel.PROCESS)
        self.assertEqual([o.value for o in out], [x * x for x in range(6)])

    def test_thread_backend_preserves_order(self):
        out = parallel.run_ordered(_square, list(range(6)), jobs=3, backend=parallel.THREAD)
        self.assertEqual([o.value for o in out], [x * x for x in range(6)])


class TestIsolation(unittest.TestCase):
    def test_one_item_failure_does_not_abort_the_rest(self):
        out = parallel.run_ordered(_boom, list(range(5)), jobs=3, backend=parallel.PROCESS)
        self.assertEqual(len(out), 5)
        self.assertIsNotNone(out[3].error)
        self.assertIn("boom-3", out[3].error)
        self.assertEqual(out[0].value, 0)
        self.assertEqual(out[4].value, 40)

    def test_worker_death_is_fail_closed_not_a_crash_or_silent_drop(self):
        out = parallel.run_ordered(_die_on_two, list(range(5)), jobs=3, backend=parallel.PROCESS)
        self.assertEqual(len(out), 5)                       # every item accounted for
        self.assertTrue(any(o.error for o in out))          # the death surfaced as an error
        # No outcome is left as a silent None-value-None-error hole.
        for o in out:
            self.assertTrue(o.error is not None or o.value is not None)

    def test_inline_path_isolates_errors_too(self):
        out = parallel.run_ordered(_boom, [1, 3, 4], jobs=1)
        self.assertEqual(out[0].value, 10)
        self.assertIn("boom-3", out[1].error)
        self.assertEqual(out[2].value, 40)


class TestCallbacksAndDefaults(unittest.TestCase):
    def test_callbacks_fire_on_the_calling_thread(self):
        caller = threading.get_ident()
        seen_threads = []
        starts, dones = [], []

        def on_start(i, item):
            seen_threads.append(threading.get_ident())
            starts.append(i)

        def on_done(o):
            seen_threads.append(threading.get_ident())
            dones.append(o.index)

        parallel.run_ordered(_square, list(range(6)), jobs=3, backend=parallel.THREAD,
                             on_start=on_start, on_done=on_done)
        self.assertEqual(sorted(starts), list(range(6)))
        self.assertEqual(sorted(dones), list(range(6)))
        self.assertTrue(all(t == caller for t in seen_threads))   # single-writer guarantee

    def test_empty_input(self):
        self.assertEqual(parallel.run_ordered(_square, [], jobs=4), [])

    def test_single_item_runs_and_is_correct(self):
        out = parallel.run_ordered(_square, [7], jobs=4, backend=parallel.PROCESS)
        self.assertEqual([o.value for o in out], [49])

    def test_unknown_backend_rejected(self):
        with self.assertRaises(ValueError):
            parallel.run_ordered(_square, [1, 2], jobs=2, backend="magic")


class TestInterrupt(unittest.TestCase):
    @unittest.skipUnless(os.name == "posix", "relies on POSIX SIGINT semantics")
    def test_ctrl_c_is_prompt_and_leaves_no_orphaned_workers(self):
        # Regression for the adversarial finding: Ctrl-C used to freeze the CLI for the whole
        # in-flight task duration (executor atexit-join) and orphan workers under a parent-only
        # signal. The interrupt must propagate quickly and terminate every worker.
        def fire():
            time.sleep(0.5)
            os.kill(os.getpid(), signal.SIGINT)     # parent-only signal (the hard case)

        threading.Thread(target=fire, daemon=True).start()
        t0 = time.perf_counter()
        with self.assertRaises(KeyboardInterrupt):
            parallel.run_ordered(_sleep_long, list(range(6)), jobs=3, backend=parallel.PROCESS)
        elapsed = time.perf_counter() - t0
        self.assertLess(elapsed, 3.0, "Ctrl-C must not wait for the 5s in-flight tasks")
        time.sleep(0.3)
        self.assertEqual(mp.active_children(), [], "no orphaned worker processes after Ctrl-C")


if __name__ == "__main__":
    unittest.main()
