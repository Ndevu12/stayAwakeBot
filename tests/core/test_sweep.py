#!/usr/bin/env python3
"""The shared sweep seam (#1327): `utils.parallel.resolve_jobs` (the one worker-count policy) and
`utils.sweep.run_sweep` (the board + ordered, fail-closed execution every repo-sweeping command
uses). These pin the properties `scan`/`fix`/`guard` all lean on."""
from __future__ import annotations

import io
import os
import unittest

from stayawake.utils import parallel
from stayawake.utils.sweep import run_sweep


class TestResolveJobs(unittest.TestCase):
    def test_single_item_is_always_one(self):
        # The inline fast-path: one item never spins up a pool, whatever was requested.
        self.assertEqual(parallel.resolve_jobs(None, 1), 1)
        self.assertEqual(parallel.resolve_jobs(8, 1), 1)
        self.assertEqual(parallel.resolve_jobs(None, 0), 1)

    def test_explicit_one_forces_sequential(self):
        self.assertEqual(parallel.resolve_jobs(1, 10), 1)

    def test_auto_is_min_budget_and_count(self):
        # AUTO no longer means every core: it means the CPU budget, which leaves the machine one and
        # honours affinity/cgroup confinement. The other half of the old contract is unchanged —
        # never more workers than there are items.
        budget = parallel.cpu_budget()
        self.assertEqual(parallel.resolve_jobs(None, 3), min(budget, 3))
        self.assertEqual(parallel.resolve_jobs(None, 10_000), budget)
        self.assertLess(budget, os.cpu_count() or 1) if (os.cpu_count() or 1) > 1 else None

    def test_explicit_caps_at_count(self):
        self.assertEqual(parallel.resolve_jobs(2, 10), 2)
        self.assertEqual(parallel.resolve_jobs(50, 4), 4)     # never more workers than items


def _describe(o):
    return "[ok      ]", f"={o.value}"


class TestRunSweep(unittest.TestCase):
    def _run(self, fn, items, *, jobs, backend=parallel.THREAD):
        labels = [f"item-{i}" for i in range(len(items))]
        return run_sweep(fn, items, jobs=jobs, backend=backend, labels=labels,
                         describe=_describe, progress_on=False, out=io.StringIO())

    def test_results_in_submission_order_regardless_of_completion(self):
        # Later items finish FIRST (descending sleeps), yet results come back in submission order.
        import time

        def work(x):
            time.sleep((10 - x) * 0.005)
            return x * 10

        outcomes = self._run(work, list(range(10)), jobs=4)
        self.assertEqual([o.value for o in outcomes], [x * 10 for x in range(10)])
        self.assertEqual([o.index for o in outcomes], list(range(10)))

    def test_seq_equals_parallel(self):
        work = lambda x: x * x
        a = [o.value for o in self._run(work, list(range(12)), jobs=1)]
        b = [o.value for o in self._run(work, list(range(12)), jobs=6)]
        self.assertEqual(a, b, "the sweep must be identical at -j1 and -j6")

    def test_one_failure_is_isolated_and_fail_closed(self):
        # One item raising becomes THAT item's Outcome.error; every other item still completes and
        # the whole run never raises — so a caller can fail closed on the error without losing peers.
        def work(x):
            if x == 3:
                raise RuntimeError("boom")
            return x

        outcomes = self._run(work, list(range(6)), jobs=4)
        self.assertEqual(len(outcomes), 6)
        self.assertIsNotNone(outcomes[3].error)
        self.assertIn("boom", outcomes[3].error)
        self.assertEqual([o.value for o in outcomes if o.error is None], [0, 1, 2, 4, 5])

    def test_describe_only_runs_for_successful_items(self):
        seen = []

        def describe(o):
            seen.append(o.index)
            return "[ok      ]", ""

        def work(x):
            if x == 1:
                raise ValueError("no")
            return x

        run_sweep(work, [0, 1, 2], jobs=2, backend=parallel.THREAD,
                  labels=["a", "b", "c"], describe=describe, progress_on=False, out=io.StringIO())
        self.assertEqual(sorted(seen), [0, 2])          # index 1 errored → describe skipped for it

    def test_empty_items(self):
        self.assertEqual(self._run(lambda x: x, [], jobs=4), [])

    def test_describe_block_renders_under_the_header(self):
        # A command can render its OWN full result (a multi-line block) as the completion output —
        # printed under the `[i/N] tag label` header, at completion, not in a separate pass.
        out = io.StringIO()
        run_sweep(lambda x: x, ["alpha", "beta"], jobs=2, backend=parallel.THREAD,
                  labels=["repo-a", "repo-b"], progress_on=False, out=out,
                  describe=lambda o: ("[ok      ]", "", f"    detail for {o.value}"))
        text = out.getvalue()
        # Each repo's block appears, and follows a header line naming that repo.
        for repo, val in (("repo-a", "alpha"), ("repo-b", "beta")):
            self.assertIn(f"detail for {val}", text)
            hdr = text.index(repo)
            self.assertLess(hdr, text.index(f"detail for {val}"), "block must follow its header")
        # Bare "" detail → no empty "()" on the header.
        self.assertNotIn("()", text)


if __name__ == "__main__":
    unittest.main()
