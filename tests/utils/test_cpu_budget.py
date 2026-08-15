#!/usr/bin/env python3
"""A scan must leave the machine usable, and must not size itself from cores it may not use.

`os.cpu_count()` reports the HOST's cores even when the process is confined, so a two-CPU container
on a large build host sized the pool from the host and oversubscribed by an order of magnitude. And
taking every core makes an unresponsive workstation indistinguishable from a scanner that hung —
which matters here, because the input being read is hostile by assumption.
"""
from __future__ import annotations

import unittest
from unittest import mock

from stayawake.utils import parallel


class TestTheBudgetLeavesTheMachineACore(unittest.TestCase):
    def test_it_reserves_one_cpu(self):
        for allowed, expected in ((16, 15), (8, 7), (4, 3), (2, 1), (1, 1)):
            with self.subTest(allowed=allowed):
                with mock.patch.object(parallel, "_allowed_cpus", return_value=allowed):
                    self.assertEqual(parallel.cpu_budget(), expected)

    def test_it_never_returns_zero(self):
        with mock.patch.object(parallel, "_allowed_cpus", return_value=1):
            self.assertGreaterEqual(parallel.cpu_budget(), 1)

    def test_auto_uses_the_budget_and_an_explicit_request_is_the_operators_call(self):
        with mock.patch.object(parallel, "cpu_budget", return_value=3):
            self.assertEqual(parallel.resolve_jobs(None, 100), 3)   # AUTO is bounded
            self.assertEqual(parallel.resolve_jobs(8, 100), 8)      # explicit is honoured
            self.assertEqual(parallel.resolve_jobs(1, 100), 1)      # and 1 stays sequential

    def test_a_single_item_sweep_never_builds_a_pool(self):
        self.assertEqual(parallel.resolve_jobs(None, 1), 1)


class TestConfinementNarrowsTheBudget(unittest.TestCase):
    """Simulated, because this machine is not confined — the kernel files are read as data, so the
    parsing can be exercised without a container."""

    def _with_cgroup(self, files: dict[str, str]):
        real_is_file, real_read = parallel.Path.is_file, parallel.Path.read_text

        def is_file(self):
            return str(self) in files or real_is_file(self)

        def read_text(self, *a, **kw):
            return files[str(self)] if str(self) in files else real_read(self, *a, **kw)

        return mock.patch.multiple(parallel.Path, is_file=is_file, read_text=read_text)

    def test_cgroup_v2_quota_is_honoured(self):
        with self._with_cgroup({"/sys/fs/cgroup/cpu.max": "200000 100000"}):
            self.assertEqual(parallel._cgroup_cpu_quota(), 2)

    def test_cgroup_v2_without_a_quota_reports_none(self):
        with self._with_cgroup({"/sys/fs/cgroup/cpu.max": "max 100000"}):
            self.assertIsNone(parallel._cgroup_cpu_quota())

    def test_cgroup_v1_quota_is_honoured(self):
        with self._with_cgroup({"/sys/fs/cgroup/cpu/cpu.cfs_quota_us": "400000",
                                "/sys/fs/cgroup/cpu/cpu.cfs_period_us": "100000"}):
            self.assertEqual(parallel._cgroup_cpu_quota(), 4)

    def test_an_unreadable_or_malformed_quota_does_not_raise(self):
        for content in ("", "garbage", "100000"):
            with self.subTest(content=content), self._with_cgroup({"/sys/fs/cgroup/cpu.max": content}):
                self.assertIsNone(parallel._cgroup_cpu_quota())

    def test_a_quota_smaller_than_the_core_count_wins(self):
        with mock.patch.object(parallel.os, "cpu_count", return_value=64), \
             mock.patch.object(parallel, "_cgroup_cpu_quota", return_value=2):
            self.assertEqual(parallel._allowed_cpus(), 2)

    def test_a_quota_never_drops_below_one(self):
        with self._with_cgroup({"/sys/fs/cgroup/cpu.max": "1000 100000"}):
            self.assertEqual(parallel._cgroup_cpu_quota(), 1)


class TestItBehavesOnEveryPlatformItRunsOn(unittest.TestCase):
    """Probes are feature-detected, not platform-branched, so a missing one narrows nothing rather
    than raising. Verified across the capability combinations rather than assumed from `sys.platform`,
    since what matters is which probe EXISTS, not what the OS is called."""

    def _budget(self, cores, process_cpu, affinity, quota):
        saved_pcc = getattr(parallel.os, "process_cpu_count", None)
        saved_aff = getattr(parallel.os, "sched_getaffinity", None)
        try:
            if process_cpu is None:
                if saved_pcc:
                    del parallel.os.process_cpu_count
            else:
                parallel.os.process_cpu_count = lambda: process_cpu
            if affinity is None:
                if saved_aff:
                    del parallel.os.sched_getaffinity
            else:
                parallel.os.sched_getaffinity = lambda _pid: set(range(affinity))
            with mock.patch.object(parallel.os, "cpu_count", return_value=cores), \
                 mock.patch.object(parallel, "_cgroup_cpu_quota", return_value=quota):
                return parallel.cpu_budget()
        finally:
            if saved_pcc:
                parallel.os.process_cpu_count = saved_pcc
            elif hasattr(parallel.os, "process_cpu_count"):
                del parallel.os.process_cpu_count
            if saved_aff:
                parallel.os.sched_getaffinity = saved_aff
            elif hasattr(parallel.os, "sched_getaffinity"):
                del parallel.os.sched_getaffinity

    def test_every_capability_combination(self):
        cases = {
            "no probes at all (macOS, older Windows)": ((16, None, None, None), 15),
            "affinity only (older Linux)":             ((16, None, 4, None), 3),
            "process_cpu_count only (Windows 3.13+)": ((16, 4, None, None), 3),
            "quota only (container)":                  ((16, None, None, 2), 1),
            "affinity and quota disagree":             ((16, 8, 8, 2), 1),
            "single core":                             ((1, 1, 1, None), 1),
        }
        for name, (args, expected) in cases.items():
            with self.subTest(environment=name):
                self.assertEqual(self._budget(*args), expected)

    def test_a_missing_cgroup_tree_is_not_an_error(self):
        # On a platform with no such path, reading it must return "no quota", never raise.
        self.assertIsNone(parallel._cgroup_cpu_quota())


if __name__ == "__main__":
    unittest.main()
