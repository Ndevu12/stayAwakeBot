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


if __name__ == "__main__":
    unittest.main()
