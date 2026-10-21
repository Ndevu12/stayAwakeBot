#!/usr/bin/env python3
"""CI's parallel jobs together run the whole suite: each module in one share, and a share missing,
repeated or run against a different suite is reported."""
from __future__ import annotations

import contextlib
import io
import json
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from tests.support import shard

_SIZES = {"a": 40, "b": 30, "c": 20, "d": 10, "e": 5, "f": 1}
_SUITE = ["a.T.test_1", "a.T.test_2", "b.T.test_1", "c.T.test_1"]


class TestEveryModuleIsInOneShare(unittest.TestCase):
    def test_the_shares_hold_every_module_once(self):
        for shares in (1, 2, 3, 4, 7):
            with self.subTest(shares=shares):
                groups = shard.split(_SIZES, shares)
                self.assertEqual(len(groups), shares)
                placed = [module for group in groups for module in group]
                self.assertEqual(sorted(placed), sorted(_SIZES))

    def test_the_shares_are_near_equal(self):
        totals = sorted(sum(_SIZES[m] for m in group) for group in shard.split(_SIZES, 3))
        self.assertEqual(totals, [31, 35, 40])

    def test_every_job_draws_the_same_shares(self):
        reordered = dict(reversed(list(_SIZES.items())))
        self.assertEqual(shard.split(_SIZES, 3), shard.split(reordered, 3))


class TestTheSharesAreCheckedTogether(unittest.TestCase):
    def setUp(self):
        self.dir = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.dir, ignore_errors=True)

    def _record(self, share, ran, shares=2, suite=_SUITE):
        path = self.dir / f"share-{share}-{len(list(self.dir.iterdir()))}.json"
        path.write_text(json.dumps({"share": share, "shares": shares, "suite": sorted(suite),
                                    "ran": sorted(ran)}))
        return path

    def test_shares_that_ran_every_test_once_pass(self):
        records = [self._record(1, _SUITE[:2]), self._record(2, _SUITE[2:])]
        self.assertEqual(shard.verify(records), [])

    def test_a_share_that_never_reported_is_named(self):
        problems = shard.verify([self._record(1, _SUITE[:2])])
        self.assertTrue(any("expected [1, 2]" in p for p in problems), problems)
        self.assertTrue(any("never ran" in p for p in problems), problems)

    def test_a_test_run_by_two_shares_is_named(self):
        records = [self._record(1, _SUITE[:3]), self._record(2, _SUITE[2:])]
        self.assertTrue(any("ran more than once" in p for p in shard.verify(records)))

    def test_the_same_share_run_twice_is_named(self):
        records = [self._record(1, _SUITE[:2]), self._record(1, _SUITE[:2])]
        problems = shard.verify(records)
        self.assertTrue(any("shares recorded [1, 1]" in p for p in problems), problems)

    def test_shares_that_discovered_different_suites_are_named(self):
        records = [self._record(1, _SUITE[:2]), self._record(2, _SUITE[2:], suite=_SUITE[1:])]
        self.assertIn("the shares discovered different suites", shard.verify(records))

    def test_shares_that_disagree_on_their_number_are_named(self):
        records = [self._record(1, _SUITE[:2]), self._record(2, _SUITE[2:], shares=3)]
        self.assertTrue(shard.verify(records))

    def test_no_record_is_a_problem(self):
        self.assertEqual(shard.verify([]), ["no share wrote a record"])

    def test_what_each_share_runs_is_what_the_check_reads(self):
        ran = []
        cases = [type("T", (unittest.TestCase,), {"__module__": module,
                                                  "test_it": lambda self: ran.append(self.id())})
                 ("test_it") for module in ("first", "second", "third")]
        records = [self.dir / "1.json", self.dir / "2.json"]
        with mock.patch.object(shard, "_discovered", return_value=cases), \
             contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            codes = [shard.run(share, 2, record) for share, record in enumerate(records, 1)]
        self.assertEqual(codes, [0, 0])
        self.assertEqual(sorted(ran), sorted(case.id() for case in cases))
        self.assertEqual(shard.verify(records), [])


if __name__ == "__main__":
    unittest.main()
