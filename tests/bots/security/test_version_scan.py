#!/usr/bin/env python3
"""Stored versions are scanned in batches that hold each path once."""
from __future__ import annotations

import random
import unittest
from types import SimpleNamespace
from unittest import mock

from stayawake.bots.security import version_scan


def _first_fit(queue: list) -> list[list]:
    out: list[list] = []
    paths: list[set[str]] = []
    for entry in queue:
        for batch, held in zip(out, paths):
            if entry.path not in held and len(batch) < version_scan.PATHS_PER_BATCH:
                batch.append(entry)
                held.add(entry.path)
                break
        else:
            out.append([entry])
            paths.append({entry.path})
    return out


class TestScanBatch(unittest.TestCase):

    def _scan(self, error):
        class Target:
            def __init__(self, *args):
                self.read_errors, self.read_in_part, self.read_ahead = [], (), {}

        batch = [SimpleNamespace(path=p, oid=p, link=False) for p in ("a.js", "b.js", "c.js")]
        result = SimpleNamespace(error=error, findings=[SimpleNamespace(path="a.js")])
        with mock.patch.object(version_scan, "PushedTarget", Target), \
                mock.patch.object(version_scan, "scan_target", return_value=result):
            return version_scan.scan_batch("/repo", "repo", batch, [], [], [], None)

    def test_files_a_cut_short_scan_did_not_report_on_are_unread(self):
        self.assertEqual({"b.js", "c.js"}, self._scan("cut short").unread)

    def test_a_finished_scan_reads_every_file(self):
        self.assertEqual(set(), self._scan(None).unread)


class TestBatches(unittest.TestCase):

    def test_batches_match_the_first_fit_split(self):
        rng = random.Random(315)
        for _round in range(300):
            paths = [f"p{i}" for i in range(rng.randint(1, 90))]
            queue = [SimpleNamespace(path=rng.choice(paths), n=n)
                     for n in range(rng.randint(0, 700))]
            self.assertEqual([[e.n for e in b] for b in _first_fit(queue)],
                             [[e.n for e in b] for b in version_scan.batches(queue)])

    def test_many_versions_are_split_quickly(self):
        import time
        queue = [SimpleNamespace(path=f"p{i % 300}") for i in range(60_000)]
        started = time.monotonic()
        version_scan.batches(queue)
        self.assertLess(time.monotonic() - started, 5.0)


if __name__ == "__main__":
    unittest.main()
