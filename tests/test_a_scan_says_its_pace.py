#!/usr/bin/env python3
"""A scan says what it will read and how long that should take, and stops itself at a deadline."""
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
import uuid
from pathlib import Path

from stayawake.bots.security.service.run import DEADLINE_REASON

REPO_ROOT = Path(__file__).resolve().parents[1]
_PLAN_FIELDS = {"event", "target", "files", "bytes", "commits", "workers", "estimate_seconds", "budget_seconds"}


class AScanSaysItsPace(unittest.TestCase):

    def _tree(self, files: int) -> Path:
        tree = Path(tempfile.mkdtemp(prefix="pace-"))
        for index in range(files):
            (tree / f"f{index}.js").write_text(f"module.exports = function f{index}(a) {{ return a + {index}; }};\n")
        return tree

    def _scan(self, tree: Path, *extra: str):
        self.marker = f"ignore:::pace_{uuid.uuid4().hex}"
        done = subprocess.run([sys.executable, "-W", self.marker, "-m", "stayawake", "scan", str(tree), "--no-stream", "--progress",
                               "jsonl", "--json", *extra], capture_output=True, text=True,
                              env={**os.environ, "PYTHONPATH": str(REPO_ROOT / "src")}, timeout=300)
        events = [json.loads(line) for line in done.stderr.splitlines() if line.startswith("{")]
        return done.returncode, events, json.loads(done.stdout)

    def test_the_plan_comes_before_the_scan_and_carries_the_work(self):
        code, events, report = self._scan(self._tree(40))
        self.assertEqual(code, 0)
        plans = [event for event in events if event["event"] == "plan"]
        self.assertEqual(len(plans), 1)
        self.assertEqual(set(plans[0]), _PLAN_FIELDS)
        self.assertEqual(plans[0]["files"], 40)
        self.assertGreaterEqual(plans[0]["budget_seconds"], plans[0]["estimate_seconds"])
        self.assertLess(events.index(plans[0]), [e["event"] for e in events].index("done"))
        self.assertFalse(report["any_error"])

    def test_a_scan_that_reaches_its_deadline_reports_what_it_did_not_finish(self):
        code, events, report = self._scan(self._tree(1200), "--deadline", "0.5")
        self.assertEqual(code, 2)
        self.assertTrue(report["any_error"])
        self.assertEqual([result["error"] for result in report["results"]], [DEADLINE_REASON])
        leftover = subprocess.run(["pgrep", "-f", self.marker], capture_output=True, text=True).stdout
        self.assertEqual(leftover.split(), [])


if __name__ == "__main__":
    unittest.main()
