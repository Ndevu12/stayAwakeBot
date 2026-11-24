#!/usr/bin/env python3
"""Ctrl-C never reaches a worker that is still starting."""
import os
import subprocess
import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]


@unittest.skipUnless(os.name == "posix", "needs POSIX process groups")
class CtrlCNeverReachesAStartingWorker(unittest.TestCase):

    def test_workers_started_under_repeated_ctrl_c_finish_the_work_quietly(self):
        done = subprocess.run([sys.executable, "-m", "tests.support.ctrl_c_while_workers_start"], cwd=REPO_ROOT,
                              capture_output=True, text=True, timeout=120, start_new_session=True,
                              env={**os.environ, "PYTHONPATH": str(REPO_ROOT / "src")})
        self.assertNotIn("Fatal Python error", done.stderr)
        self.assertNotIn("Traceback", done.stderr)
        self.assertEqual(done.stdout.strip(), str(sum(range(1, 65))))
        self.assertEqual(done.returncode, 0)


if __name__ == "__main__":
    unittest.main()
