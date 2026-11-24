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

    def _run(self, *args: str) -> subprocess.CompletedProcess:
        return subprocess.run([sys.executable, "-m", "tests.support.ctrl_c_while_workers_start", *args], cwd=REPO_ROOT,
                              capture_output=True, text=True, timeout=120, start_new_session=True,
                              env={**os.environ, "PYTHONPATH": str(REPO_ROOT / "src")})

    def test_workers_started_under_repeated_ctrl_c_finish_the_work_quietly(self):
        done = self._run()
        self.assertNotIn("Fatal Python error", done.stderr)
        self.assertNotIn("Traceback", done.stderr)
        self.assertEqual(done.stdout.strip(), str(sum(range(1, 65))))
        self.assertEqual(done.returncode, 0)

    def test_a_ctrl_c_in_the_middle_of_starting_a_worker_stops_the_run_quietly(self):
        done = self._run("mid-launch")
        self.assertNotIn("Traceback", done.stderr)
        self.assertEqual(done.stdout.strip(), "stopped")
        self.assertEqual(done.returncode, 0)


if __name__ == "__main__":
    unittest.main()
