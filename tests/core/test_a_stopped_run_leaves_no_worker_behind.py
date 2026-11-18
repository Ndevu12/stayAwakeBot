#!/usr/bin/env python3
"""A run stopped from outside leaves no worker behind, and lets go of its caller's output."""
from __future__ import annotations

import os
import select
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
_POOL = """
import time
from stayawake.utils import parallel

if __name__ == "__main__":
    parallel.run_ordered(time.sleep, [60, 60, 60], jobs=3, on_start=lambda i, item: print("started", flush=True))
"""


def _children(pid: int) -> set[int]:
    listed = subprocess.run(["pgrep", "-P", str(pid)], capture_output=True, text=True).stdout
    return {int(line) for line in listed.split()}


def _alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


@unittest.skipUnless(os.name == "posix", "needs POSIX signals")
class AStoppedRun(unittest.TestCase):

    def _start(self) -> subprocess.Popen:
        script = Path(tempfile.mkdtemp()) / "pool.py"
        script.write_text(_POOL)
        run = subprocess.Popen([sys.executable, str(script)], stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                               env={**os.environ, "PYTHONPATH": str(REPO_ROOT / "src")})
        self.addCleanup(lambda: run.poll() is None and run.kill())
        deadline = time.monotonic() + 60
        while time.monotonic() < deadline and b"started" not in (run.stdout.readline() or b"started"):
            pass
        self.workers = _children(run.pid)
        self.addCleanup(lambda: [os.kill(pid, signal.SIGKILL) for pid in self.workers if _alive(pid)])
        self.assertTrue(self.workers, "the run started no workers")
        return run

    def _output_closes(self, run: subprocess.Popen, within: float) -> bool:
        deadline = time.monotonic() + within
        while time.monotonic() < deadline:
            ready, _, _ = select.select([run.stdout], [], [], 0.2)
            if ready and not os.read(run.stdout.fileno(), 65536):
                return True
        return False

    def _workers_end(self, within: float) -> bool:
        deadline = time.monotonic() + within
        while time.monotonic() < deadline:
            if not any(_alive(pid) for pid in self.workers):
                return True
            time.sleep(0.2)
        return False

    def test_sigterm_stops_the_workers_and_the_output_closes(self):
        run = self._start()
        run.send_signal(signal.SIGTERM)
        self.assertIsNotNone(run.wait(timeout=15))
        self.assertTrue(self._workers_end(10), "a worker outlived the run")
        self.assertTrue(self._output_closes(run, 5), "the caller's output stayed open")

    def test_workers_end_when_the_run_is_killed_outright(self):
        run = self._start()
        run.send_signal(signal.SIGKILL)
        run.wait(timeout=15)
        self.assertTrue(self._workers_end(10), "a worker outlived a killed run")
        self.assertTrue(self._output_closes(run, 5), "the caller's output stayed open")


if __name__ == "__main__":
    unittest.main()
