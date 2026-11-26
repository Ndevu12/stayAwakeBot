#!/usr/bin/env python3
"""Ctrl-C ends saw with one line and no Python traceback, at any moment of a run."""
from __future__ import annotations

import os
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
_SAW_STARTS = b"saw is starting"
_START_SAW = ("import sys; sys.stderr.write('saw is starting\\n'); sys.stderr.flush(); "
              "from stayawake.cli import main; sys.exit(main())")
_FILES_TO_OUTLAST_THE_INTERRUPT = 20_000


@unittest.skipUnless(os.name == "posix", "needs POSIX process groups")
class CtrlCEndsSawQuietly(unittest.TestCase):

    def setUp(self):
        self.tree = Path(tempfile.mkdtemp(prefix="ctrl-c-"))
        for index in range(_FILES_TO_OUTLAST_THE_INTERRUPT):
            (self.tree / f"f{index}.js").write_text(f"module.exports = function f{index}(a) {{ return a + {index}; }};\n")

    def _interrupted(self, *, after_line: bytes | None, after_seconds: float) -> tuple[int, str]:
        run = subprocess.Popen([sys.executable, "-c", _START_SAW, "scan", str(self.tree), "--no-stream",
                                "--progress", "jsonl"], stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                               env={**os.environ, "PYTHONPATH": str(REPO_ROOT / "src")}, start_new_session=True)
        self.addCleanup(lambda: run.poll() is None and run.kill())
        seen = b""
        if after_line is not None:
            deadline = time.monotonic() + 60
            while time.monotonic() < deadline and after_line not in seen:
                line = run.stderr.readline()
                if not line:
                    break
                seen += line
        time.sleep(after_seconds)
        try:
            os.killpg(run.pid, signal.SIGINT)
        except (ProcessLookupError, PermissionError):
            pass
        out, err = run.communicate(timeout=60)
        return run.returncode, (seen + out + err).decode(errors="replace")

    def test_a_scan_with_workers_running_ends_with_one_line(self):
        code, printed = self._interrupted(after_line=b"workers", after_seconds=0.2)
        self.assertNotIn("Traceback", printed)
        self.assertIn("saw: stopped.", printed)
        self.assertEqual(code, -signal.SIGINT)
        time.sleep(1)
        leftover = subprocess.run(["pgrep", "-f", str(self.tree)], capture_output=True, text=True).stdout.split()
        self.assertEqual(leftover, [])

    def test_a_ctrl_c_while_saw_is_still_starting_shows_no_traceback(self):
        for moment in (0.05, 0.2, 0.4):
            with self.subTest(moment=moment):
                _code, printed = self._interrupted(after_line=_SAW_STARTS, after_seconds=moment)
                self.assertNotIn("Traceback", printed)

class ACtrlCPythonSwallowsIsDeliveredAgain(unittest.TestCase):

    def test_a_ctrl_c_raised_inside_a_callback_still_stops_saw(self):
        swallowed_then_waited = (
            "import time, weakref\n"
            "import stayawake.cli\n"
            "class Held:\n"
            "    pass\n"
            "def interrupted(_ref):\n"
            "    raise KeyboardInterrupt\n"
            "def wait():\n"
            "    deadline = time.monotonic() + 10\n"
            "    while time.monotonic() < deadline:\n"
            "        pass\n"
            "def run():\n"
            "    held = Held()\n"
            "    watcher = weakref.ref(held, interrupted)\n"
            "    try:\n"
            "        del held\n"
            "        wait()\n"
            "        print('not stopped', flush=True)\n"
            "    except KeyboardInterrupt:\n"
            "        print('stopped', flush=True)\n"
            "run()\n")
        run = subprocess.run([sys.executable, "-c", swallowed_then_waited], capture_output=True, text=True,
                             timeout=60, env={**os.environ, "PYTHONPATH": str(REPO_ROOT / "src")})
        self.assertEqual(run.stdout.strip(), "stopped", run.stderr)
        self.assertNotIn("Exception ignored", run.stderr)

if __name__ == "__main__":
    unittest.main()
