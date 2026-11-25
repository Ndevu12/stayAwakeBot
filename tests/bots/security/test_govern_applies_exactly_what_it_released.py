#!/usr/bin/env python3
"""saw govern apply brings in exactly what its own prepare released, one run at a time per holding
folder, and names what happened in a code."""
from __future__ import annotations

import io
import json
import os
import signal
import subprocess
import sys
import time
from contextlib import redirect_stdout
from unittest import mock

from stayawake import cli
from stayawake.bots.security import govern, govern_status
from stayawake.utils import exitcodes, folderlock
from tests.support.gitrepo import GitSandbox

_SCAN = "stayawake.bots.security.govern._scan_arrived"


class GovernAppliesExactlyWhatItReleased(GitSandbox):

    def setUp(self):
        super().setUp()
        state = mock.patch.dict(os.environ, {"XDG_STATE_HOME": str(self.root / "state")})
        state.start()
        self.addCleanup(state.stop)
        self.repo = self.new_repo("open")
        self.write(self.repo, "keep.txt", "already\n")
        self.base = self.commit(self.repo, "start")
        for branch, text in (("next", "from next\n"), ("other", "from other\n")):
            self.git(self.repo, "checkout", "-q", "-b", branch, "main")
            self.write(self.repo, "arrived.txt", text)
            self.commit(self.repo, branch)
        self.git(self.repo, "checkout", "-q", "main")
        self.into = self.root / "holding"

    def _run(self, *args: str) -> tuple[int, dict]:
        out = io.StringIO()
        with redirect_stdout(out):
            code = cli.main(list(args))
        return code, json.loads(out.getvalue())

    def _prepare(self, branch: str) -> dict:
        code, body = self._run("govern", "prepare", "--json", "--repo", str(self.repo), "--into", str(self.into),
                               "--tool", "git", "--", "checkout", branch)
        self.assertEqual(code, exitcodes.CLEAN, body)
        return body

    def _apply(self, *extra: str) -> dict:
        return self._run("govern", "apply", "--json", "--repo", str(self.repo), "--into", str(self.into), *extra)[1]

    def test_an_apply_bound_to_its_prepare_brings_that_update_in(self):
        released = self._prepare("next")
        applied = self._apply("--expect", released["state_id"])
        self.assertEqual((applied["applied"], applied["outcome"]), (True, "brought_in"))
        self.assertEqual((self.repo / "arrived.txt").read_text(), "from next\n")

    def test_an_apply_whose_update_was_replaced_brings_nothing_in(self):
        first = self._prepare("next")
        self._prepare("other")
        applied = self._apply("--expect", first["state_id"])
        self.assertEqual((applied["applied"], applied["outcome"]), (False, "state_changed"))
        self.assertEqual(self.rev(self.repo), self.base)
        self.assertFalse((self.repo / "arrived.txt").exists())

    def test_each_way_an_apply_can_end_has_its_code(self):
        self.assertEqual(self._apply()["outcome"], "nothing_to_apply")
        with mock.patch(_SCAN, return_value=({"results": [{"verdict": "suspicious", "findings": []}]}, exitcodes.CLEAN, [])):
            self._prepare("next")
        self.assertEqual(self._apply()["outcome"], "held")
        self.write(self.repo, "arrived.txt", "mine\n")
        self._prepare("next")
        self.assertEqual(self._apply()["outcome"], "not_brought_in")

    def test_a_held_folder_makes_a_second_run_say_it_is_busy(self):
        self._prepare("next")
        with folderlock.held(self.into, wait=0), mock.patch.object(govern, "_HOLD_WAIT_SECONDS", 0.2):
            applied = self._apply()
        self.assertEqual((applied["applied"], applied["outcome"]), (False, "busy"))
        self.assertEqual(self._apply()["outcome"], "brought_in")

    def test_a_run_that_dies_leaves_no_hold_behind(self):
        holder = subprocess.Popen([sys.executable, "-c",
                                   "import sys, time; from pathlib import Path; from stayawake.utils import folderlock\n"
                                   "with folderlock.held(Path(sys.argv[1]), wait=5):\n print('held', flush=True); time.sleep(60)",
                                   str(self.into)], stdout=subprocess.PIPE, text=True,
                                  env={**os.environ, "PYTHONPATH": os.pathsep.join(sys.path)})
        self.assertEqual(holder.stdout.readline().strip(), "held")
        holder.send_signal(signal.SIGKILL)
        holder.wait()
        started = time.monotonic()
        with folderlock.held(self.into, wait=5):
            self.assertLess(time.monotonic() - started, 1)

    def test_an_interrupted_apply_is_reported_where_the_folder_is(self):
        released = self._prepare("next")
        state = json.loads((self.into / "state.json").read_text())
        govern_status.write(self.repo, "checking", step="applying the checked update",
                            applying={"base": state["base"], "commit": state["commit"], "paths": state["paths"]})
        self.assertEqual(govern.verdict(str(self.repo))[0]["interrupted"], {"matches": "base"})
        self.write(self.repo, "arrived.txt", "half written\n")
        self.assertEqual(govern.verdict(str(self.repo))[0]["interrupted"], {"matches": "neither"})
        applied = self._apply("--expect", released["state_id"])
        self.assertEqual((applied["outcome"], applied["matches"]), ("folder_may_have_changed", "neither"))
        self.assertNotIn("interrupted", govern.verdict(str(self.repo))[0])
        (self.repo / "arrived.txt").unlink()
        self.assertEqual(self._apply("--expect", released["state_id"])["outcome"], "brought_in")
