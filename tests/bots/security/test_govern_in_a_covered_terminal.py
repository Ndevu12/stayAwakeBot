#!/usr/bin/env python3
"""In a terminal saw's stand-in covers, saw's own git is never governed, so an update is checked."""
from __future__ import annotations

import os
import subprocess
from pathlib import Path
from unittest import mock

from stayawake.bots.security import govern
from stayawake.utils import env as saw_env
from tests.bots.security.test_govern_replays_a_tracking_checkout import _TrackingCheckout


class ACoveredTerminal(_TrackingCheckout):

    def setUp(self):
        super().setUp()
        self.governed = self.root / "governed.log"
        standin = self.root / "standin-bin"
        standin.mkdir()
        exec_path = subprocess.run(["git", "--exec-path"], capture_output=True, text=True, check=True).stdout
        real_git = Path(exec_path.strip()) / "git"
        (standin / "git").write_text(
            "#!/bin/sh\n"
            'if [ -n "$SAW_GOVERN_SYSTEM$SAW_GOVERN_HOLDING" ]; then\n'
            f'  echo "$@" >> "{self.governed}"; exit 2\n'
            "fi\n"
            f'exec "{real_git}" "$@"\n')
        (standin / "git").chmod(0o755)
        self.path = f"{standin}{os.pathsep}{os.environ['PATH']}"

    def _covered(self, variable: str):
        return mock.patch.dict(os.environ, {"PATH": self.path, variable: "1"})

    def test_a_pull_is_checked_and_applied_in_a_covered_terminal(self):
        for variable in saw_env.GOVERN_ACTIVATION:
            with self.subTest(variable=variable):
                with self._covered(variable):
                    answer, _code = govern.prepare(str(self.open), str(self.into), "git", ["pull"])
                    applied = govern.apply(str(self.open), str(self.into))[0]
                self.assertIn("scan", answer, answer)
                self.assertEqual(applied, {"applied": True, "outcome": "brought_in"})
                self.assertTrue((self.open / "new.txt").exists())
                self.assertFalse(self.governed.exists(), self.governed.exists() and self.governed.read_text())
                self.git(self.open, "reset", "-q", "--hard", "HEAD~1")


if __name__ == "__main__":
    import unittest
    unittest.main()
