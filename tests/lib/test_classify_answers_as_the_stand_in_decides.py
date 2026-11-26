#!/usr/bin/env python3
"""saw govern classify answers checked for exactly the command lines saw's git stand-in sends to saw:
both read the same table of command lines, which the stand-in's own tests read too. A line the
stand-in runs directly may be answered checked, with a reason, for a repository it names that cannot
be read."""
from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from stayawake.bots.security import govern
from stayawake.lib.git import runs_directly

COMMAND_LINES = (Path(__file__).resolve().parents[2] / "src" / "stayawake" / "bots" / "mcp" / "session" / "tests"
                 / "command_lines_saw_checks.json")
_SETTINGS_VARIABLES = ("GIT_CONFIG_PARAMETERS", "GIT_CONFIG_COUNT", "GIT_CONFIG_GLOBAL", "GIT_CONFIG_SYSTEM",
                       "GIT_CONFIG", "GIT_CONFIG_NOSYSTEM", "GIT_WORK_TREE", "GIT_DIR")


class ClassifyAnswersAsTheStandInDecides(unittest.TestCase):

    def setUp(self):
        made = tempfile.TemporaryDirectory()
        self.addCleanup(made.cleanup)
        self.folder = Path(made.name)
        (self.folder / "sub").mkdir()
        environment = mock.patch.dict(os.environ)
        environment.start()
        self.addCleanup(environment.stop)
        for name in _SETTINGS_VARIABLES:
            os.environ.pop(name, None)

    def test_every_line_in_the_table_is_answered_as_the_stand_in_decides(self):
        lines = json.loads(COMMAND_LINES.read_text(encoding="utf-8"))
        self.assertGreater(len(lines), 20)
        for line in lines:
            with self.subTest(line=line):
                body, _code = govern.classify(str(self.folder), line["tool"], line["args"])
                if body["checked"] and not line["checked"]:
                    self.assertTrue(any(arg.startswith(("--git-dir", "--work-tree", "--bare")) for arg in line["args"]))
                    self.assertTrue(body.get("reason"))
                    self.assertNotIn("run_with", body)
                    continue
                self.assertEqual(body["checked"], line["checked"])

    def test_a_setting_given_through_the_environment_sends_a_command_to_saw(self):
        self.assertEqual(runs_directly.decide("git", ["status"], self.folder, {}), runs_directly.RUNS_AS_TYPED)
        self.assertEqual(runs_directly.decide("git", ["status"], self.folder, {"GIT_CONFIG_COUNT": "1"}),
                         runs_directly.CHECKED_FOR_WHAT_IT_NAMES)
        self.assertEqual(runs_directly.decide("git", ["status"], self.folder, {"GIT_WORK_TREE": "x"}),
                         runs_directly.CHECKED)

    def test_a_push_to_a_folder_on_this_machine_is_checked(self):
        self.assertEqual(runs_directly.decide("git", ["push", "sub", "main"], self.folder, {}),
                         runs_directly.CHECKED_FOR_WHAT_IT_NAMES)
        self.assertEqual(runs_directly.decide("git", ["push", "--rece=x", "origin"], self.folder, {}),
                         runs_directly.CHECKED_FOR_WHAT_IT_NAMES)
        self.assertEqual(runs_directly.decide("git", ["push", "git@host:o/r.git", "main"], self.folder, {}),
                         runs_directly.RUNS_AS_TYPED)


if __name__ == "__main__":
    unittest.main()
