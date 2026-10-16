#!/usr/bin/env python3
"""When saw tells you to run it through sudo, it names the saw you ran: by its full path when sudo would not find it,
such as one in a virtual environment or installed with pipx, and as plain `saw` when it sits where sudo always looks."""
from __future__ import annotations

import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from stayawake.bots.security import harden
from stayawake.bots.security.harden import denial, live
from stayawake.utils import elevate, own_command
from tests.bots.security.test_harden_leaves_ordinary_programs_alone import _harden
from tests.bots.security.test_take_back_says_what_it_did import _take_back
from tests.bots.security.test_harden import _hooks_already_there
from stayawake.bots.security.harden import approvals as agentapprovals, settings as editorsettings


def _installed(*parts: str) -> str:
    """A saw program file at `parts` under a fresh folder, as an installer leaves it."""
    path = Path(tempfile.mkdtemp(), *parts)
    path.parent.mkdir(parents=True)
    path.write_text("#!/usr/bin/env python3\n", encoding="utf-8")
    return str(path)


def _on_the_system(path: str) -> str:
    with mock.patch.object(own_command.os.path, "isfile", return_value=True):
        return own_command.saw_command(path)


class TestTheCommandNamesTheSawThatRuns(unittest.TestCase):
    def test_a_saw_sudo_would_not_find_is_named_by_its_full_path(self):
        for label, parts in (("a virtual environment", ("saw-test", "bin", "saw")),
                             ("pipx", (".local", "bin", "saw")),
                             ("the longer name", ("venv", "bin", "stayawake"))):
            with self.subTest(label=label):
                path = _installed(*parts)
                self.assertEqual(own_command.saw_command(path), path)

    def test_a_saw_where_sudo_always_looks_is_named_plainly(self):
        for path, command in (("/usr/bin/saw", "saw"), ("/bin/saw", "saw"), ("/usr/bin/stayawake", "stayawake")):
            with self.subTest(path=path):
                self.assertEqual(_on_the_system(path), command)

    def test_a_saw_in_a_folder_some_sudo_skips_is_named_by_its_full_path(self):
        for path in ("/usr/local/bin/saw", "/opt/homebrew/bin/saw", "/usr/local/sbin/saw"):
            with self.subTest(path=path):
                self.assertEqual(_on_the_system(path), path)

    def test_a_full_path_with_a_space_is_quoted(self):
        path = _installed("my tools", "bin", "saw")
        self.assertEqual(own_command.saw_command(path), f"'{path}'")

    def test_saw_run_as_a_module_is_named_with_its_interpreter(self):
        main = str(Path(own_command.__file__).resolve().parent.parent / "__main__.py")
        self.assertEqual(own_command.saw_command(main, "/opt/py/bin/python3"), "/opt/py/bin/python3 -m stayawake")

    def test_a_program_that_is_not_saw_leaves_the_plain_name(self):
        for started_as in ("", "python -m unittest", _installed("bin", "python3"), "/nowhere/bin/saw"):
            with self.subTest(started_as=started_as):
                self.assertEqual(own_command.saw_command(started_as), "saw")

    def test_through_sudo_it_names_the_running_saw(self):
        path = _installed("saw-test", "bin", "saw")
        with mock.patch.object(sys, "argv", [path, "harden"]):
            self.assertEqual(own_command.saw_through_sudo(), f"sudo {path}")


class TestHardenAdvisesTheSawThatRuns(unittest.TestCase):
    def setUp(self):
        self.saw = _installed("saw-test", "bin", "saw")
        patcher = mock.patch.object(sys, "argv", [self.saw, "harden"])
        patcher.start()
        self.addCleanup(patcher.stop)

    def _placed(self, state):
        return harden.run(editor_pass=editorsettings.Correcting, agent_pass=agentapprovals.Correcting,
                          altered=lambda: [], saw_runs=lambda: True, supported=lambda: True, live=lambda: [],
                          folders=lambda: [Path("/mine")], apply=lambda p: denial.PathOutcome(p, state, "x"),
                          settle_hooks=_hooks_already_there, stop=lambda: None, schedule_pass=lambda: None)[1]

    def test_what_needs_an_administrator_names_the_saw_that_ran(self):
        self.assertIn(f"Run `sudo {self.saw} harden` to place the rest.", self._placed(denial.NEEDS_ROOT))

    def test_controls_your_account_could_undo_name_the_saw_that_ran(self):
        self.assertIn(f"Run `sudo {self.saw} harden` so only an administrator can.",
                      self._placed(denial.SELF_ENFORCING))

    def test_code_another_account_runs_names_the_saw_that_ran(self):
        for asking, said in ((None, f"Run `sudo {self.saw} harden` to stop it."),
                             (elevate.NOT_AN_ADMINISTRATOR, f"An administrator can stop it with `sudo {self.saw} harden`.")):
            with self.subTest(asking=asking):
                ending = live.Ending(matched=1, refused=[405], asked_for=[405], asking=asking, quiet=True,
                                     still_holding=1)
                self.assertIn(said, _harden(ending)[1])

    def test_taking_back_what_needs_an_administrator_names_the_saw_that_ran(self):
        _code, text = _take_back([denial.PathOutcome(Path("/root-held"), denial.NEEDS_ROOT, "x")])
        self.assertIn(f"Run `sudo {self.saw} harden --take-back` to take it back.", text)

    def test_no_advice_is_left_with_a_name_to_fill_in(self):
        for text in (self._placed(denial.NEEDS_ROOT), self._placed(denial.SELF_ENFORCING),
                     _take_back([denial.PathOutcome(Path("/r"), denial.NEEDS_ROOT, "x")])[1]):
            with self.subTest(text=text[:40]):
                self.assertNotIn("{", text)
                self.assertNotIn("`sudo saw ", text)


if __name__ == "__main__":
    unittest.main()
