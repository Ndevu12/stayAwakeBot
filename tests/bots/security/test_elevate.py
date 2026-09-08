#!/usr/bin/env python3
"""Asking for privilege for one action, on a machine that is already assumed compromised.

The binary is the whole risk here. An implant that can put a `sudo` earlier in `PATH` would
otherwise be handed root by the very command sent to remove it.
"""
from __future__ import annotations

import os
import stat
import unittest
import unittest.mock
from pathlib import Path

from stayawake.utils import elevate


class TestItWillNotBeHandedAnAttackersSudo(unittest.TestCase):
    def test_a_sudo_that_is_not_root_owned_is_not_used(self):
        with unittest.mock.patch.object(elevate.os, "stat",
                                        return_value=os.stat_result(
                                            (0o104755, 0, 0, 1, 501, 0, 0, 0, 0, 0))):
            self.assertIsNone(elevate.trusted_sudo(), "it accepted a sudo owned by a user")

    def test_a_sudo_anyone_can_write_is_not_used(self):
        mode = 0o104757                                   # setuid, and world-writable
        with unittest.mock.patch.object(elevate.os, "stat",
                                        return_value=os.stat_result(
                                            (mode, 0, 0, 1, 0, 0, 0, 0, 0, 0))):
            self.assertIsNone(elevate.trusted_sudo())

    def test_a_sudo_without_setuid_is_not_used(self):
        with unittest.mock.patch.object(elevate.os, "stat",
                                        return_value=os.stat_result(
                                            (0o100755, 0, 0, 1, 0, 0, 0, 0, 0, 0))):
            self.assertIsNone(elevate.trusted_sudo())

    def test_it_is_never_resolved_through_the_path(self):
        source = Path(elevate.__file__).read_text()
        self.assertNotIn("which(", source)
        self.assertNotIn("shutil", source)
        for candidate in elevate._SUDO_PATHS:
            self.assertTrue(candidate.startswith("/"), f"{candidate} is not an absolute path")

    def test_the_real_one_on_this_machine_passes_its_own_check(self):
        found = elevate.trusted_sudo()
        if found is None:
            self.skipTest("no sudo on this machine")
        info = os.stat(found)
        self.assertEqual(info.st_uid, 0)
        self.assertFalse(info.st_mode & (stat.S_IWGRP | stat.S_IWOTH))


class TestItAsksOnlyWhenThereIsSomebodyToAsk(unittest.TestCase):
    def test_it_does_not_prompt_where_nobody_can_answer(self):
        calls = []

        def run(argv, **kw):
            calls.append(argv)
            class Done:
                returncode = 1
            return Done()

        outcome, detail = elevate.run_as_root(["/bin/kill", "-KILL", "9"],
                                              sudo=lambda: "/usr/bin/sudo",
                                              ask=lambda: False, run=run)
        self.assertEqual(outcome, elevate.CANNOT_ASK)
        self.assertEqual(len(calls), 1, "it prompted with no terminal to prompt on")
        self.assertIn("-n", calls[0])

    def test_already_granted_is_never_interrupted(self):
        class Done:
            returncode = 0
        outcome, _detail = elevate.run_as_root(["/bin/kill", "-KILL", "9"],
                                               sudo=lambda: "/usr/bin/sudo",
                                               ask=lambda: True,
                                               run=lambda argv, **kw: Done())
        self.assertEqual(outcome, elevate.GRANTED)

    def test_no_trustworthy_sudo_is_said_rather_than_guessed_at(self):
        outcome, detail = elevate.run_as_root(["/bin/kill"], sudo=lambda: None)
        self.assertEqual(outcome, elevate.NOT_AVAILABLE)
        self.assertIn("sudo", detail)

    def test_the_command_is_a_list_so_a_pid_cannot_become_a_shell_line(self):
        seen = []
        class Done:
            returncode = 0
        elevate.run_as_root(["/bin/kill", "-KILL", "9; rm -rf /"], sudo=lambda: "/usr/bin/sudo",
                            ask=lambda: True, run=lambda argv, **kw: seen.append(argv) or Done())
        self.assertIsInstance(seen[0], list)
        self.assertIn("9; rm -rf /", seen[0], "the argument was split or interpolated")


class TestItAsksWhereverSudoCouldPrompt(unittest.TestCase):
    """sudo prompts on /dev/tty. Testing stdin or stderr instead answers no whenever output is
    redirected, so a run that could have asked would give up with the implant still running."""

    def test_a_redirected_run_with_a_terminal_can_still_ask(self):
        self.assertTrue(elevate.can_ask(terminal=lambda: True))

    def test_no_controlling_terminal_cannot_ask(self):
        def none():
            raise OSError(6, "Device not configured")
        self.assertFalse(elevate.can_ask(terminal=none))

    def test_it_asks_the_terminal_and_not_the_streams(self):
        source = Path(elevate.__file__).read_text()
        self.assertIn("/dev/tty", source)
        self.assertNotIn("stdin.isatty", source)
        self.assertNotIn("stderr.isatty", source)


if __name__ == "__main__":
    unittest.main()
