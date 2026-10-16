#!/usr/bin/env python3
"""The infected warning of saw's git hooks is shown once per git operation, however many of saw's
hooks run for it, and every check still reports the repository infected."""
from __future__ import annotations

import json
import os
import shutil
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from stayawake.bots.security import hook
from stayawake.bots.security.models import CONFIRMED
from stayawake.utils.procsnap import Start

_FOUND = [SimpleNamespace(signature_id="known-loader", path="app.js", line=3, commit_sha="",
                          confidence=CONFIRMED)]


class TestTheWarningIsShownOncePerOperation(unittest.TestCase):
    def setUp(self):
        self.home = Path(tempfile.mkdtemp(prefix="warn-once-"))
        self.addCleanup(shutil.rmtree, self.home, True)
        self.repo = self.home / "repo"
        self.repo.mkdir()
        record = self.home / "shown.json"
        patcher = mock.patch.object(hook.hookscript, "warnings_shown_path", lambda: record)
        patcher.start()
        self.addCleanup(patcher.stop)
        self.shown = []

    def _warn(self, operation, root=None, at=1000.0):
        hook._warn_once(root or self.repo, operation, _FOUND, lambda findings: self.shown.append(operation),
                        now=lambda: at)

    def test_the_second_hook_of_the_same_operation_does_not_show_it_again(self):
        self._warn("head:policy:100:5")
        self._warn("head:policy:100:5")
        self.assertEqual(len(self.shown), 1)

    def test_another_operation_shows_it_again(self):
        self._warn("head:policy:100:5")
        self._warn("head:policy:100:6")
        self._warn("head:policy:101:5")
        self.assertEqual(len(self.shown), 3)

    def test_another_repository_shows_it_again(self):
        other = self.home / "other"
        other.mkdir()
        self._warn("head:policy:100:5")
        self._warn("head:policy:100:5", root=other)
        self.assertEqual(len(self.shown), 2)

    def test_the_same_operation_warns_again_once_a_while_has_passed(self):
        self._warn("head:policy:100:5", at=1000.0)
        self._warn("head:policy:100:5", at=1000.0 + hook._SAME_OPERATION_WITHIN_SECONDS)
        self.assertEqual(len(self.shown), 2)

    def test_a_record_from_the_future_does_not_hold_the_warning_back(self):
        self._warn("head:policy:100:5", at=5000.0)
        self._warn("head:policy:100:5", at=1000.0)
        self.assertEqual(len(self.shown), 2)

    def test_a_hook_whose_operation_is_unknown_always_warns(self):
        self._warn(None)
        self._warn(None)
        self.assertEqual(len(self.shown), 2)

    def test_a_record_holding_no_operation_never_holds_an_unknown_one_back(self):
        hook.hookscript.warnings_shown_path().write_text(json.dumps(
            {os.path.realpath(self.repo): {"operation": None, "at": 1000.0}}))
        self._warn(None)
        self.assertEqual(len(self.shown), 1)

    def test_a_record_with_a_time_that_cannot_be_compared_still_shows_it(self):
        for at in (10 ** 400, True, "1000", None):
            self.shown.clear()
            hook.hookscript.warnings_shown_path().write_text(json.dumps(
                {os.path.realpath(self.repo): {"operation": "head:policy:100:5", "at": at}}))
            self._warn("head:policy:100:5", at=50.0)
            self.assertEqual(len(self.shown), 1, repr(at))

    def test_a_record_that_cannot_be_read_still_shows_it(self):
        hook.hookscript.warnings_shown_path().write_text("not json")
        self._warn("head:policy:100:5")
        self.assertEqual(len(self.shown), 1)

    def test_every_check_still_reports_the_repository_infected(self):
        class _Infected:
            infected, error, suspicious, residue, findings = True, "", False, False, []
        with mock.patch.object(hook, "_warn_infected"):
            first = hook._tell(_Infected(), "repo", "saw scan repo", "repo", root=self.repo,
                               command="100:5")
            second = hook._tell(_Infected(), "repo", "saw scan repo", "repo", root=self.repo,
                                command="100:5")
        self.assertEqual((first, second), (1, 1))


class TestEachGitCommandIsOneOperation(unittest.TestCase):
    def _key(self, table, me=10, event="post-checkout", argv=("a", "b", "1")):
        return hook._operation_key("abc", None, event, list(argv), started=lambda pid: table.get(pid),
                                   me=lambda: me)

    def test_the_hooks_of_one_git_command_are_one_operation(self):
        table = {10: Start(at_ns=1, name="python3.14", ppid=9), 9: Start(at_ns=2, name="sh", ppid=8),
                 8: Start(at_ns=77, name="git", ppid=7), 7: Start(at_ns=3, name="Code Helper", ppid=1)}
        key = self._key(table)
        self.assertTrue(key.startswith("abc:"))
        self.assertTrue(key.endswith(":8:77"))

    def test_two_git_commands_from_one_editor_are_two_operations(self):
        first = {10: Start(at_ns=1, name="sh", ppid=8), 8: Start(at_ns=77, name="git", ppid=7),
                 7: Start(at_ns=3, name="Code Helper", ppid=1)}
        second = {20: Start(at_ns=1, name="sh", ppid=18), 18: Start(at_ns=99, name="git", ppid=7),
                  7: Start(at_ns=3, name="Code Helper", ppid=1)}
        self.assertNotEqual(self._key(first), self._key(second, me=20))

    def test_another_event_or_checkout_under_one_git_process_is_another_operation(self):
        table = {10: Start(at_ns=1, name="sh", ppid=8), 8: Start(at_ns=77, name="git", ppid=1)}
        first = self._key(table)
        self.assertNotEqual(first, self._key(table, event="post-merge", argv=("0",)))
        self.assertNotEqual(first, self._key(table, argv=("b", "a", "1")))
        self.assertEqual(first, self._key(table))

    def test_a_hook_run_outside_git_always_warns(self):
        table = {10: Start(at_ns=1, name="python3.14", ppid=9), 9: Start(at_ns=2, name="zsh", ppid=1)}
        self.assertIsNone(self._key(table))

    def test_a_hook_whose_git_command_cannot_be_read_always_warns(self):
        self.assertIsNone(self._key({10: Start(at_ns=1, name="sh", ppid=9)}))

    def test_a_git_command_far_above_the_hook_always_warns(self):
        table = {pid: Start(at_ns=pid, name="sh", ppid=pid - 1) for pid in range(3, 40)}
        table[2] = Start(at_ns=2, name="git", ppid=1)
        self.assertIsNone(self._key(table, me=39))


if __name__ == "__main__":
    unittest.main()
