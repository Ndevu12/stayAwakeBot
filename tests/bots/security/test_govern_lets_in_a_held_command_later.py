#!/usr/bin/env python3
"""`saw govern let-in` runs again, through saw's stand-in and in a terminal, the command whose update
saw held where no one could be asked: the command is kept only for such a hold, holds no file
content, needs a person at a terminal, and is gone once it ran."""
from __future__ import annotations

import io
import json
import os
import shutil
import stat
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest import mock

from stayawake import cli
from stayawake.bots.security import govern, govern_held_commands

_HELD = {"scan": {"results": [{"verdict": "suspicious"}]},
         "decision": {"choices": ["let-in", "leave-unchanged"],
                      "let_in": ["saw", "govern", "apply", "--accept", "c0ffee"], "confirm": "yes"}}
_CLEAN = {"scan": {"results": [{"verdict": "clean"}]}}


class _Terminal(io.StringIO):
    def isatty(self):
        return True


class LetInLater(unittest.TestCase):
    def setUp(self):
        base = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, base, ignore_errors=True)
        state = mock.patch.dict(os.environ, {"XDG_STATE_HOME": str(base / "state")})
        state.start()
        self.addCleanup(state.stop)
        self.folder = base / "open folder"
        self.folder.mkdir()
        self.ran = base / "ran"
        self.standin = base / "standin"
        self.standin.write_text(f'#!/bin/sh\npwd > "{self.ran}"\nprintf "%s\\n" "$@" >> "{self.ran}"\n')
        self.standin.chmod(self.standin.stat().st_mode | stat.S_IXUSR)
        named = mock.patch.dict(os.environ, {"SAW_STANDIN_BIN": str(self.standin)})
        named.start()
        self.addCleanup(named.stop)
        here = os.getcwd()
        os.chdir(self.folder)
        self.addCleanup(os.chdir, here)

    def _prepare(self, answer: dict, *flags: str, args=("pull",)) -> dict:
        with mock.patch.object(govern, "prepare", return_value=(json.loads(json.dumps(answer)), 1)), \
                redirect_stdout(io.StringIO()) as out:
            cli.main(["govern", "prepare", "--repo", str(self.folder), "--into", "unused", "--tool", "git",
                      *flags, "--", *args])
        return json.loads(out.getvalue())

    def _let_in(self, attended: bool, *flags: str) -> tuple[int, str]:
        said = _Terminal() if attended else io.StringIO()
        stdin = _Terminal() if attended else io.StringIO()
        with mock.patch("sys.stdin", stdin), redirect_stderr(said):
            code = cli.main(["govern", "let-in", *flags])
        return code, said.getvalue()

    def _kept(self):
        return govern_held_commands.read(str(self.folder))

    def test_an_unattended_hold_keeps_only_the_command_the_folder_and_the_time(self):
        printed = self._prepare(_HELD, "--no-one-to-ask", args=("pull", "origin", "main"))
        record = self._kept()
        self.assertEqual(set(record), {"version", "folder", "ran_in", "command", "at"})
        self.assertEqual(record["command"], ["git", "pull", "origin", "main"])
        self.assertEqual(record["folder"], os.path.realpath(self.folder))
        self.assertEqual(printed["decision"]["let_in_later"], ["saw", "govern", "let-in"])

    def test_nothing_is_kept_where_someone_can_be_asked_or_nothing_is_held(self):
        self._prepare(_HELD)
        self.assertIsNone(self._kept())
        self._prepare(_CLEAN, "--no-one-to-ask")
        self.assertIsNone(self._kept())

    def test_the_let_in_command_names_the_folder_when_it_ran_elsewhere(self):
        os.chdir(self.folder.parent)
        printed = self._prepare(_HELD, "--no-one-to-ask")
        self.assertEqual(printed["decision"]["let_in_later"],
                         ["saw", "govern", "let-in", "--repo", os.path.realpath(self.folder)])

    def test_a_second_held_command_replaces_the_first(self):
        self._prepare(_HELD, "--no-one-to-ask", args=("pull",))
        self._prepare(_HELD, "--no-one-to-ask", args=("merge", "topic"))
        self.assertEqual(self._kept()["command"], ["git", "merge", "topic"])
        self.assertEqual(len(list(govern_held_commands.store().iterdir())), 1)

    def test_nothing_is_kept_inside_a_repository(self):
        inside = self.folder.parent / "checkout"
        (inside / ".git").mkdir(parents=True)
        with mock.patch.dict(os.environ, {"XDG_STATE_HOME": str(inside / "state")}):
            printed = self._prepare(_HELD, "--no-one-to-ask")
            self.assertIsNone(self._kept())
        self.assertNotIn("let_in_later", printed["decision"])

    def test_without_a_terminal_it_refuses_and_runs_nothing(self):
        self._prepare(_HELD, "--no-one-to-ask")
        code, said = self._let_in(attended=False)
        self.assertNotEqual(code, 0)
        self.assertIn("needs a person at a terminal", said)
        self.assertFalse(self.ran.exists(), "the stand-in ran without a person")
        self.assertIsNotNone(self._kept(), "the held command was dropped without running")

    def test_at_a_terminal_it_runs_the_stand_in_with_the_command_in_the_folder_then_forgets_it(self):
        self._prepare(_HELD, "--no-one-to-ask", args=("pull", "origin", "it's main"))
        os.chdir(self.folder.parent)
        code, _said = self._let_in(True, "--repo", str(self.folder))
        self.assertEqual(code, 0)
        where, *argv = self.ran.read_text().splitlines()
        self.assertEqual(os.path.realpath(where), os.path.realpath(self.folder))
        self.assertEqual(argv, ["git", "pull", "origin", "it's main"])
        self.assertIsNone(self._kept(), "the held command is still kept after it ran")

    def test_with_nothing_held_it_says_so_and_runs_nothing(self):
        code, said = self._let_in(attended=True)
        self.assertNotEqual(code, 0)
        self.assertIn("no update is held for review", said)
        self.assertFalse(self.ran.exists())


if __name__ == "__main__":
    unittest.main()
