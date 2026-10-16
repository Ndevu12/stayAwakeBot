#!/usr/bin/env python3
"""One git command shows the infected warning once for each finding: a later hook of the same command that
finds only what was already shown prints nothing more and still reports the repository infected; a finding
not yet shown is shown; another git command shows them all again."""
from __future__ import annotations

import contextlib
import io
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from stayawake.bots.security import hook
from stayawake.bots.security.models import CONFIRMED
from tests.bots.security.test_hook import _INFECTED, _Isolated

_SOURCE = Path(hook.__file__).resolve().parents[3]


def _finding(path: str, line: int = 1):
    return SimpleNamespace(signature_id="known-loader", category="code-loader", path=path, line=line,
                           commit_sha="", confidence=CONFIRMED)


def _infected(*findings):
    return SimpleNamespace(infected=True, error="", suspicious=False, residue=False, findings=list(findings))


class TestOneGitCommandShowsEachFindingOnce(unittest.TestCase):
    def setUp(self):
        self.home = Path(tempfile.mkdtemp(prefix="one-warning-"))
        self.addCleanup(shutil.rmtree, self.home, True)
        self.repo = self.home / "repo"
        self.repo.mkdir()
        record = self.home / "shown.json"
        patcher = mock.patch.object(hook.hookscript, "warnings_shown_path", lambda: record)
        patcher.start()
        self.addCleanup(patcher.stop)

    def _tell(self, result, command="100:5") -> tuple[int, str]:
        printed = io.StringIO()
        with contextlib.redirect_stderr(printed):
            code = hook._tell(result, "repo", "saw scan repo", "repo", root=self.repo, command=command)
        return code, printed.getvalue()

    def test_a_later_hook_finding_what_was_shown_prints_nothing_and_still_reports_it_infected(self):
        first = self._tell(_infected(_finding("a.js")))
        second = self._tell(_infected(_finding("a.js")))
        self.assertEqual((first[0], second[0]), (1, 1))
        self.assertEqual(first[1].count("WORM DETECTED"), 1)
        self.assertEqual(second[1], "")

    def test_a_finding_not_yet_shown_is_shown(self):
        self._tell(_infected(_finding("a.js")))
        code, printed = self._tell(_infected(_finding("a.js"), _finding("b.js")))
        self.assertEqual(code, 1)
        self.assertEqual(printed.count("WORM DETECTED"), 1)
        self.assertIn("b.js", printed)
        self.assertNotIn("a.js", printed)

    def test_the_same_file_with_another_finding_in_it_is_shown(self):
        self._tell(_infected(_finding("a.js", 1)))
        self.assertIn("a.js:9", self._tell(_infected(_finding("a.js", 9)))[1])

    def test_a_finding_past_the_ones_a_warning_names_is_named_by_the_next_hook(self):
        first = self._tell(_infected(*[_finding(f"f{n}.js") for n in range(1, 6)], _finding("package.json")))
        self.assertIn("…and 1 more", first[1])
        self.assertNotIn("package.json", first[1])
        code, printed = self._tell(_infected(_finding("package.json")))
        self.assertEqual(code, 1)
        self.assertIn("package.json", printed)

    def test_a_finding_whose_fields_are_not_text_is_still_a_worm_warning(self):
        odd = SimpleNamespace(signature_id="known-loader", category="code-loader", path=Path("a.js"),
                              line="3", commit_sha=None, confidence=CONFIRMED)
        self.assertEqual(hook._finding_digest(odd), hook._finding_digest(odd))
        code, printed = self._tell(_infected(odd))
        self.assertEqual(code, 1)
        self.assertIn("WORM DETECTED", printed)
        for missing in ("signature_id", "path"):
            with self.subTest(missing=missing):
                bare = SimpleNamespace(**{k: v for k, v in vars(odd).items() if k != missing})
                self.assertTrue(hook._finding_digest(bare))

    def test_another_git_command_shows_them_all_again(self):
        self._tell(_infected(_finding("a.js")), command="100:5")
        self.assertIn("a.js", self._tell(_infected(_finding("a.js")), command="101:5")[1])

    def test_a_hook_whose_git_command_is_unknown_always_shows_them(self):
        self._tell(_infected(_finding("a.js")), command=None)
        self.assertIn("a.js", self._tell(_infected(_finding("a.js")), command=None)[1])

    def test_a_record_that_cannot_be_read_shows_them_all(self):
        self._tell(_infected(_finding("a.js")))
        where = os.path.realpath(self.repo)
        for shown in ("not a list", [1, 2], None, {"x": 1}):
            with self.subTest(shown=shown):
                hook.hookscript.warnings_shown_path().write_text(json.dumps(
                    {where: {"operation": "100:5", "at": 9e18, "shown": shown}}))
                self.assertIn("a.js", self._tell(_infected(_finding("a.js")))[1])
        hook.hookscript.warnings_shown_path().write_text("not json")
        self.assertIn("a.js", self._tell(_infected(_finding("a.js")))[1])


_SAW_STAND_IN = '''import json, sys
sys.path.insert(0, {source!r})
from stayawake.bots.security import hook
hook._bring_up_to_date = lambda: None
code = hook.run_event(sys.argv[1], sys.argv[2:])
with open({log!r}, "a") as log:
    log.write(json.dumps({{"event": sys.argv[1], "code": code}}) + "\\n")
sys.exit(code)
'''


class TestAnInfectedPullThatRebasesWarnsOnce(_Isolated):
    def setUp(self):
        super().setUp()
        self.folder = Path(tempfile.mkdtemp(prefix="rebase-warns-once-"))
        self.addCleanup(shutil.rmtree, self.folder, True)
        self.log = self.folder / "runs.jsonl"
        stand_in = self.folder / "stand_in.py"
        stand_in.write_text(_SAW_STAND_IN.format(source=str(_SOURCE), log=str(self.log)))
        hooks = self.folder / "hooks"
        hooks.mkdir()
        for event in ("post-checkout", "post-rewrite"):
            script = hooks / event
            script.write_text(f'#!/bin/sh\nexec "{sys.executable}" -I "{stand_in}" {event} "$@"\n')
            script.chmod(0o755)
        (self.home / "gitconfig").write_text(
            "[user]\n\tname = t\n\temail = t@t\n[commit]\n\tgpgsign = false\n[init]\n\tdefaultBranch = main\n"
            f"[core]\n\thooksPath = {hooks}\n")
        self.up, self.down = self.folder / "up", self.folder / "down"
        self.up.mkdir()
        self._git(self.up, "init", "-q")
        self._commit(self.up, {"app.js": "export const x = 1;\n"})
        self._git(self.folder, "clone", "-q", str(self.up), str(self.down))

    def _git(self, where: Path, *args: str, check: bool = True):
        result = subprocess.run(["git", *args], cwd=where, capture_output=True, text=True,
                                stdin=subprocess.DEVNULL, env={**os.environ, "GIT_EDITOR": "true"})
        if check:
            self.assertEqual(result.returncode, 0, result.stderr)
        return result

    def _commit(self, where: Path, files: dict[str, str]):
        for rel, text in files.items():
            (where / rel).write_text(text)
        self._git(where, "add", "-A")
        self._git(where, "commit", "-q", "-m", "work")

    def test_both_hooks_report_it_infected_and_the_warning_is_shown_once(self):
        self._commit(self.up, {".gitignore": _INFECTED, "c.txt": "c\n"})
        self._commit(self.down, {"d.txt": "local\n"})
        self.log.write_text("")
        pulled = self._git(self.down, "pull", "-q", "--rebase")
        runs = [json.loads(line) for line in self.log.read_text().splitlines()]
        self.assertEqual([(run["event"], run["code"]) for run in runs],
                         [("post-checkout", 1), ("post-rewrite", 1)])
        self.assertEqual(pulled.stderr.count("WORM DETECTED"), 1, pulled.stderr)

    def test_two_git_commands_each_show_it(self):
        self._commit(self.up, {".gitignore": _INFECTED})
        first = self._git(self.folder, "clone", "-q", str(self.up), "first", check=False)
        second = self._git(self.folder, "clone", "-q", str(self.up), "second", check=False)
        self.assertEqual((first.stderr.count("WORM DETECTED"), second.stderr.count("WORM DETECTED")), (1, 1))


if __name__ == "__main__":
    unittest.main()
