#!/usr/bin/env python3
"""A git command runs saw's check once: when saw's hook in git's settings and saw's hook in the hooks
folder both run for one git command, the second returns the first one's outcome without checking again;
a check that did not finish, another git command, or a record that is old or unreadable is checked
again."""
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
from unittest import mock

from stayawake.bots.security import hook
from stayawake.utils import env
from stayawake.utils.procsnap import Start
from tests.bots.security.test_hook import _INFECTED, _Isolated, _repo, _run

_SOURCE = Path(hook.__file__).resolve().parents[3]
_NULL = "0" * 40


class _OneRepository(_Isolated):
    def setUp(self):
        super().setUp()
        self.scans: list = []
        real = hook._scan_within_budget

        def counting(root, include, config_path, display, merges=None):
            self.scans.append(include)
            return real(root, include, config_path, display, merges)

        patcher = mock.patch.object(hook, "_scan_within_budget", side_effect=counting)
        patcher.start()
        self.addCleanup(patcher.stop)
        no_upkeep = mock.patch.object(hook, "_bring_up_to_date")
        no_upkeep.start()
        self.addCleanup(no_upkeep.stop)

    def _repository(self, files: dict[str, str]) -> tuple[Path, str]:
        repo = _repo(files)
        self.addCleanup(shutil.rmtree, repo, True)
        self._in_repo(repo)
        return repo, hook.gitutil.stdout(repo, ["rev-parse", "HEAD"]).strip()

    def _clone_check(self, head: str, operation: str | None, **kwargs) -> tuple[int, str]:
        printed = io.StringIO()
        with mock.patch.object(hook, "_operation_key", return_value=operation), \
                contextlib.redirect_stderr(printed):
            code = hook.run_event("post-checkout", [_NULL, head, "1"], **kwargs)
        return code, printed.getvalue()


class TestTheSecondHookOfOneGitCommandChecksNothingAgain(_OneRepository):
    def test_an_infected_clone_is_found_warned_once_and_both_hooks_say_infected(self):
        _, head = self._repository({".gitignore": _INFECTED})
        first = self._clone_check(head, "op-1", from_settings=True)
        second = self._clone_check(head, "op-1")
        self.assertEqual((first[0], second[0]), (1, 1))
        self.assertIn("StayAwakeBot", first[1])
        self.assertEqual(second[1], "")
        self.assertEqual(len(self.scans), 1)

    def test_a_clean_checkout_is_checked_once(self):
        repo, head = self._repository({"app.js": "export const x = 1;\n"})
        (repo / "app.js").write_text("export const x = 2;\n")
        _run(repo, "commit", "-qam", "next")
        new = hook.gitutil.stdout(repo, ["rev-parse", "HEAD"]).strip()
        for from_settings in (True, False):
            with mock.patch.object(hook, "_operation_key", return_value="op-1"):
                code = hook.run_event("post-checkout", [head, new, "1"], from_settings=from_settings)
                self.assertEqual(code, 0)
        self.assertEqual(self.scans, [("app.js",)])


class TestEveryOtherCheckRunsAgain(_OneRepository):
    def test_another_git_command_is_checked_again(self):
        _, head = self._repository({".gitignore": _INFECTED})
        self._clone_check(head, "op-1")
        self.assertEqual(self._clone_check(head, "op-2")[0], 1)
        self.assertEqual(len(self.scans), 2)

    def test_a_hook_with_no_git_command_above_it_is_checked_every_time(self):
        _, head = self._repository({".gitignore": _INFECTED})
        self._clone_check(head, None)
        self.assertEqual(self._clone_check(head, None)[0], 1)
        self.assertEqual(len(self.scans), 2)

    def test_a_check_that_did_not_finish_is_checked_again(self):
        _, head = self._repository({".gitignore": _INFECTED})
        with mock.patch.object(hook, "_scan_within_budget", return_value=hook._TIMED_OUT):
            self.assertEqual(self._clone_check(head, "op-1")[0], 2)
        self.assertEqual(self._clone_check(head, "op-1")[0], 1)
        self.assertEqual(len(self.scans), 1)

    def test_a_record_a_minute_old_is_checked_again(self):
        repo, _ = self._repository({"app.js": "x\n"})
        hook._record_outcome(repo, "op-1", 1, now=lambda: 1000.0)
        self.assertEqual(hook._outcome_already_found(repo, "op-1", now=lambda: 1000.0 + 5), 1)
        self.assertIsNone(hook._outcome_already_found(
            repo, "op-1", now=lambda: 1000.0 + hook._SAME_CHECK_WITHIN_SECONDS))
        self.assertIsNone(hook._outcome_already_found(repo, "op-1", now=lambda: 900.0))

    def test_a_record_of_another_repository_or_operation_is_not_used(self):
        repo, _ = self._repository({"app.js": "x\n"})
        other = Path(tempfile.mkdtemp(prefix="other-"))
        self.addCleanup(shutil.rmtree, other, True)
        hook._record_outcome(repo, "op-1", 0, now=lambda: 1000.0)
        self.assertIsNone(hook._outcome_already_found(other, "op-1", now=lambda: 1001.0))
        self.assertIsNone(hook._outcome_already_found(repo, "op-2", now=lambda: 1001.0))

    def test_an_outcome_that_is_not_a_complete_check_is_neither_recorded_nor_used(self):
        repo, _ = self._repository({"app.js": "x\n"})
        hook._record_outcome(repo, "op-1", 2, now=lambda: 1000.0)
        self.assertIsNone(hook._outcome_already_found(repo, "op-1", now=lambda: 1001.0))
        where = os.path.realpath(repo)
        hook.hookscript.checks_made_path().parent.mkdir(parents=True, exist_ok=True)
        for outcome in (2, True, "1", None, [1]):
            with self.subTest(outcome=outcome):
                hook.hookscript.checks_made_path().write_text(json.dumps(
                    {where: {"operation": "op-1", "at": 1000.0, "outcome": outcome}}))
                self.assertIsNone(hook._outcome_already_found(repo, "op-1", now=lambda: 1001.0))

    def test_a_record_that_cannot_be_read_is_not_used(self):
        repo, _ = self._repository({"app.js": "x\n"})
        path = hook.hookscript.checks_made_path()
        path.parent.mkdir(parents=True, exist_ok=True)
        for text in ("not json", "[]", json.dumps({os.path.realpath(repo): "op-1"}),
                     " " * (hook._LARGEST_CHECKS_RECORD + 1)):
            with self.subTest(text=text[:20]):
                path.write_text(text)
                self.assertIsNone(hook._outcome_already_found(repo, "op-1", now=lambda: 1001.0))

    def test_the_record_holds_a_bounded_number_of_repositories(self):
        folders = [Path(tempfile.mkdtemp(prefix="held-")) for _ in range(hook._MOST_REPOSITORIES_HELD + 5)]
        for folder in folders:
            self.addCleanup(shutil.rmtree, folder, True)
        for n, folder in enumerate(folders):
            hook._record_outcome(folder, f"op-{n}", 0, now=lambda n=n: 1000.0 + n)
        held = json.loads(hook.hookscript.checks_made_path().read_text())
        self.assertEqual(len(held), hook._MOST_REPOSITORIES_HELD)
        self.assertIn(os.path.realpath(folders[-1]), held)
        self.assertNotIn(os.path.realpath(folders[0]), held)

    def test_the_record_is_kept_in_saws_own_cache(self):
        repo, _ = self._repository({"app.js": "x\n"})
        path = hook.hookscript.checks_made_path().resolve()
        self.assertTrue(path.is_relative_to(Path(env.xdg_cache_home()).resolve()))
        self.assertFalse(path.is_relative_to(repo.resolve()))


class TestOnePushIsJudgedOnce(_OneRepository):
    def _judge_twice(self, outcome: int) -> tuple[list[int], int]:
        self._repository({"app.js": "x\n"})
        judged = []

        def judging(*args, **kwargs):
            judged.append(args)
            return outcome

        with mock.patch.object(hook.outbound, "check_push", side_effect=judging), \
                mock.patch.object(hook, "_operation_key", return_value="push-1"):
            outcomes = [hook._check_push_once(["origin", "url"], "refs", None, True) for _ in range(2)]
        return outcomes, len(judged)

    def test_a_push_blocked_by_the_first_hook_is_blocked_by_the_second_without_judging_again(self):
        self.assertEqual(self._judge_twice(1), ([1, 1], 1))

    def test_a_push_that_could_not_be_verified_is_judged_again(self):
        self.assertEqual(self._judge_twice(2), ([2, 2], 2))


class TestWhatGitGaveTheHookIsPartOfTheOperation(unittest.TestCase):
    def test_another_input_under_one_git_command_is_another_operation(self):
        table = {10: Start(at_ns=1, name="sh", ppid=8), 8: Start(at_ns=77, name="git", ppid=1)}

        def key(given):
            return hook._operation_key("abc", None, "post-rewrite", ["rebase"], given=given,
                                       started=lambda pid: table.get(pid), me=lambda: 10)
        self.assertEqual(key("a b\n"), key("a b\n"))
        self.assertNotEqual(key("a b\n"), key("a c\n"))


_SAW_STAND_IN = '''import json, sys
sys.path.insert(0, {source!r})
from stayawake.bots.security import hook
args = sys.argv[1:]
assert args[:2] == ["hook", "run"], args
args = args[2:]
from_settings = "--from-settings" in args
args = [a for a in args if a != "--from-settings"]
event, argv = args[0], args[1:]
real = hook._scan_within_budget
scans = []


def noting(root, include, config_path, display, merges=None):
    scans.append(None if include is None else sorted(include))
    return real(root, include, config_path, display, merges)


hook._scan_within_budget = noting
hook._bring_up_to_date = lambda: None
code = hook.run_event(event, argv, from_settings=from_settings)
with open({log!r}, "a") as log:
    run = {{"event": event, "from_settings": from_settings, "scans": scans, "code": code}}
    log.write(json.dumps(run) + "\\n")
sys.exit(code)
'''


@unittest.skipUnless(hook.git_runs_settings_hooks(), "the git here does not run hooks set in its settings")
class TestBothOfSawsHooksRunOneCheckPerGitCommand(_Isolated):
    def setUp(self):
        super().setUp()
        self.folder = Path(tempfile.mkdtemp(prefix="check-once-"))
        self.addCleanup(shutil.rmtree, self.folder, True)
        self.log = self.folder / "runs.jsonl"
        stand_in = self.folder / "stand_in.py"
        stand_in.write_text(_SAW_STAND_IN.format(source=str(_SOURCE), log=str(self.log)))
        self.saw = self.folder / "saw"
        self.saw.write_text(f'#!/bin/sh\nexec "{sys.executable}" -I "{stand_in}" "$@"\n')
        self.saw.chmod(0o755)
        hooks = self.folder / "hooks"
        hooks.mkdir()
        lines = ["[user]\n\tname = t\n\temail = t@t\n[commit]\n\tgpgsign = false\n",
                 "[init]\n\tdefaultBranch = main\n", f"[core]\n\thooksPath = {hooks}\n"]
        for event in hook.hookscript.HOOKS:
            script = hooks / event
            script.write_text(hook.hookscript.render(event, str(self.saw), None))
            script.chmod(0o755)
            command = hook.hookscript.settings_command(event, str(self.saw), None)
            lines.append(f'[hook "saw-{event}"]\n\tcommand = {json.dumps(command)}\n\tevent = {event}\n')
        self.config = self.home / "gitconfig"
        self.config.write_text("".join(lines))
        self.up = self.folder / "up"
        self.up.mkdir()
        self._git(self.up, "init", "-q")
        (self.up / "app.js").write_text("export const x = 1;\n")
        self._git(self.up, "add", "-A")
        self._git(self.up, "commit", "-qm", "base")

    def _git(self, where: Path, *args: str, check: bool = True):
        result = subprocess.run(["git", *args], cwd=where, capture_output=True, text=True,
                                stdin=subprocess.DEVNULL, env={**os.environ, "GIT_EDITOR": "true"})
        if check:
            self.assertEqual(result.returncode, 0, result.stderr)
        return result

    def _runs_during(self, where: Path, *args: str, check: bool = True) -> list[dict]:
        self.log.write_text("")
        self._git(where, *args, check=check)
        return [json.loads(line) for line in self.log.read_text().splitlines()]

    def _clone(self) -> Path:
        self._git(self.folder, "clone", "-q", str(self.up), "down")
        return self.folder / "down"

    def _upstream_change(self):
        (self.up / "app.js").write_text("export const x = 2;\n")
        self._git(self.up, "commit", "-qam", "next")

    def _checks(self, runs: list[dict]) -> int:
        return sum(len(run["scans"]) for run in runs)

    def test_each_git_command_runs_one_check_when_both_hooks_run(self):
        self.log.write_text("")
        down = self._clone()
        clone_runs = [json.loads(line) for line in self.log.read_text().splitlines()]
        self.assertEqual(self._checks(clone_runs), 1)
        self.assertEqual(len(clone_runs), 2)
        self._upstream_change()
        self._git(down, "fetch", "-q")
        commands = {
            "checkout": ("switch", "-q", "--detach", "origin/main"),
            "back": ("switch", "-q", "main"),
            "pull": ("pull", "-q", "--no-rebase", "--no-edit"),
        }
        for name, args in commands.items():
            with self.subTest(command=name):
                runs = self._runs_during(down, *args)
                self.assertEqual(len(runs), 2)
                self.assertLessEqual(self._checks(runs), 1)
                self.assertEqual({run["code"] for run in runs}, {0})
        (down / "local.txt").write_text("local\n")
        self._git(down, "add", "-A")
        self._git(down, "commit", "-qm", "local")
        (down / "local.txt").write_text("amended\n")
        self._git(down, "add", "-A")
        runs = self._runs_during(down, "commit", "-q", "--amend", "--no-edit")
        self.assertEqual((len(runs), self._checks(runs)), (2, 1))
        self._upstream_change_again()
        runs = self._runs_during(down, "pull", "-q", "--rebase")
        self.assertEqual(self._checks(runs), 1)
        (down / "app.js").write_text("changed by hand\n")
        runs = self._runs_during(down, "checkout", "--", "app.js")
        self.assertEqual(len(runs), 2)
        self.assertEqual(self._checks(runs), 1)

    def _upstream_change_again(self):
        (self.up / "other.js").write_text("export const y = 1;\n")
        self._git(self.up, "add", "-A")
        self._git(self.up, "commit", "-qm", "other")

    def test_an_infected_clone_is_found_once_and_both_hooks_say_infected(self):
        (self.up / ".gitignore").write_text(_INFECTED)
        self._git(self.up, "add", "-A")
        self._git(self.up, "commit", "-qm", "worm")
        self.log.write_text("")
        result = self._git(self.folder, "clone", str(self.up), "down")
        runs = [json.loads(line) for line in self.log.read_text().splitlines()]
        self.assertEqual([run["code"] for run in runs], [1, 1])
        self.assertEqual(self._checks(runs), 1)
        self.assertEqual(result.stderr.count(".gitignore:"), 1, result.stderr)

    def test_the_hooks_folder_checks_when_the_hook_in_gits_settings_does_not_run(self):
        down = self._clone()
        self._upstream_change()
        self._git(down, "fetch", "-q")
        switched_off = {
            "missing": lambda: self._git(self.folder, "config", "--global", "--remove-section",
                                         "hook.saw-post-checkout"),
            "off in the settings": lambda: self._git(self.folder, "config", "--global",
                                                     "hook.saw-post-checkout.enabled", "false"),
            "event off in the settings": lambda: self._git(self.folder, "config", "--global",
                                                           "hook.post-checkout.enabled", "false"),
            "off in the repository": lambda: self._git(down, "config", "hook.post-checkout.enabled", "false"),
            "pointing at a saw that is gone": lambda: self._git(
                self.folder, "config", "--global", "hook.saw-post-checkout.command",
                hook.hookscript.settings_command("post-checkout", str(self.folder / "gone" / "saw"), None)),
        }
        for name, switch in switched_off.items():
            with self.subTest(how=name):
                saved = self.config.read_text()
                switch()
                runs = self._runs_during(down, "switch", "-q", "--detach", "origin/main")
                self.config.write_text(saved)
                self._git(down, "config", "--unset-all", "hook.post-checkout.enabled", check=False)
                self._git(down, "switch", "-q", "main")
                self.assertEqual([(run["from_settings"], len(run["scans"])) for run in runs], [(False, 1)])
        for how in (("-c", "hook.post-checkout.enabled=false"),
                    ("-c", "hook.saw-post-checkout.enabled=false")):
            with self.subTest(how=" ".join(how)):
                runs = self._runs_during(down, *how, "switch", "-q", "--detach", "origin/main")
                self.assertEqual([(run["from_settings"], len(run["scans"])) for run in runs], [(False, 1)])
                self._git(down, "switch", "-q", "main")


if __name__ == "__main__":
    unittest.main()
