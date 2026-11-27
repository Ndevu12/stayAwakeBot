#!/usr/bin/env python3
"""`saw govern classify --serve` answers each request line with the document `saw govern classify
--json` prints for that command run in the request's environment, reads the repository afresh for
each request, answers a malformed line with its reason and goes on, echoes a request's `id`, and
leaves nothing running after stdin closes. Each case runs saw in a process of its own."""
from __future__ import annotations

import json
import os
import subprocess
import sys
import unittest
from pathlib import Path

import stayawake
from stayawake.utils import env as saw_env
from tests.support.gitrepo import GitSandbox

SOURCE = str(Path(stayawake.__file__).resolve().parent.parent)
SAW = [sys.executable, "-m", "stayawake"]
SANDBOX_SETTING_FILES = ("GIT_CONFIG_GLOBAL", "GIT_CONFIG_SYSTEM", "GIT_CONFIG_NOSYSTEM")
"""The variables the sandbox names its settings files with, which an operator's terminal does not
set and which make saw check every command."""
ANSWER_WAIT_SECONDS = 120


class ServeSandbox(GitSandbox):
    """A repository, an operator's home whose settings name an alias, and the environment a terminal
    in that home runs commands with."""

    def setUp(self):
        super().setUp()
        self.repo = self.new_repo("repo")
        self.write(self.repo, "README.md", "hello\n")
        self.commit(self.repo, "first")
        self.environment = self._terminal("home", "status")

    def _terminal(self, name: str, alias_runs: str) -> dict[str, str]:
        """Make a home whose settings name the alias `st` for `alias_runs`. Takes the home's name and
        the alias's command. Returns the environment a terminal there runs commands with."""
        home = self.owned(self.root / name)
        home.mkdir()
        (home / ".gitconfig").write_text(f"[alias]\n\tst = {alias_runs}\n", encoding="utf-8")
        environment = {key: value for key, value in os.environ.items()
                       if key not in SANDBOX_SETTING_FILES and key not in saw_env.GOVERN_ACTIVATION
                       and key != "SAW_BIN"}
        return {**environment, "HOME": str(home), "XDG_CONFIG_HOME": str(home / ".config"),
                "PYTHONPATH": SOURCE}

    def one_shot(self, tool: str, argv: list[str], environment: dict[str, str]) -> dict:
        """Ask one-shot classify. Takes the tool, the arguments and the environment it runs with.
        Returns its document."""
        done = subprocess.run([*SAW, "govern", "classify", "--json", "--tool", tool, "--repo", str(self.repo),
                               "--", *argv], env=environment, capture_output=True, stdin=subprocess.DEVNULL,
                              timeout=ANSWER_WAIT_SECONDS, check=False)
        return json.loads(done.stdout)

    def serving(self, environment: dict[str, str]) -> subprocess.Popen:
        """Start `saw govern classify --serve` in its own process group. Takes its own environment.
        Returns the process, ended when the test ends."""
        errors = open(self.owned(self.root / "serve-errors.txt"), "wb")
        self.addCleanup(errors.close)
        process = subprocess.Popen([*SAW, "govern", "classify", "--serve"], env=environment,
                                   stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=errors,
                                   start_new_session=os.name != "nt")
        self.addCleanup(self._end, process)
        return process

    @staticmethod
    def _end(process: subprocess.Popen) -> None:
        """Kill a serve process the test left running, and close its pipes."""
        if process.poll() is None:
            process.kill()
            process.wait(timeout=ANSWER_WAIT_SECONDS)
        for stream in (process.stdin, process.stdout):
            if stream and not stream.closed:
                stream.close()

    def request(self, tool: str, argv: list[str], environment: dict[str, str], **extra) -> bytes:
        """Spell one request line. Takes the tool, the arguments, the environment and other fields.
        Returns the line."""
        fields = {"tool": tool, "repo": str(self.repo), "argv": argv, "environment": environment, **extra}
        return json.dumps(fields).encode("utf-8") + b"\n"

    @staticmethod
    def ask(process: subprocess.Popen, line: bytes) -> dict:
        """Send one line and read the answer. Takes the process and the line. Returns the answer."""
        process.stdin.write(line)
        process.stdin.flush()
        return json.loads(process.stdout.readline())


class TestServeAnswersAsOneShotDoes(ServeSandbox):
    def test_several_requests_in_one_process_get_the_one_shot_answers_with_their_ids(self):
        moved = {**self.environment, "GIT_WORK_TREE": str(self.root)}
        cases = [("git", ["status"], self.environment), ("git", ["log", "-1"], self.environment),
                 ("git", ["pull"], self.environment), ("git", ["st"], self.environment),
                 ("git", ["status"], moved), ("gh", ["pr", "checkout", "1"], self.environment)]
        own = {**self._terminal("serve-home", "log -1"), "GIT_DIR": str(self.root / "elsewhere"),
               "GIT_WORK_TREE": str(self.root / "elsewhere")}
        serve = self.serving(own)
        for number, (tool, argv, environment) in enumerate(cases):
            with self.subTest(tool=tool, argv=argv, moved="GIT_WORK_TREE" in environment):
                answer = self.ask(serve, self.request(tool, argv, environment, id=f"request-{number}"))
                self.assertEqual(answer.pop("id"), f"request-{number}")
                self.assertEqual(answer, self.one_shot(tool, argv, environment))
        self.assertEqual(self.ask(serve, self.request("git", ["st"], self.environment))["subcommand"], "status")

    def test_a_repository_setting_changed_between_two_requests_is_seen(self):
        serve = self.serving(self.environment)
        self.git(self.repo, "config", "alias.sx", "status")
        before = self.ask(serve, self.request("git", ["sx"], self.environment))
        self.git(self.repo, "config", "alias.sx", "!echo changed")
        after = self.ask(serve, self.request("git", ["sx"], self.environment))
        self.assertEqual(before["subcommand"], "status")
        self.assertNotEqual(after, before)
        self.assertEqual(after, self.one_shot("git", ["sx"], self.environment))

    def test_a_malformed_line_gets_its_reason_and_the_next_line_is_answered(self):
        serve = self.serving(self.environment)
        unreadable = self.ask(serve, b"this is not json\n")
        unknown_tool = self.ask(serve, self.request("svn", ["update"], self.environment, id=7))
        no_environment = self.ask(serve, json.dumps({"tool": "git", "repo": str(self.repo),
                                                     "argv": ["status"]}).encode() + b"\n")
        answered = self.ask(serve, self.request("git", ["status"], self.environment, id=8))
        for refused in (unreadable, unknown_tool, no_environment):
            self.assertTrue(refused["reason"])
            self.assertNotIn("readable", refused)
        self.assertEqual(unknown_tool["id"], 7)
        self.assertEqual(answered.pop("id"), 8)
        self.assertEqual(answered, self.one_shot("git", ["status"], self.environment))

    def test_the_end_of_stdin_ends_saw_with_nothing_left_running(self):
        serve = self.serving(self.environment)
        self.ask(serve, self.request("git", ["status"], self.environment))
        serve.stdin.close()
        self.assertEqual(serve.wait(timeout=ANSWER_WAIT_SECONDS), 0)
        self.assertEqual(serve.stdout.read(), b"")
        if os.name != "nt":
            with self.assertRaises(ProcessLookupError):
                os.killpg(serve.pid, 0)


if __name__ == "__main__":
    unittest.main()
