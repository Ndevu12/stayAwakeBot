#!/usr/bin/env python3
"""`saw govern classify` answers for a plain repository within a fixed number of git runs, and still
reads every settings file and every view of a repository: an include reached by two spellings, a
conditional include, the settings of each linked worktree, and a file changed between two answers."""
from __future__ import annotations

import json
import os
import subprocess
import sys
import unittest
from pathlib import Path

import stayawake
from stayawake.bots.security import govern
from stayawake.lib.git.run import real_git
from tests.support.gitrepo import GitSandbox

SOURCE = str(Path(stayawake.__file__).resolve().parent.parent)
SANDBOX_SETTING_FILES = ("GIT_CONFIG_GLOBAL", "GIT_CONFIG_SYSTEM", "GIT_CONFIG_NOSYSTEM")
"""The variables the sandbox names its settings files with, which an operator's terminal does not
set and which make saw check every command."""
GIT_RUNS_FOR_A_PLAIN_REPOSITORY = {("status",): 8, ("log", "-1"): 8, ("pull",): 0}
"""The most git runs one answer takes in a repository with no linked worktree or submodule."""


class FewGitRunsSandbox(GitSandbox):
    """Repositories built with real git, and the environment an operator's terminal runs commands
    with."""

    def setUp(self):
        super().setUp()
        self.program = self.owned(self.root / "planted")
        self.program.write_text("#!/bin/sh\n", encoding="utf-8")
        home = self.owned(self.root / "home")
        home.mkdir()
        self.environment = {**{key: value for key, value in os.environ.items() if key not in SANDBOX_SETTING_FILES},
                            "HOME": str(home), "XDG_CONFIG_HOME": str(home / ".config")}

    def plain(self, name: str = "repo") -> Path:
        """Make a repository with one commit. Takes its name. Returns it."""
        repo = self.new_repo(name)
        self.write(repo, "README.md", "hello\n")
        self.commit(repo, "first")
        return repo

    def run_with_keys(self, folder: Path, *args: str) -> list[str]:
        """Ask classify how to run a git command. Takes the folder and the arguments. Returns the
        keys of the settings its answer runs the command with."""
        answer, _code = govern.classify(str(folder), "git", list(args), dict(self.environment))
        self.assertFalse(answer["checked"], answer)
        return [setting["key"] for setting in answer["run_with"]["settings"]]


class TestAPlainRepositoryTakesFewGitRuns(FewGitRunsSandbox):
    @unittest.skipIf(os.name == "nt", "the counting git is a shell script")
    def test_each_answer_takes_at_most_its_git_runs(self):
        repo = self.plain()
        counting = self.owned(self.root / "counting")
        counting.mkdir()
        log = self.owned(self.root / "git-runs.log")
        git = counting / "git"
        git.write_text(f'#!/bin/sh\necho run >> "{log}"\nexec "{real_git()}" "$@"\n', encoding="utf-8")
        git.chmod(0o755)
        environment = {**self.environment, "PYTHONPATH": SOURCE,
                       "PATH": f"{counting}{os.pathsep}{self.environment['PATH']}"}
        for args, most in GIT_RUNS_FOR_A_PLAIN_REPOSITORY.items():
            with self.subTest(args=args):
                log.write_text("", encoding="utf-8")
                done = subprocess.run([sys.executable, "-m", "stayawake", "govern", "classify", "--json", "--tool",
                                       "git", "--repo", str(repo), "--", *args], env=environment,
                                      capture_output=True, stdin=subprocess.DEVNULL, timeout=120, check=False)
                self.assertIn("readable", json.loads(done.stdout))
                self.assertLessEqual(len(log.read_text(encoding="utf-8").splitlines()), most)


class TestEverySettingIsStillRead(FewGitRunsSandbox):
    def test_an_include_reached_by_two_spellings_and_its_own_include_are_read(self):
        repo = self.plain()
        git_dir = repo / ".git"
        self.write(git_dir, "extra.cfg", f"[core]\n\tpager = {self.program}\n[include]\n\tpath = deeper.cfg\n")
        self.write(git_dir, "deeper.cfg", f"[diff]\n\texternal = {self.program}\n")
        os.symlink(git_dir / "extra.cfg", git_dir / "extra-link.cfg")
        self.git(repo, "config", "--add", "include.path", "extra.cfg")
        self.git(repo, "config", "--add", "include.path", str(git_dir / "extra-link.cfg"))
        keys = self.run_with_keys(repo, "status")
        self.assertIn("core.pager", keys)
        self.assertIn("diff.external", keys)

    def test_a_conditional_include_that_applies_is_read(self):
        repo = self.plain("inc-if")
        self.write(repo / ".git", "cond.cfg", f"[core]\n\teditor = {self.program}\n")
        self.git(repo, "config", "includeIf.gitdir:**/inc-if/**.path", "cond.cfg")
        self.assertIn("core.editor", self.run_with_keys(repo, "status"))

    def test_every_linked_worktree_s_own_settings_are_read(self):
        repo = self.plain()
        self.git(repo, "config", "extensions.worktreeConfig", "true")
        self.git(repo, "branch", "a")
        self.git(repo, "branch", "b")
        first, second = self.owned(self.root / "wt-a"), self.owned(self.root / "wt-b")
        self.git(repo, "worktree", "add", "-q", str(first), "a")
        self.git(repo, "worktree", "add", "-q", str(second), "b")
        self.git(first, "config", "--worktree", "core.fsmonitor", str(self.program))
        self.git(second, "config", "--worktree", "core.sshCommand", str(self.program))
        for folder in (repo, first, second):
            with self.subTest(folder=folder.name):
                keys = self.run_with_keys(folder, "status")
                self.assertIn("core.fsmonitor", keys)
                self.assertIn("core.sshcommand", keys)

    def test_a_settings_file_changed_between_two_answers_is_read_again(self):
        repo = self.plain()
        before = self.run_with_keys(repo, "status")
        self.git(repo, "config", "core.fsmonitor", str(self.program))
        after = self.run_with_keys(repo, "status")
        self.assertNotIn("core.fsmonitor", before)
        self.assertIn("core.fsmonitor", after)


if __name__ == "__main__":
    unittest.main()
