#!/usr/bin/env python3
"""Every git command that can bring files into the folder is checked or left to the operator,
however it is spelled, and a command that brings none runs as typed."""
from __future__ import annotations

import os
import unittest
from pathlib import Path
from unittest import mock

from stayawake.bots.security import govern
from stayawake.lib.git import incoming
from stayawake.utils import exitcodes
from tests.bots.security.test_govern_replays_a_tracking_checkout import _TrackingCheckout
from tests.support import samples

_LOADER = 'var _0x=[String.%s(127)];eval(_0x.join(""));\n' % samples.FROM_CHAR_CODE


class WhatACommandBrings(unittest.TestCase):

    def test_a_command_that_lands_another_commit_is_checked(self):
        for kind, args in (("reset", ["reset", "--hard", "origin/evil"]),
                           ("reset", ["reset", "origin/evil", "--hard"]),
                           ("reset", ["reset", "-q", "--keep", "origin/evil"]),
                           ("reset", ["reset", "--merge", "origin/evil"]),
                           ("reset", ["reset", "--soft", "--hard", "--end-of-options", "origin/evil"]),
                           ("reset", ["-C", ".", "reset", "--hard", "origin/evil"]),
                           ("cherry-pick", ["cherry-pick", "origin/evil"]),
                           ("cherry-pick", ["cherry-pick", "-x", "-m", "1", "origin/evil"]),
                           ("cherry-pick", ["cherry-pick", "-n", "--commit", "origin/evil"]),
                           ("revert", ["revert", "--no-edit", "origin/evil"]),
                           ("checkout", ["checkout", "-m", "origin/evil"]),
                           ("checkout", ["checkout", "--recurse-submodules", "origin/evil"]),
                           ("checkout", ["checkout", "--orphan", "x", "origin/evil"]),
                           ("checkout", ["checkout", "-qt", "origin/evil"]),
                           ("switch", ["switch", "-m", "origin/evil"]),
                           ("checkout", ["--attr-source", "HEAD", "checkout", "origin/evil"]),
                           ("checkout", ["--namespace", "n", "checkout", "origin/evil"]),
                           ("merge", ["--shallow-file", "s", "merge", "origin/evil"])):
            with self.subTest(args=args):
                self.assertEqual(incoming.classify("git", args), kind)
                self.assertFalse(incoming.brings_nothing("git", args))

    def test_a_command_that_brings_files_saw_does_not_replay_is_left_to_the_operator(self):
        for args in (["restore", "--source", "origin/evil", "-S", "-W", "."], ["restore", "-sorigin/evil", "."],
                     ["restore", "-Ws", "origin/evil", "."], ["restore", "--source=origin/evil", "--", "."],
                     ["read-tree", "-u", "--reset", "origin/evil"], ["read-tree", "-mu", "HEAD", "origin/evil"],
                     ["cherry-pick", "-n", "origin/evil"], ["revert", "--no-commit", "origin/evil"],
                     ["cherry-pick", "--continue"], ["worktree", "add", "../wt", "origin/evil"],
                     ["worktree", "add", "../evil"], ["stash", "apply"], ["stash", "pop", "--index"],
                     ["stash", "branch", "b"], ["submodule", "add", "https://example.invalid/r"],
                     ["submodule", "foreach", "git", "pull"], ["reset", "origin/evil", "--", "a.txt"],
                     ["restore", "-S", "--source", "origin/evil", "a.txt"], ["read-tree", "origin/evil"],
                     ["update-ref", "refs/heads/main", "origin/evil"], ["update-ref", "--stdin"],
                     ["update-index", "--index-info"], ["checkout", "--recurse-submodules", "--", "a.txt"],
                     ["-c", "submodule.recurse", "restore", "a.txt"],
                     ["clone", "https://example.invalid/r"], ["co", "origin/evil"], ["chekout", "origin/evil"],
                     ["reset", "--ha", "origin/evil"], ["restore", "--sou", "origin/evil", "."],
                     ["--git-dir=elsewhere/.git", "reset", "--hard", "origin/evil"],
                     ["--work-tree", "elsewhere", "checkout", "origin/evil"]):
            with self.subTest(args=args):
                self.assertIsNone(incoming.classify("git", args))
                self.assertFalse(incoming.brings_nothing("git", args))

    def test_a_command_that_brings_no_files_runs_as_typed(self):
        for args in (["reset"], ["reset", "HEAD~1"], ["reset", "--soft", "HEAD~1"], ["reset", "--hard"],
                     ["reset", "--hard", "HEAD"], ["reset", "-q", "HEAD", "--", "a.txt"], ["reset", "-p"],
                     ["restore", "a.txt"], ["restore", "--staged", "a.txt"],
                     ["restore", "-S", "--source", "HEAD~1", "a.txt"], ["read-tree", "HEAD"],
                     ["read-tree", "-mun", "HEAD", "origin/evil"], ["stash"], ["stash", "-m", "pop"],
                     ["stash", "list"], ["worktree", "list"], ["worktree", "remove", "../wt"], ["submodule"],
                     ["submodule", "status"], ["checkout", "--orphan", "fresh"], ["checkout", "--", "a.txt"],
                     ["switch", "-c", "try"], ["switch", "--orphan", "fresh"],
                     ["--git-dir=.git", "checkout", "--", "a.txt"], ["update-ref", "-d", "refs/heads/old"],
                     ["update-ref", "refs/heads/here", "HEAD"], ["update-index", "--refresh"],
                     ["checkout", "--recurse-submodules", "--no-recurse-submodules", "--", "a.txt"]):
            with self.subTest(args=args):
                self.assertTrue(incoming.brings_nothing("git", args))
                self.assertIsNone(incoming.classify("git", args))

    def test_an_interactive_pull_rebase_spelled_short_runs_other_commands(self):
        for args, runs in ((["-ri"], True), (["-rinteractive", "origin"], True), (["-r"], False),
                           (["-rtrue", "origin"], False)):
            with self.subTest(args=args):
                self.assertEqual(incoming.runs_other_commands("pull", args), runs)

    def test_a_github_command_that_names_its_repository_is_checked(self):
        for args in (["-R", "owner/repo", "pr", "checkout", "7"], ["--repo", "owner/repo", "repo", "sync"],
                     ["pr", "checkout", "-R", "owner/repo", "7"], ["--repo=owner/repo", "release", "download"]):
            with self.subTest(args=args):
                self.assertEqual(incoming.classify("gh", args), "gh")

    def test_a_repository_named_in_the_environment_is_left_to_the_operator(self):
        for variable in ("GIT_DIR", "GIT_WORK_TREE", "GIT_INDEX_FILE", "GIT_OBJECT_DIRECTORY"):
            with self.subTest(variable=variable), mock.patch.dict(os.environ, {variable: "elsewhere"}):
                self.assertIsNone(incoming.classify("git", ["checkout", "origin/evil"]))
                self.assertIsNone(incoming.classify("git", ["reset", "--hard", "origin/evil"]))


class ACommandThatLandsACommit(_TrackingCheckout):
    """A checkout tracking an upstream that has a clean commit on main and an infected one on evil."""

    def setUp(self):
        super().setUp()
        self.git(self.upstream, "checkout", "-q", "-b", "evil")
        self.write(self.upstream, "loader.js", _LOADER)
        self.commit(self.upstream, "worm")
        self.git(self.upstream, "rm", "-q", "loader.js")
        self.commit(self.upstream, "worm removed")
        self.git(self.upstream, "checkout", "-q", "main")
        self.git(self.open, "fetch", "-q")
        self.start = self.rev(self.open)

    def _prepare(self, *args: str) -> tuple[dict, int]:
        return govern.prepare(str(self.open), str(self.into), "git", list(args))

    def _blob(self, text: str) -> str:
        source = self.root / "staged-content"
        source.write_text(text, encoding="utf-8")
        return self.git(self.open, "hash-object", "-w", str(source)).strip()

    def _held(self, *args: str) -> None:
        answer, code = self._prepare(*args)
        self.assertEqual(code, exitcodes.FINDINGS, answer)
        self.assertEqual(answer["scan"]["results"][0]["verdict"], "infected", answer)
        self.assertEqual(self.rev(self.open), self.start)
        self.assertFalse((self.open / "loader.js").exists())
        self.assertFalse(govern.apply(str(self.open), str(self.into))[0]["applied"])
        self.assertEqual(self.rev(self.open), self.start)
        self.assertFalse((self.open / "loader.js").exists())

    def test_an_infected_reset_hard_is_held_and_the_folder_stays_as_it_was(self):
        self._held("reset", "--hard", "origin/evil~1")

    def test_an_infected_cherry_pick_and_revert_are_held(self):
        for args in (["cherry-pick", "origin/evil~1"], ["revert", "--no-edit", "origin/evil"]):
            with self.subTest(args=args):
                self._held(*args)

    def test_a_clean_reset_hard_moves_the_branch_and_the_files(self):
        answer, code = self._prepare("reset", "--hard", "origin/main")
        self.assertEqual(code, exitcodes.CLEAN, answer)
        self.assertEqual(govern.apply(str(self.open), str(self.into))[0], {"applied": True})
        self.assertEqual(self.rev(self.open), self.rev(self.open, "origin/main"))
        self.assertEqual(self.git(self.open, "branch", "--show-current").strip(), "main")
        self.assertEqual((self.open / "new.txt").read_text(encoding="utf-8"), "new\n")

    def test_a_clean_cherry_pick_lands_as_a_new_commit_on_the_branch(self):
        answer, code = self._prepare("cherry-pick", "origin/main")
        self.assertEqual(code, exitcodes.CLEAN, answer)
        self.assertEqual(govern.apply(str(self.open), str(self.into))[0], {"applied": True})
        self.assertEqual(self.rev(self.open, "HEAD~1"), self.start)
        self.assertEqual(self.git(self.open, "branch", "--show-current").strip(), "main")
        self.assertTrue((self.open / "new.txt").is_file())

    def test_a_command_saw_does_not_replay_is_left_to_the_operator_with_the_folder_unchanged(self):
        for args in (["restore", "--source", "origin/evil~1", "."], ["stash", "pop"], ["co", "origin/evil~1"]):
            with self.subTest(args=args):
                answer, code = self._prepare(*args)
                self.assertEqual(code, exitcodes.INCOMPLETE, answer)
                self.assertEqual(answer["reason"], "saw does not check that command")
                self.assertEqual(answer["decision"]["choices"], ["run-as-typed", "leave-unchanged"])
                self.assertFalse((self.open / "loader.js").exists())

    def test_a_reset_that_keeps_the_files_runs_as_typed(self):
        for args in (["reset", "--soft", "HEAD"], ["reset", "--hard"], ["reset", "--", "kept.txt"],
                     ["reset", "origin/feature"], ["reset", "kept.txt"]):
            with self.subTest(args=args):
                answer, code = self._prepare(*args)
                self.assertEqual((answer.get("passthrough"), code), (True, exitcodes.CLEAN), answer)
                self.assertNotIn("scan", answer)

    def test_moving_head_to_an_infected_commit_then_resetting_the_files_lands_nothing(self):
        answer, code = self._prepare("reset", "--soft", "origin/evil~1")
        self.assertEqual(code, exitcodes.FINDINGS, answer)
        self.assertNotIn("passthrough", answer)
        self.assertNotIn("decision", answer)
        self.assertEqual(self.rev(self.open), self.start)
        self.assertEqual(self._prepare("reset", "--hard")[0].get("passthrough"), True)
        self.git(self.open, "reset", "-q", "--hard")
        self.assertFalse((self.open / "loader.js").exists())

    def test_moving_head_to_a_clean_commit_outside_its_history_runs_as_typed_after_its_check(self):
        answer, code = self._prepare("reset", "origin/main")
        self.assertEqual((answer.get("passthrough"), code), (True, exitcodes.CLEAN), answer)
        self.assertEqual(answer["scan"]["results"][0]["verdict"], "clean")

    def test_staging_a_blob_is_checked_and_an_infected_one_is_held(self):
        clean = self._blob("mine\n")
        answer, code = self._prepare("update-index", "--add", "--cacheinfo", "100644", clean, "kept.txt")
        self.assertEqual((answer.get("passthrough"), code), (True, exitcodes.CLEAN), answer)
        infected = self._blob(_LOADER)
        for args in (["update-index", "--add", "--cacheinfo", "100644", infected, "loader.js"],
                     ["update-index", "--add", f"--cacheinfo=100644,{infected},loader.js"]):
            with self.subTest(args=args):
                answer, code = self._prepare(*args)
                self.assertEqual(code, exitcodes.FINDINGS, answer)
                self.assertNotIn("passthrough", answer)
                self.assertNotIn("decision", answer)

    def test_a_command_that_would_update_submodules_is_left_to_the_operator(self):
        self.assertEqual(self._prepare("checkout", "--recurse-submodules", "--", "kept.txt")[0].get("passthrough"),
                         True)
        (self.open / ".gitmodules").write_text('[submodule "sub"]\n\tpath = sub\n\turl = ../sub\n', encoding="utf-8")
        for args in (["checkout", "--recurse-submodules", "--", "kept.txt"],
                     ["-c", "submodule.recurse=true", "reset", "--hard"]):
            with self.subTest(args=args):
                answer, _code = self._prepare(*args)
                self.assertNotIn("passthrough", answer)
                self.assertEqual(answer["decision"]["choices"], ["run-as-typed", "leave-unchanged"])
        self.git(self.open, "config", "submodule.recurse", "true")
        self.assertNotIn("passthrough", self._prepare("restore", "kept.txt")[0])
        self.assertEqual(self._prepare("restore", "--no-recurse-submodules", "kept.txt")[0].get("passthrough"), True)

    def test_a_repository_named_in_the_environment_is_left_to_the_operator(self):
        with mock.patch.dict(os.environ, {"GIT_DIR": str(self.open / ".git")}):
            answer, _code = self._prepare("reset", "--hard", "origin/evil~1")
        self.assertEqual(answer["reason"], "saw does not check that command")
        self.assertFalse((self.open / "loader.js").exists())

    def test_after_a_clone_or_a_new_worktree_runs_as_typed_the_folder_it_creates_is_scanned(self):
        for created, args in (("tool", ["clone", "https://example.invalid/team/tool.git"]),
                              ("tool.git", ["clone", "--bare", "https://example.invalid/team/tool.git/"]),
                              ("dest", ["clone", "-o", "upstream", "https://example.invalid/team/tool", "dest"]),
                              ("../wt", ["worktree", "add", "-b", "try", "../wt", "origin/main"])):
            with self.subTest(args=args):
                answer, _code = self._prepare(*args)
                self.assertEqual(answer["decision"]["scan_after"], ["saw", "scan", str(Path(self.open) / created)])
        answer, _code = self._prepare("stash", "pop")
        self.assertEqual(answer["decision"]["scan_after"], ["saw", "scan", str(self.open)])


if __name__ == "__main__":
    unittest.main()
