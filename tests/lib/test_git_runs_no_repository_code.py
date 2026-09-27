#!/usr/bin/env python3
"""saw's git never runs code a repository configures.

Each pin builds a repository that names a program for git to run — fsmonitor, a clean filter, a
merge driver, a textconv — drives the saw call that reaches that part of git, and asserts the program
never ran: it would have created a file in the sentinel directory. The two ratchets hold the shape:
no git subprocess outside `lib/git/run.py`, and nothing outside the UNTRUSTED allowlist run there.
"""
from __future__ import annotations

import ast
import os
import stat
import unittest
from pathlib import Path

from stayawake.lib import git as gitutil
from stayawake.lib.git import allowlist, owned
from stayawake.lib.git.borrowed import borrow
from stayawake.lib.git.contexts import child_env, UNTRUSTED, OPERATOR_PUSH
from stayawake.lib.git.merge.detect import evil_merge_paths
from stayawake.lib.git.query import introduced_added_text, file_commits, tracked_under
from stayawake.lib.git.run import GitRefused, run
from stayawake.lib.git.write.transfer import adopt_objects
from tests.support.gitrepo import GitSandbox

_SRC = Path(__file__).resolve().parents[2] / "src" / "stayawake"
_RUNNER = _SRC / "lib" / "git" / "run.py"
_RUNNER_FUNCTIONS = {"run", "run_ok", "stdout", "stdout_bytes", "stdout_bytes_fed", "open_stdout"}


def _python_files():
    return sorted(p for p in _SRC.rglob("*.py") if "__pycache__" not in p.parts)


class TestOnlyTheRunnerStartsGit(unittest.TestCase):
    """Ratchet 1: an argv that starts with "git" is built only in `lib/git/run.py`."""

    def test_no_git_argv_outside_the_runner(self):
        found = []
        for path in _python_files():
            if path == _RUNNER:
                continue
            for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
                if (isinstance(node, (ast.List, ast.Tuple)) and node.elts
                        and isinstance(node.elts[0], ast.Constant) and node.elts[0].value == "git"):
                    found.append(f"{path.relative_to(_SRC)}:{node.lineno}")
        self.assertEqual([], found, "a git subprocess is started outside lib/git/run.py")


def _context_of(call: ast.Call) -> str:
    for kw in call.keywords:
        if kw.arg == "context":
            value = kw.value
            return value.attr if isinstance(value, ast.Attribute) else getattr(value, "id", "?")
    return "UNTRUSTED"


def _literal_args(call: ast.Call) -> list[str] | None:
    if len(call.args) < 2 or not isinstance(call.args[1], (ast.List, ast.Tuple)):
        return None
    out = []
    for elt in call.args[1].elts:
        if isinstance(elt, ast.Constant) and isinstance(elt.value, str):
            out.append(elt.value)
        else:
            break
    return out


class TestUntrustedCallsAreAllowed(unittest.TestCase):
    """Ratchet 2: every subcommand a call site runs as UNTRUSTED is on the allowlist."""

    def test_every_untrusted_subcommand_literal_is_allowed(self):
        refused = []
        for path in _python_files():
            if path.parent == _RUNNER.parent and path.name in ("run.py", "allowlist.py"):
                continue
            for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
                if not isinstance(node, ast.Call):
                    continue
                name = getattr(node.func, "attr", None) or getattr(node.func, "id", None)
                if name not in _RUNNER_FUNCTIONS or _context_of(node) != "UNTRUSTED":
                    continue
                args = _literal_args(node)
                if not args:
                    continue
                _globals, sub, _rest = allowlist.split(args)
                if sub and not sub.startswith("-") and sub not in allowlist.UNTRUSTED_SUBCOMMANDS:
                    refused.append(f"{path.relative_to(_SRC)}:{node.lineno} git {sub}")
        self.assertEqual([], refused, "a call site runs a driver-capable subcommand as UNTRUSTED")


def _sentinel_program(root: Path, name: str) -> str:
    """A program that leaves `<root>/ran/<name>` behind, and passes stdin through."""
    ran = root / "ran"
    ran.mkdir(exist_ok=True)
    script = root / f"{name}.sh"
    script.write_text(f"#!/bin/sh\ntouch '{ran / name}'\ncat\n", encoding="utf-8")
    script.chmod(script.stat().st_mode | stat.S_IXUSR)
    return str(script)


class HostileRepo(GitSandbox):

    def ran(self) -> list[str]:
        where = self.root / "ran"
        return sorted(os.listdir(where)) if where.is_dir() else []

    def configure(self, repo: Path, text: str) -> None:
        with open(repo / ".git" / "config", "a", encoding="utf-8") as fh:
            fh.write(text)

    def conflicting_merge(self, repo: Path) -> str:
        self.write(repo, "f.txt", "base\n")
        self.commit(repo, "base")
        self.git(repo, "checkout", "-q", "-b", "side")
        self.write(repo, "f.txt", "side\n")
        self.commit(repo, "side")
        self.git(repo, "checkout", "-q", "main")
        self.write(repo, "f.txt", "main\n")
        self.commit(repo, "main")
        self.git_may_fail(repo, "merge", "-q", "side")
        self.write(repo, "f.txt", "resolved\n")
        self.git(repo, "add", "-A")
        self.git(repo, "commit", "-qm", "merge")
        return self.rev(repo)


class TestNoRepositoryProgramRuns(HostileRepo):

    def test_fsmonitor_does_not_run_on_a_query(self):
        repo = self.new_repo()
        self.write(repo, "a.txt", "a\n")
        self.commit(repo, "a")
        self.configure(repo, f"[core]\n\tfsmonitor = {_sentinel_program(self.root, 'fsmonitor')}\n")
        tracked_under(repo, ".")
        self.assertEqual([], self.ran())

    def test_a_clean_filter_is_never_reached(self):
        repo = self.new_repo()
        self.write(repo, "a.txt", "a\n")
        self.write(repo, ".gitattributes", "* filter=evil\n")
        self.commit(repo, "a")
        self.configure(repo, f'[filter "evil"]\n\tclean = {_sentinel_program(self.root, "clean")}\n')
        self.write(repo, "a.txt", "changed\n")
        for args in (["diff", "HEAD"], ["hash-object", "a.txt"], ["status"]):
            with self.subTest(args=args), self.assertRaises(GitRefused):
                run(repo, args)
        self.assertEqual([], self.ran())

    def _merge_driver_case(self, driver_name: str):
        repo = self.new_repo()
        self.write(repo, ".gitattributes", f"* merge={driver_name}\n")
        self.git(repo, "add", "-A")
        self.git(repo, "commit", "-qm", "attrs")
        merge = self.conflicting_merge(repo)
        program = _sentinel_program(self.root, "merge")
        self.configure(repo, f'[merge "{driver_name}"]\n\tdriver = {program} %O %A %B\n')
        self.git_may_fail(repo, "merge-tree", "--write-tree", f"{merge}^1", f"{merge}^2")
        self.assertEqual(["merge"], self.ran(), "the fixture does not reach the driver")
        os.remove(self.root / "ran" / "merge")
        evil_merge_paths(repo, merge)
        self.assertEqual([], self.ran())

    def test_a_merge_driver_does_not_run_when_a_merge_is_replayed(self):
        self._merge_driver_case("evil")

    def test_a_merge_driver_whose_name_holds_an_equals_sign_does_not_run(self):
        self._merge_driver_case("a=b")

    def test_textconv_does_not_run_on_an_introduced_hunk(self):
        repo = self.new_repo()
        self.write(repo, ".gitattributes", "*.txt diff=evil\n")
        self.write(repo, "f.txt", "one\n")
        base = self.commit(repo, "one")
        self.write(repo, "f.txt", "one\ntwo\n")
        head = self.commit(repo, "two")
        self.configure(repo, f'[diff "evil"]\n\ttextconv = {_sentinel_program(self.root, "tc")}\n')
        self.assertEqual("two", introduced_added_text(repo, base, head, "f.txt"))
        self.assertEqual([], self.ran())

    def test_a_path_is_never_read_as_pathspec_magic(self):
        repo = self.new_repo()
        self.write(repo, "a.js", "a\n")
        self.commit(repo, "a.js")
        self.assertEqual([], file_commits(repo, "*.js"))
        self.assertEqual([], file_commits(repo, ":(glob)**"))


class TestContexts(HostileRepo):

    def test_an_inherited_repository_location_is_dropped(self):
        env = child_env(UNTRUSTED, dict(os.environ, GIT_DIR="/elsewhere"))
        self.assertIn("GIT_DIR", env, "an explicitly passed GIT_DIR must survive")
        os.environ["GIT_DIR"] = "/elsewhere"
        try:
            self.assertNotIn("GIT_DIR", child_env(UNTRUSTED, None))
            self.assertNotIn("GIT_DIR", child_env(UNTRUSTED, dict(os.environ)))
        finally:
            del os.environ["GIT_DIR"]
        self.assertEqual(os.devnull, child_env(UNTRUSTED, None)["GIT_CONFIG_GLOBAL"])

    def test_a_network_command_never_runs_in_a_repository_saw_did_not_make(self):
        repo = self.new_repo()
        with self.assertRaises(GitRefused):
            run(repo, ["ls-remote", "origin"], context=OPERATOR_PUSH)
        with self.assertRaises(GitRefused):
            run(repo, ["ls-remote", "origin"])

    def test_a_caller_cannot_put_back_what_a_context_overrides(self):
        repo = self.new_repo()
        with self.assertRaises(GitRefused):
            run(repo, ["-c", "core.fsmonitor=/bin/sh", "rev-parse", "HEAD"])


class TestBorrowed(HostileRepo):

    def test_materialise_writes_the_stored_bytes(self):
        repo = self.new_repo()
        self.write(repo, ".gitattributes", "* text eol=crlf ident filter=evil\n")
        self.write(repo, "f.txt", "a\n$Id$\n")
        tip = self.commit(repo, "f")
        self.configure(repo, f'[filter "evil"]\n\tsmudge = {_sentinel_program(self.root, "sm")}\n')
        dest = self.owned(self.root / "out")
        dest.mkdir()
        with borrow(repo) as borrowed:
            self.assertTrue(borrowed.materialise(tip, dest))
        self.assertEqual(b"a\n$Id$\n", (dest / "f.txt").read_bytes())
        self.assertEqual([], self.ran())

    def test_published_objects_are_usable_by_the_operator_repository(self):
        repo = self.new_repo()
        merge = self.conflicting_merge(repo)
        a, b = self.git(repo, "rev-list", "--parents", "-n1", merge).split()[1:]
        with borrow(repo) as borrowed:
            merged = borrowed.merge_tree(a, b)
            self.assertIsNotNone(merged)
            self.assertEqual("", adopt_objects(repo, borrowed.path, [merged.tree], [a, b]))
            bare = borrowed.path
        self.assertFalse(owned.is_owned(bare))
        self.assertEqual("tree", self.git(repo, "cat-file", "-t", merged.tree).strip())

    def test_the_replay_reads_the_checkouts_attributes(self):
        repo = self.new_repo()
        self.write(repo, "log.md", "a\n")
        self.write(repo, ".gitattributes", "log.md merge=union\n")
        self.commit(repo, "base")
        self.git(repo, "checkout", "-q", "-b", "side")
        self.write(repo, "log.md", "a\nside\n")
        self.commit(repo, "side")
        self.git(repo, "checkout", "-q", "main")
        self.write(repo, "log.md", "a\nmain\n")
        self.commit(repo, "main")
        with borrow(repo) as borrowed:
            merged = borrowed.merge_tree(self.rev(repo, "main"), self.rev(repo, "side"))
        self.assertIsNotNone(merged)
        self.assertEqual(frozenset(), merged.conflicted)


if __name__ == "__main__":
    unittest.main()
