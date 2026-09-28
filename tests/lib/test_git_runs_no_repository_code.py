#!/usr/bin/env python3
"""saw's git never runs code a repository configures.

Each pin builds a repository that names a program for git to run — fsmonitor, a clean filter, a
merge driver, a textconv — drives the saw call that reaches that part of git, and asserts the program
never ran: it would have created a file in the sentinel directory. The two ratchets hold the shape:
no git subprocess outside `lib/git/run.py`, and nothing outside the UNTRUSTED allowlist run there.
"""
from __future__ import annotations

import ast
import importlib
import os
import stat
import threading
import unittest
from pathlib import Path
from unittest import mock

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


class TestAStalledGitCommand(GitSandbox):
    """Check what a git command that does not answer in time becomes."""

    def test_outside_a_scan_it_answers_none(self):
        runner = importlib.import_module("stayawake.lib.git.run")
        with mock.patch.object(runner.subprocess, "run",
                               side_effect=runner.subprocess.TimeoutExpired("git", 1)):
            self.assertIsNone(runner.run(None, ["config", "--global", "--list"]))

    def test_inside_a_scan_the_repository_is_not_read_in_full(self):
        from stayawake.bots.security.scanner import scan_target
        from stayawake.bots.security.signatures import load_signatures
        from stayawake.bots.security.targets.base import ScanOptions
        from stayawake.bots.security.targets.local import LocalRepoTarget
        runner = importlib.import_module("stayawake.lib.git.run")
        repo = self.new_repo("stalled")
        self.write(repo, "a.txt", "a\n")
        self.commit(repo, "init")
        real = runner.subprocess.run

        def merges_stall(argv, *args, **kwargs):
            if "--merges" in argv:
                raise runner.subprocess.TimeoutExpired(argv, 1)
            return real(argv, *args, **kwargs)
        with mock.patch.object(runner.subprocess, "run", side_effect=merges_stall):
            result = scan_target(LocalRepoTarget(repo, str(repo), ScanOptions()),
                                 load_signatures(), [])
        self.assertTrue(result.error, "a scan whose git did not answer was called clean")

    def test_what_a_matcher_found_before_a_stall_is_kept(self):
        from stayawake.bots.security import scanner
        from stayawake.bots.security.models import Finding, Severity
        from stayawake.bots.security.targets.base import ScanOptions
        from stayawake.bots.security.targets.local import LocalRepoTarget
        runner = importlib.import_module("stayawake.lib.git.run")
        repo = self.new_repo("partial")
        self.write(repo, "a.txt", "a\n")
        self.commit(repo, "init")

        class FindsThenStalls:
            def scan(self, target, signatures):
                found = Finding("x", "c", Severity.CRITICAL, "a.txt", "d", confidence="confirmed")
                runner.run(target.root, ["rev-parse", "HEAD"])
                return [found]
        target = LocalRepoTarget(repo, str(repo), ScanOptions())
        with mock.patch.dict(scanner.REGISTRY, {"finds-then-stalls": FindsThenStalls()}), \
                mock.patch.object(runner.subprocess, "run",
                                  side_effect=runner.subprocess.TimeoutExpired("git", 1)):
            out = scanner.run_matchers(target, ["finds-then-stalls"], {"finds-then-stalls": []}, [])
        self.assertEqual(1, len(out["finds-then-stalls"]))
        self.assertTrue(target.read_errors)

    def test_a_mailmap_that_is_a_pipe_does_not_stall_a_log(self):
        repo = self.new_repo("mailmap")
        self.write(repo, "a.txt", "a\n")
        self.commit(repo, "init")
        os.mkfifo(repo / ".mailmap")
        answers = []
        reader = threading.Thread(target=lambda: answers.append(
            run(repo, ["log", "-1", "--format=%an"], timeout=20)), daemon=True)
        reader.start()
        reader.join(10)
        self.assertFalse(reader.is_alive(), "git log waited on the mailmap")
        self.assertEqual(0, answers[0].returncode)


class TestARepositoryWhoseConfigurationWaitsIsNotAsked(GitSandbox):
    """Check a repository whose configuration every git command would wait on, within one pass."""

    def setUp(self):
        super().setUp()
        self.runner = importlib.import_module("stayawake.lib.git.run")
        self.waits = self.new_repo("waits")
        self.other = self.new_repo("other")
        self.pipe = self.root / "pipe"
        os.mkfifo(self.pipe)
        self.started = []
        real = self.runner.subprocess.run

        def counted(argv, *args, **kwargs):
            self.started.append(argv)
            if argv[1:3] == ["-C", str(self.waits)] and self._includes_the_pipe():
                raise self.runner.subprocess.TimeoutExpired(argv, 1)
            return real(argv, *args, **kwargs)
        patcher = mock.patch.object(self.runner.subprocess, "run", side_effect=counted)
        patcher.start()
        self.addCleanup(patcher.stop)

    def _includes_the_pipe(self):
        return f"[include]\n\tpath = {self.pipe}" in (self.waits / ".git" / "config").read_text()

    def _include(self, text):
        with open(self.waits / ".git" / "config", "a", encoding="utf-8") as fh:
            fh.write(text)

    def _asked_in(self, repo):
        return [argv for argv in self.started if argv[1:3] == ["-C", str(repo)]]

    def test_no_command_there_starts_git(self):
        self._include(f"[include]\n\tpath = {self.pipe}\n")
        with self.runner.one_pass(), self.runner.stalls_recorded() as stalled:
            self.assertIsNone(self.runner.run(self.waits, ["rev-parse", "HEAD"]))
            self.assertIsNone(self.runner.stdout_bytes(self.waits, ["ls-files"]))
            self.assertIsNone(self.runner.stdout_bytes_fed(self.waits, ["ls-files"], b""))
        self.assertEqual([], self._asked_in(self.waits))
        self.assertEqual(3, len(stalled))
        self.assertIn(str(self.waits), stalled[0])

    def test_a_streamed_command_there_is_not_started(self):
        with mock.patch("stayawake.lib.git.exec_surface.config_waits", return_value=True), \
                mock.patch.object(self.runner.subprocess, "Popen") as popen:
            with self.runner.one_pass():
                self.assertIsNone(self.runner.open_stdout(self.other, ["ls-files"]))
        popen.assert_not_called()

    def test_a_pipe_included_from_an_included_file_counts(self):
        middle = self.root / "middle.cfg"
        middle.write_text(f"[include]\n\tpath = {self.pipe}\n")
        self._include(f"[include]\n\tpath = {middle}\n")
        with self.runner.one_pass():
            self.assertIsNone(self.runner.run(self.waits, ["rev-parse", "HEAD"]))
        self.assertEqual([], self._asked_in(self.waits))

    def test_a_pipe_named_only_under_a_condition_leaves_every_command_asked(self):
        self._include(f'[includeIf "gitdir:/no/such/place/"]\n\tpath = {self.pipe}\n')
        with self.runner.one_pass():
            answer = self.runner.run(self.waits, ["rev-parse", "HEAD"])
        self.assertEqual(1, len(self._asked_in(self.waits)))
        self.assertIsNotNone(answer)

    def test_another_repository_is_still_asked(self):
        self._include(f"[include]\n\tpath = {self.pipe}\n")
        with self.runner.one_pass():
            self.runner.run(self.waits, ["rev-parse", "HEAD"])
            answer = self.runner.run(self.other, ["rev-parse", "--git-dir"])
        self.assertEqual(0, answer.returncode)

    def test_outside_a_pass_every_command_is_asked(self):
        self._include(f"[include]\n\tpath = {self.pipe}\n")
        self.runner.run(self.waits, ["rev-parse", "HEAD"])
        self.runner.run(self.waits, ["ls-files"])
        self.assertEqual(2, len(self._asked_in(self.waits)))

    def test_a_new_pass_reads_the_configuration_again(self):
        config = (self.waits / ".git" / "config").read_text()
        self._include(f"[include]\n\tpath = {self.pipe}\n")
        with self.runner.one_pass():
            self.runner.run(self.waits, ["rev-parse", "HEAD"])
        (self.waits / ".git" / "config").write_text(config)
        with self.runner.one_pass():
            self.runner.run(self.waits, ["rev-parse", "HEAD"])
        self.assertEqual(1, len(self._asked_in(self.waits)))

    def test_a_pass_inside_a_pass_shares_its_answers(self):
        self._include(f"[include]\n\tpath = {self.pipe}\n")
        with mock.patch("stayawake.lib.git.exec_surface.config_waits",
                        return_value=True) as read:
            with self.runner.one_pass():
                self.runner.run(self.waits, ["rev-parse", "HEAD"])
                with self.runner.one_pass():
                    self.runner.run(self.waits, ["ls-files"])
        self.assertEqual(1, read.call_count)

    def test_a_scan_runs_no_git_there_and_is_not_clean(self):
        from stayawake.bots.security.scanner import scan_target
        from stayawake.bots.security.signatures import load_signatures
        from stayawake.bots.security.targets.base import ScanOptions
        from stayawake.bots.security.targets.local import LocalRepoTarget
        self.write(self.waits, "a.txt", "a\n")
        self._include(f"[include]\n\tpath = {self.pipe}\n")
        result = scan_target(LocalRepoTarget(self.waits, str(self.waits), ScanOptions()),
                             load_signatures(), [])
        self.assertTrue(result.error)
        self.assertEqual([], self._asked_in(self.waits))


class TestWhatCountsAsAConfigurationGitWouldWaitOn(GitSandbox):
    """Check which repositories are judged to make every git command wait, against git itself."""

    def setUp(self):
        super().setUp()
        from stayawake.lib.git import exec_surface
        self.waits = exec_surface.config_waits
        self.surface = exec_surface
        self.repo = self.new_repo("repo")
        self.pipe = self.root / "pipe"
        os.mkfifo(self.pipe)

    def _include(self, value, repo=None):
        with open((repo or self.repo) / ".git" / "config", "a", encoding="utf-8") as fh:
            fh.write(f"[include]\n\tpath = {value}\n")

    def test_an_included_pipe_is_certain(self):
        self._include(self.pipe)
        self.assertTrue(self.waits(self.repo))

    def test_a_relative_include_is_joined_to_the_including_file(self):
        os.mkfifo(self.repo / ".git" / "piped")
        self._include("piped")
        self.assertTrue(self.waits(self.repo))

    def test_a_relative_include_through_a_link_is_resolved_by_the_file_system(self):
        elsewhere = self.root / "elsewhere" / "inner"
        elsewhere.mkdir(parents=True)
        (self.repo / ".git" / "lnk").symlink_to(elsewhere)
        os.mkfifo(self.repo / ".git" / "x")
        self._include("lnk/../x")
        self.assertFalse(self.waits(self.repo))

    def test_a_worktree_configuration_file_is_never_counted(self):
        self.git(self.repo, "config", "extensions.worktreeConfig", "true")
        os.mkfifo(self.repo / ".git" / "config.worktree")
        self.assertFalse(self.waits(self.repo))

    def test_an_include_named_by_a_prefix_placeholder_is_not_counted(self):
        (self.repo / ".git" / "%(prefix)").mkdir()
        os.mkfifo(self.repo / ".git" / "%(prefix)" / "pipe")
        self._include("%(prefix)/pipe")
        self.assertFalse(self.waits(self.repo))

    def test_an_incomplete_git_directory_inside_a_repository_is_not_counted(self):
        sub = self.repo / "sub"
        (sub / ".git").mkdir(parents=True)
        os.mkfifo(sub / ".git" / "config")
        self.assertFalse(self.waits(sub))

    def test_a_directory_without_its_own_git_directory_is_not_counted(self):
        self._include(self.pipe)
        (self.repo / "sub").mkdir()
        self.assertFalse(self.waits(self.repo / "sub"))

    def test_a_link_into_another_repository_is_judged_by_where_it_leads(self):
        other = self.new_repo("other")
        (other / "sub").mkdir()
        self._include(self.pipe)
        (self.repo / "link").symlink_to(other / "sub")
        self.assertFalse(self.waits(self.repo / "link"))

    def test_a_git_directory_pointer_is_resolved_by_the_file_system(self):
        work = self.root / "w"
        work.mkdir()
        deep = self.root / "else2" / "deep"
        deep.mkdir(parents=True)
        (work / "lnk").symlink_to(deep)
        real = self.root / "else2" / "g"
        __import__("shutil").copytree(self.repo / ".git", real)
        fake = work / "g"
        __import__("shutil").copytree(self.repo / ".git", fake)
        (fake / "config").unlink()
        os.mkfifo(fake / "config")
        (work / ".git").write_text("gitdir: lnk/../g\n")
        self.assertFalse(self.waits(work))

    def test_a_git_directory_whose_head_git_rejects_is_not_counted(self):
        sub = self.repo / "sub"
        (sub / ".git" / "objects").mkdir(parents=True)
        (sub / ".git" / "refs").mkdir()
        (sub / ".git" / "HEAD").write_text("junk\n")
        os.mkfifo(sub / ".git" / "config")
        self.assertFalse(self.waits(sub))

    def test_includes_deeper_than_git_follows_are_not_counted(self):
        previous = self.pipe
        for i in range(self.surface.MAX_INCLUDE_DEPTH + 2):
            here = self.root / f"d{i}.cfg"
            here.write_text(f"[include]\n\tpath = {previous}\n")
            previous = here
        self._include(previous)
        self.assertFalse(self.waits(self.repo))

    def test_a_wide_include_tree_is_read_within_a_bound(self):
        count = self.surface.MAX_WAIT_FILES + 44
        for i in range(count):
            (self.root / f"n{i}.cfg").write_text("[core]\n\tx = 1\n")
            self._include(self.root / f"n{i}.cfg")
        read = []
        real = self.surface.list_config_file

        def counted(path):
            read.append(path)
            return real(path)
        with mock.patch.object(self.surface, "list_config_file", side_effect=counted):
            self.assertFalse(self.waits(self.repo))
        self.assertLessEqual(len(read), self.surface.MAX_WAIT_FILES)

    def test_reading_one_named_configuration_file_is_never_skipped(self):
        runner = importlib.import_module("stayawake.lib.git.run")
        self._include(self.pipe)
        with runner.one_pass():
            self.assertTrue(runner._not_answering(self.repo, ["rev-parse", "HEAD"]))
            for named in (["config", "--global", "--list"],
                          ["config", "--file", str(self.root / "x.cfg"), "--list"],
                          ["config", f"--file={self.root / 'x.cfg'}", "--list"]):
                self.assertFalse(runner._not_answering(self.repo, named))


class TestARepositoryWithOneSlowCommandIsStillAsked(GitSandbox):
    """Check a repository where one git command does not answer in time while git itself does."""

    def setUp(self):
        super().setUp()
        self.runner = importlib.import_module("stayawake.lib.git.run")
        self.repo = self.new_repo("large")
        self.write(self.repo, "a.txt", "a\n")
        self.commit(self.repo, "init")
        self.started = []
        real = self.runner.subprocess.run

        def one_command_is_slow(argv, *args, **kwargs):
            self.started.append(argv)
            if "--merges" in argv:
                raise self.runner.subprocess.TimeoutExpired(argv, 1)
            return real(argv, *args, **kwargs)
        patcher = mock.patch.object(self.runner.subprocess, "run", side_effect=one_command_is_slow)
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_every_timeout_leaves_the_next_command_asked(self):
        with self.runner.one_pass():
            for _ in range(3):
                self.runner.run(self.repo, ["rev-list", "--merges", "HEAD"])
        self.assertEqual(3, len([argv for argv in self.started if "--merges" in argv]))

    def test_later_commands_there_still_run(self):
        with self.runner.one_pass():
            self.assertIsNone(self.runner.run(self.repo, ["rev-list", "--merges", "HEAD"]))
            answer = self.runner.run(self.repo, ["rev-parse", "HEAD"])
        self.assertIsNotNone(answer)
        self.assertEqual(0, answer.returncode)

    def test_a_scan_still_runs_every_other_git_command(self):
        from stayawake.bots.security.scanner import scan_target
        from stayawake.bots.security.signatures import load_signatures
        from stayawake.bots.security.targets.base import ScanOptions
        from stayawake.bots.security.targets.local import LocalRepoTarget
        result = scan_target(LocalRepoTarget(self.repo, str(self.repo), ScanOptions()),
                             load_signatures(), [])
        self.assertTrue(result.error)
        after = self.started[next(i for i, argv in enumerate(self.started) if "--merges" in argv) + 1:]
        inside = [argv for argv in after
                  if argv[1:3] == ["-C", str(self.repo)] and "--git-dir" not in argv]
        self.assertTrue(inside, "no git command ran in the repository after one slow command")

if __name__ == "__main__":
    unittest.main()
