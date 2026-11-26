#!/usr/bin/env python3
"""In a mirror clone or any other repository with no working tree, git runs as typed. A command
that creates or writes a working tree is still checked, and a fetch saw writes itself brings what
git would."""
from __future__ import annotations

import os
import subprocess

from stayawake.bots.security import govern
from stayawake.lib.git import replay
from stayawake.utils import exitcodes
from tests.support.gitrepo import GitSandbox
from tests.support.local_remotes import allow_local_remotes


class _Mirrored(GitSandbox):
    """An upstream, a mirror clone and a bare clone of it, and an upstream that then moved on: a new
    commit on main, a new branch, and a branch it deleted."""

    def setUp(self):
        super().setUp()
        allow_local_remotes(self)
        self.upstream = self.new_repo("upstream")
        self.write(self.upstream, "kept.txt", "kept\n")
        self.commit(self.upstream, "start")
        self.git(self.upstream, "branch", "gone")
        self.mirror = self.owned(self.root / "mirror.git")
        self.bare = self.owned(self.root / "bare.git")
        self._raw("clone", "-q", "--mirror", str(self.upstream), str(self.mirror))
        self._raw("clone", "-q", "--bare", str(self.upstream), str(self.bare))
        self.write(self.upstream, "new.txt", "new\n")
        self.arrived = self.commit(self.upstream, "arrives")
        self.git(self.upstream, "branch", "side")
        self.git(self.upstream, "branch", "-D", "gone")
        self.into = self.root / "holding"

    def _raw(self, *args: str, env: "dict | None" = None) -> subprocess.CompletedProcess:
        return subprocess.run(["git", *args], cwd=self.root, check=True, capture_output=True, text=True,
                              stdin=subprocess.DEVNULL, env={**os.environ, **(env or {})})

    def _prepare(self, where, *args: str, environment: "dict | None" = None, brings_no_files: bool = False):
        return govern.prepare(str(where), str(self.into), "git", list(args), environment=environment,
                              brings_no_files=brings_no_files)

    def _runs_as_typed(self, where, *args: str, environment: "dict | None" = None,
                       brings_no_files: bool = False) -> None:
        answer, code = self._prepare(where, *args, environment=environment, brings_no_files=brings_no_files)
        self.assertEqual((answer.get("passthrough"), code), (True, exitcodes.CLEAN), answer)

    def _governed(self, where, *args: str, environment: "dict | None" = None) -> dict:
        answer, _code = self._prepare(where, *args, environment=environment)
        self.assertNotIn("passthrough", answer)
        return answer

    def _has(self, repository, commit: str) -> bool:
        return self.git_may_fail(repository, "cat-file", "-e", f"{commit}^{{commit}}").returncode == 0


class ARepositoryWithNoWorkingTreeRunsGitAsTyped(_Mirrored):

    def test_a_fetch_by_commit_into_a_mirror_writes_fetch_head_and_brings_the_objects(self):
        self.assertFalse(self._has(self.mirror, self.arrived))
        self._runs_as_typed(self.mirror, "fetch", str(self.upstream), self.arrived)
        self.git(self.mirror, "fetch", "-q", str(self.upstream), self.arrived)
        fetch_head = (self.mirror / "FETCH_HEAD").read_text(encoding="utf-8")
        self.assertTrue(fetch_head.startswith(self.arrived), fetch_head)
        self.assertTrue(self._has(self.mirror, self.arrived))

    def test_fetch_prune_origin_refreshes_a_mirror(self):
        self._runs_as_typed(self.mirror, "fetch", "--prune", "origin")
        self.git(self.mirror, "fetch", "-q", "--prune", "origin")
        listed = self.git(self.mirror, "for-each-ref", "--format=%(refname) %(objectname)", "refs/heads")
        self.assertEqual(listed.split("\n"), [f"refs/heads/main {self.arrived}", f"refs/heads/side {self.arrived}", ""])

    def test_a_plain_bare_repository_runs_as_typed_however_it_is_named(self):
        empty = self.owned(self.root / "empty.git")
        self._raw("init", "-q", "--bare", str(empty))
        for where, args, environment in (
                (self.bare, ["fetch", str(self.upstream), self.arrived], None),
                (empty, ["fetch", str(self.upstream), self.arrived], None),
                (self.bare, ["fetch", "origin"], None),
                (self.root, ["--git-dir", str(self.bare), "fetch", "origin"], None),
                (self.root, [f"--git-dir={self.mirror}", "fetch", "--prune", "origin"], None),
                (self.root, ["fetch", "origin"], {"GIT_DIR": str(self.mirror)}),
                (self.mirror, ["--bare", "fetch", "origin"], None),
                (self.mirror, ["update-ref", "refs/heads/main", self.arrived], None)):
            with self.subTest(args=args, environment=environment):
                self._runs_as_typed(where, *args, environment=environment)

    def test_a_remote_update_in_a_mirror_runs_as_typed(self):
        self._runs_as_typed(self.mirror, "remote", "update", brings_no_files=True)
        self._runs_as_typed(self.mirror, "maintenance", "run", "--task=prefetch", brings_no_files=True)


class ACommandThatCreatesOrWritesAWorkingTreeIsStillChecked(_Mirrored):

    def test_a_working_tree_it_creates_or_is_given_is_checked(self):
        files = self.owned(self.root / "files")
        files.mkdir()
        for where, args, environment in (
                (self.mirror, ["worktree", "add", str(self.root / "wt"), "main"], None),
                (self.mirror, ["clone", str(self.mirror), str(self.root / "copy")], None),
                (self.root, [f"--git-dir={self.mirror}", f"--work-tree={files}", "checkout", "-f", "main"], None),
                (self.root, ["checkout", "-f", "main"], {"GIT_DIR": str(self.mirror), "GIT_WORK_TREE": str(files)}),
                (files, [f"--git-dir={self.mirror}", "--work-tree=.", "read-tree", "-u", "--reset", "main"], None)):
            with self.subTest(args=args, environment=environment):
                self.assertIn("decision", self._governed(where, *args, environment=environment))
        self.assertEqual(sorted(os.listdir(files)), [])
        self.assertFalse((self.root / "wt").exists() or (self.root / "copy").exists())

    def test_a_repository_with_no_working_tree_among_a_checkouts_files_is_checked(self):
        checkout = self.owned(self.root / "checkout")
        self._raw("clone", "-q", str(self.upstream), str(checkout))
        vendored = checkout / "vendor" / "x.git"
        self._raw("clone", "-q", "--bare", str(self.upstream), str(vendored))
        self.assertIn("decision", self._governed(vendored, "fetch", "origin"))
        self.assertIn("decision", self._governed(checkout, "--git-dir=vendor/x.git", "fetch", "origin"))

    def test_a_configuration_file_the_environment_names_is_judged_against_any_working_tree(self):
        checkout = self.owned(self.root / "checkout")
        self._raw("clone", "-q", str(self.upstream), str(checkout))
        self._raw("clone", "-q", "--bare", str(self.upstream), str(checkout / "vendor" / "x.git"))
        self.write(checkout, "hooks/reference-transaction", "#!/bin/sh\n")
        self.write(checkout, "tool.sh", "#!/bin/sh\n")
        self.write(checkout, "hooks.gitconfig", f"[core]\n\thooksPath = {checkout / 'hooks'}\n")
        outside = self.root / "configs"
        for name, text in (("hooks", f"[core]\n\thooksPath = {checkout / 'hooks'}\n"),
                           ("embedded", f"[core]\n\thooksPath = {checkout / 'vendor' / 'x.git' / 'hooks'}\n"),
                           ("pager", f"[core]\n\tpager = {checkout / 'tool.sh'}\n"),
                           ("external", f"[diff]\n\texternal = {checkout / 'tool.sh'}\n"),
                           ("plain", "[user]\n\tname = Operator\n")):
            self.write(self.root, f"configs/{name}.gitconfig", text)
        fetch = ("fetch", "origin", "+refs/heads/*:refs/remotes/up/*")
        for variable, named, args, brings_no_files in (
                ("GIT_CONFIG_GLOBAL", checkout / "hooks.gitconfig", fetch, False),
                ("GIT_CONFIG_SYSTEM", outside / "hooks.gitconfig", fetch, False),
                ("GIT_CONFIG", outside / "embedded.gitconfig", fetch, False),
                ("GIT_CONFIG_GLOBAL", outside / "pager.gitconfig", ("log", "-1"), True),
                ("GIT_CONFIG_GLOBAL", outside / "external.gitconfig", ("diff", "HEAD"), True)):
            with self.subTest(variable=variable, named=named.name, args=args):
                answer, _code = self._prepare(self.bare, *args, environment={variable: str(named)},
                                              brings_no_files=brings_no_files)
                self.assertTrue(answer.get("checked"), answer)
                self.assertIn("decision", answer)
        self._runs_as_typed(self.bare, *fetch, environment={"GIT_CONFIG_GLOBAL": str(outside / "plain.gitconfig")})

    def test_a_patch_applied_where_there_is_no_working_tree_is_checked(self):
        patch = self.root / "change.patch"
        patch.write_text("--- /dev/null\n+++ b/hooks/post-update\n@@ -0,0 +1 @@\n+echo\n", encoding="utf-8")
        self._governed(self.mirror, "apply", str(patch))
        self.assertFalse((self.mirror / "hooks" / "post-update").exists())

    def test_a_setting_that_runs_a_program_is_still_asked_about(self):
        answer = self._governed(self.mirror, "-c", "core.sshCommand=ssh -v", "fetch", "origin")
        self.assertEqual(answer["reason"], replay.RUNS_OTHER_COMMANDS)


class AFetchIntoACheckoutIsWrittenAsGitWritesIt(_Mirrored):

    def test_a_fetch_by_commit_writes_fetch_head_and_brings_the_objects(self):
        checkout = self.owned(self.root / "checkout")
        self._raw("clone", "-q", "--no-local", str(self.mirror), str(checkout))
        answer, code = self._prepare(checkout, "fetch", str(self.upstream), self.arrived)
        self.assertEqual(code, exitcodes.CLEAN, answer)
        self.assertNotIn("passthrough", answer)
        self.assertFalse(self._has(checkout, self.arrived))
        self.assertEqual(govern.apply(str(checkout), str(self.into))[0], {"applied": True})
        fetch_head = (checkout / ".git" / "FETCH_HEAD").read_text(encoding="utf-8")
        self.assertTrue(fetch_head.startswith(self.arrived), fetch_head)
        self.assertTrue(self._has(checkout, self.arrived))
        self.assertEqual(self.git(checkout, "status", "--porcelain"), "")


if __name__ == "__main__":
    import unittest
    unittest.main()
