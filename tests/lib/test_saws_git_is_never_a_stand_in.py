#!/usr/bin/env python3
"""saw runs the real git, never a git stand-in that comes first on PATH."""
from __future__ import annotations

import contextlib
import importlib
import io
import os
import shutil
from pathlib import Path
from unittest import mock

from stayawake.lib.git.run import UNTRUSTED
from tests.support.gitrepo import GitSandbox

_REAL_GIT = shutil.which("git", path=os.defpath)
runner = importlib.import_module("stayawake.lib.git.run")


class SawsGitIsNeverAStandIn(GitSandbox):

    def setUp(self):
        super().setUp()
        runner._first_real.cache_clear()
        self.addCleanup(runner._first_real.cache_clear)
        self.ran = self.root / "ran"
        self.ran.mkdir()
        marked = self.root / "marked"
        marked.mkdir()
        self._script(marked / "git", f'#!/bin/sh\n# saw-govern-standin\ntouch "{self.ran}/marked"\nexit 1\n')
        own = self.root / "own"
        own.mkdir()
        self._script(own / "saw-git-standin", f'#!/bin/sh\ntouch "{self.ran}/own"\nexit 1\n')
        linked = self.root / "linked"
        linked.mkdir()
        (linked / "git").symlink_to(own / "saw-git-standin")
        real = self.root / "real"
        real.mkdir()
        (real / "git").symlink_to(_REAL_GIT)
        self.stand_ins = [str(marked), str(linked)]
        self.real = real / "git"

    def _script(self, path: Path, text: str) -> None:
        path.write_text(text)
        path.chmod(0o755)

    def _path(self, *folders: str):
        return mock.patch.dict(os.environ, {"PATH": os.pathsep.join(folders)})

    def test_the_real_git_after_the_stand_ins_runs(self):
        repo = self.new_repo()
        self.write(repo, "a.txt", "one\n")
        head = self.commit(repo, "one")
        with self._path(*self.stand_ins, str(self.real.parent)):
            self.assertEqual(runner.real_git(), str(self.real))
            self.assertEqual(runner.stdout(repo, ["rev-parse", "HEAD"], context=UNTRUSTED).strip(), head)
        self.assertEqual(sorted(p.name for p in self.ran.iterdir()), [])

    def test_each_kind_of_stand_in_is_recognised(self):
        self.assertTrue(runner.is_standin(Path(self.stand_ins[0]) / "git"))
        self.assertTrue(runner.is_standin(Path(self.stand_ins[1]) / "git"))
        self.assertFalse(runner.is_standin(self.real))

    def test_with_only_stand_ins_saw_runs_no_git_and_says_so(self):
        repo = self.new_repo()
        runner._told_no_git = False
        err = io.StringIO()
        with self._path(*self.stand_ins), contextlib.redirect_stderr(err):
            self.assertIsNone(runner.real_git())
            self.assertEqual(runner.stdout(repo, ["rev-parse", "HEAD"], context=UNTRUSTED), "")
        self.assertIn("no git was found on PATH apart from a git stand-in", err.getvalue())
        self.assertEqual(sorted(p.name for p in self.ran.iterdir()), [])
