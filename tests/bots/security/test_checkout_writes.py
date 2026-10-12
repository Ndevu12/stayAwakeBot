#!/usr/bin/env python3
"""A file checkout's scan covers the files the git command that ran the hook wrote."""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

from stayawake.bots.security import checkout_writes
from stayawake.bots.security.targets import ScanOptions
from stayawake.utils import procsnap

_ISOLATED = {"GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_NOSYSTEM": "1"}


def _run(repo: Path, *args: str) -> None:
    subprocess.run(["git", "-C", str(repo), *args], check=True, capture_output=True,
                   env={**os.environ, **_ISOLATED})


class _Repo(unittest.TestCase):
    def setUp(self):
        self.root = Path(tempfile.mkdtemp(prefix="checkout-writes-")).resolve()
        self.addCleanup(shutil.rmtree, self.root, ignore_errors=True)
        _run(self.root, "init", "-q")
        for setting in (["user.email", "t@t"], ["user.name", "t"], ["commit.gpgsign", "false"]):
            _run(self.root, "config", *setting)
        self.opts = ScanOptions()

    def _write(self, rel: str, text: str = "x\n") -> None:
        (self.root / rel).parent.mkdir(parents=True, exist_ok=True)
        (self.root / rel).write_text(text)

    def _now_on_disk(self) -> int:
        time.sleep(0.05)
        fd, probe = tempfile.mkstemp(dir=self.root.parent)
        os.close(fd)
        seen = os.stat(probe).st_ctime_ns
        os.unlink(probe)
        return seen

    def _written(self, since: int):
        with mock.patch.object(checkout_writes, "_CLOCK_SLACK_NS", 0):
            return checkout_writes.written(self.root, self.opts, since)


class TestTheFilesWrittenSinceAMoment(_Repo):
    def test_a_file_written_after_the_moment_is_listed_and_one_before_is_not(self):
        self._write("old.js")
        since = self._now_on_disk()
        self._write("new.js")
        self.assertEqual(self._written(since), ("new.js",))

    def test_a_file_written_just_before_the_moment_is_listed(self):
        self._write("a.js")
        since = os.lstat(self.root / "a.js").st_ctime_ns + 1_000_000_000
        self.assertEqual(checkout_writes.written(self.root, self.opts, since), ("a.js",))

    def test_a_tracked_file_in_a_folder_a_scan_skips_is_listed(self):
        self._write("dist/x.js")
        self._write("dist/untracked.js")
        _run(self.root, "add", "dist/x.js")
        self.assertEqual(self._written(0), ("dist/x.js",))

    def test_a_link_to_a_written_file_is_listed(self):
        self._write("plain.txt")
        os.symlink("plain.txt", self.root / "first")
        os.symlink("first", self.root / "second")
        since = self._now_on_disk()
        self._write("plain.txt", "rewritten\n")
        self.assertEqual(self._written(since), ("first", "plain.txt", "second"))

    def test_a_link_to_a_file_not_written_is_not_listed(self):
        self._write("plain.txt")
        self._write("other.txt")
        os.symlink("plain.txt", self.root / "link")
        since = self._now_on_disk()
        self._write("other.txt", "rewritten\n")
        self.assertEqual(self._written(since), ("other.txt",))

    def test_a_link_naming_a_written_file_with_another_spelling_is_listed(self):
        self._write("plain.txt")
        if not (self.root / "PLAIN.txt").exists():
            self.skipTest("this filesystem tells names apart by case")
        os.symlink("PLAIN.txt", self.root / "link")
        since = self._now_on_disk()
        self._write("plain.txt", "rewritten\n")
        self.assertEqual(self._written(since), ("link", "plain.txt"))

    def test_a_written_link_to_a_folder_is_listed(self):
        (self.root / "sub").mkdir()
        self._write("sub/a.js")
        os.symlink("sub", self.root / "folder")
        _run(self.root, "add", "folder")
        since = self._now_on_disk()
        os.unlink(self.root / "folder")
        os.symlink("sub", self.root / "folder")
        self.assertEqual(self._written(since), ("folder",))

    def test_when_a_link_is_written_every_link_is_listed(self):
        (self.root / "a").mkdir()
        (self.root / "b").mkdir()
        self._write("b/x")
        os.symlink("a", self.root / "d")
        os.symlink("d/x", self.root / "old")
        _run(self.root, "add", "d", "old")
        since = self._now_on_disk()
        os.unlink(self.root / "d")
        os.symlink("b", self.root / "d")
        self.assertEqual(self._written(since), ("d", "old"))

    def test_a_folder_git_tracks_is_not_listed(self):
        self._write("a.js")
        _run(self.root, "add", "a.js")
        blob = subprocess.run(["git", "-C", str(self.root), "hash-object", "a.js"], capture_output=True,
                              text=True, check=True, env={**os.environ, **_ISOLATED}).stdout.strip()
        _run(self.root, "update-index", "--add", "--cacheinfo", f"160000,{blob},sub")
        (self.root / "sub").mkdir()
        self.assertEqual(self._written(0), ("a.js",))

    @unittest.skipIf(os.geteuid() == 0, "root enters every folder")
    def test_a_tree_with_a_folder_it_cannot_enter_lists_nothing(self):
        self._write("shut/a.js")
        os.chmod(self.root / "shut", 0)
        self.addCleanup(os.chmod, self.root / "shut", 0o755)
        self.assertIsNone(self._written(0))

    def test_a_list_of_tracked_files_that_cannot_be_read_lists_nothing(self):
        self._write("a.js")
        with mock.patch.object(checkout_writes, "stdout_bytes", return_value=None):
            self.assertIsNone(self._written(0))


def _process(name: str, ppid: int, at_ns: int = 7) -> procsnap.Start:
    return procsnap.Start(at_ns, name, ppid)


class TestTheStartOfTheGitCommand(_Repo):
    def test_a_hook_finds_the_start_of_the_git_command_that_ran_it(self):
        self._write("a.js")
        _run(self.root, "add", "a.js")
        _run(self.root, "commit", "-qm", "a")
        hooks = self.root.parent / (self.root.name + "-hooks")
        hooks.mkdir()
        self.addCleanup(shutil.rmtree, hooks, ignore_errors=True)
        found = self.root.parent / (self.root.name + "-found")
        self.addCleanup(lambda: found.unlink(missing_ok=True))
        src = Path(checkout_writes.__file__).resolve().parents[3]
        script = hooks / "post-checkout"
        script.write_text(
            "#!/bin/sh\n"
            f"exec '{sys.executable}' -c 'import json, sys; sys.path.insert(0, sys.argv[1]); "
            "from stayawake.bots.security import checkout_writes; "
            "open(sys.argv[2], \"w\").write(json.dumps(checkout_writes.git_started_ns()))' "
            f"'{src}' '{found}'\n")
        script.chmod(0o755)
        (self.root / "a.js").write_text("edited\n")
        before = time.time_ns()
        _run(self.root, "-c", f"core.hooksPath={hooks}", "checkout", "--", "a.js")
        after = time.time_ns()
        started = json.loads(found.read_text())
        self.assertIsInstance(started, int)
        self.assertLessEqual(before - 2_000_000_000, started)
        self.assertLessEqual(started, after)

    def test_the_nearest_git_above_is_the_one_read(self):
        chain = {10: _process("sh", 20), 20: _process("git", 30, at_ns=5), 30: _process("git", 1, at_ns=1)}
        with mock.patch.object(checkout_writes.os, "getppid", return_value=10), \
                mock.patch.object(procsnap, "started", side_effect=chain.get):
            self.assertEqual(checkout_writes.git_started_ns(), 5)

    def test_no_git_above_finds_nothing(self):
        chain = {10: _process("sh", 20), 20: _process("python3", 1)}
        with mock.patch.object(checkout_writes.os, "getppid", return_value=10), \
                mock.patch.object(procsnap, "started", side_effect=chain.get):
            self.assertIsNone(checkout_writes.git_started_ns())

    def test_a_process_it_cannot_read_finds_nothing(self):
        chain = {10: _process("sh", 20)}
        with mock.patch.object(checkout_writes.os, "getppid", return_value=10), \
                mock.patch.object(procsnap, "started", side_effect=chain.get):
            self.assertIsNone(checkout_writes.git_started_ns())


if __name__ == "__main__":
    unittest.main()
