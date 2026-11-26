#!/usr/bin/env python3
"""A copied git index keeps the time git wrote it, and a file rewritten with the same size in the
same second is still seen as changed."""
from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
import time
import unittest
from pathlib import Path

from stayawake.lib.git import owned, replay
from stayawake.lib.git.index_copy import copy_index


def _git(work: Path, *args: str, index: Path | None = None) -> str:
    env = {**os.environ, **({"GIT_INDEX_FILE": str(index)} if index else {})}
    return subprocess.run(["git", *args], cwd=work, env=env, check=True, capture_output=True,
                          text=True).stdout


class AnIndexCopyKeepsItsOwnTime(unittest.TestCase):
    def setUp(self):
        self.root = Path(tempfile.mkdtemp(prefix="index-time-"))
        self.addCleanup(shutil.rmtree, self.root, ignore_errors=True)

    def test_the_copy_has_the_time_of_the_index(self):
        source, target = self.root / "index", self.root / "copy"
        source.write_bytes(b"DIRC")
        os.utime(source, ns=(1_000_000_000, 1_000_000_000))
        copy_index(source, target)
        self.assertEqual(target.stat().st_mtime_ns, 1_000_000_000)

    def test_a_same_size_rewrite_in_the_same_second_is_in_the_tree(self):
        work = self.root / "work"
        work.mkdir()
        _git(work, "init", "-q")
        _git(work, "config", "core.checkStat", "minimal")
        owned.own(work)
        self.addCleanup(owned.disown, work)
        script, files_index = work / "x.sh", self.root / "files.index"
        script.write_text("echo 47\n")
        _git(work, "add", "x.sh", index=files_index)
        written = script.stat().st_mtime_ns
        os.utime(files_index, ns=(written, written))
        script.unlink()
        script.write_text("echo 29\n")
        os.utime(script, ns=(written, written))
        time.sleep(1.1)
        tree = replay._tree_of_files(work, files_index, self.root / "after.index")
        self.assertIsNotNone(tree)
        blob = _git(work, "rev-parse", f"{tree}:x.sh").strip()
        self.assertEqual(blob, _git(work, "hash-object", "x.sh").strip())


if __name__ == "__main__":
    unittest.main()
