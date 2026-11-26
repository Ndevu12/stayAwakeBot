#!/usr/bin/env python3
"""On Windows, a read that must not follow a link reads the file itself, and nothing for a link or a
junction at its name."""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from stayawake.bots.security.hygiene import staging_kit
from stayawake.utils import pathsafe

WINDOWS_ONLY = unittest.skipUnless(os.name == "nt", "the Windows read runs only on Windows")


def junction(link: Path, target: Path) -> None:
    subprocess.run(["cmd", "/c", "mklink", "/J", str(link), str(target)], check=True,
                   capture_output=True)


@WINDOWS_ONLY
class TestAReadNeverFollowsALinkOnWindows(unittest.TestCase):

    def setUp(self):
        self.base = Path(tempfile.mkdtemp(prefix="saw-reads-"))
        self.addCleanup(shutil.rmtree, self.base, True)
        self.file = self.base / "record.json"
        self.file.write_bytes(b"0123456789")

    def test_the_windows_read_is_the_one_in_use(self):
        from stayawake.utils import winopen
        self.assertIs(winopen.read_regular_no_follow, pathsafe.read_regular_no_follow)

    def test_a_regular_file_is_read_up_to_its_limit(self):
        self.assertEqual(b"0123456789", pathsafe.read_regular_no_follow(self.file, 10))
        self.assertIsNone(pathsafe.read_regular_no_follow(self.file, 9))
        self.assertEqual(b"0123456789", pathsafe.read_regular_no_follow(self.file, 10,
                                                                         same_as=os.lstat(self.file)))

    def test_a_link_a_junction_a_folder_or_another_file_reads_as_nothing(self):
        (self.base / "link.json").symlink_to(self.file)
        (self.base / "folder").mkdir()
        junction(self.base / "junction", self.base / "folder")
        other = self.base / "other.json"
        other.write_bytes(b"other")
        for path in (self.base / "link.json", self.base / "folder", self.base / "junction",
                     self.base / "missing.json"):
            self.assertIsNone(pathsafe.read_regular_no_follow(path, 100), path.name)
        self.assertIsNone(pathsafe.read_regular_no_follow(self.file, 100, same_as=os.lstat(other)))

    def test_a_kit_whose_manifest_is_a_link_is_not_taken_for_a_kit(self):
        real = self.base / "real"
        real.mkdir()
        (real / "package.json").write_text(json.dumps({"dependencies": {"axios": "^1.7.0"}}),
                                           encoding="utf-8")
        self.assertTrue(staging_kit.holds_a_kit(real))
        linked = self.base / "linked"
        linked.mkdir()
        (linked / "package.json").symlink_to(real / "package.json")
        self.assertFalse(staging_kit.holds_a_kit(linked))


if __name__ == "__main__":
    unittest.main()
