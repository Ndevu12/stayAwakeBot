#!/usr/bin/env python3
"""On Windows, saw deletes the known worm's staging kit through folders it holds open, keeping its
facts and refusing any link or junction."""
from __future__ import annotations

import datetime
import json
import os
import shutil
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from stayawake.bots.security.harden import remove_kit
from stayawake.utils import winlock

WINDOWS_ONLY = unittest.skipUnless(os.name == "nt", "saw's Windows kit removal runs only on Windows")
_KIT_MANIFEST = json.dumps({"dependencies": {"axios": "^1.7.0", "socket.io-client": "^4.7.0"}})
_KIT_LOCK = json.dumps({"lockfileVersion": 3, "packages": {"": {}, "node_modules/axios": {"version": "1.7.9"},
                                                            "node_modules/socket.io-client": {"version": "4.8.1"}}})
_NOW = datetime.datetime(2026, 11, 25, 12, 0, 0, tzinfo=datetime.timezone.utc)


def junction(link: Path, target: Path) -> None:
    subprocess.run(["cmd", "/c", "mklink", "/J", str(link), str(target)], check=True,
                   capture_output=True)


def a_kit_named(where: Path) -> Path:
    where.mkdir()
    (where / "package.json").write_text(_KIT_MANIFEST, encoding="utf-8")
    (where / "package-lock.json").write_text(_KIT_LOCK, encoding="utf-8")
    (where / "node_modules" / "axios").mkdir(parents=True)
    (where / "node_modules" / "axios" / "index.js").write_text("module.exports = 1;\n", encoding="utf-8")
    return where


@WINDOWS_ONLY
class TestTheKitIsRemovedOnWindows(unittest.TestCase):

    def setUp(self):
        self.home = Path(tempfile.mkdtemp(prefix="saw-kit-"))
        self.addCleanup(shutil.rmtree, self.home, True)
        self.captured = self.home / "captured"
        self.target = self.home / ".node_modules"

    def remove(self, path: Path) -> remove_kit.Removal:
        return remove_kit.remove(path, self.captured, now=_NOW)

    def test_the_kit_is_deleted_and_its_facts_kept(self):
        a_kit_named(self.target)
        self.assertEqual(remove_kit.Removal(removed=True), self.remove(self.target))
        self.assertEqual([], [p.name for p in self.home.iterdir() if p.name.startswith(".node_modules")])
        [record] = self.captured.iterdir()
        kept = json.loads(record.read_text(encoding="utf-8"))
        self.assertEqual(["axios", "socket.io-client"], [p["name"] for p in kept["packages"]])

    def test_a_read_only_file_inside_is_deleted_too(self):
        a_kit_named(self.target)
        os.chmod(self.target / "node_modules" / "axios" / "index.js", stat.S_IREAD)
        self.assertEqual(remove_kit.Removal(removed=True), self.remove(self.target))

    def test_a_link_inside_is_deleted_as_a_link_and_what_it_leads_to_is_untouched(self):
        victim = self.home / "victim"
        victim.mkdir()
        (victim / "KEEPME").write_text("x", encoding="utf-8")
        a_kit_named(self.target)
        junction(self.target / "node_modules" / "trap", victim)
        (self.target / "trap-file").symlink_to(victim / "KEEPME")
        self.assertEqual(remove_kit.Removal(removed=True), self.remove(self.target))
        self.assertEqual(["KEEPME"], [p.name for p in victim.iterdir()])
        self.assertEqual("x", (victim / "KEEPME").read_text(encoding="utf-8"))

    def test_a_kit_reached_through_a_junction_is_left_alone(self):
        real = self.home / "real"
        real.mkdir()
        a_kit_named(real / ".node_modules")
        junction(self.home / "linked", real)
        self.assertEqual(remove_kit.Removal(), self.remove(self.home / "linked" / ".node_modules"))
        self.assertTrue((real / ".node_modules" / "package.json").is_file())

    def test_a_kit_name_that_is_a_junction_is_left_alone(self):
        real = a_kit_named(self.home / "real-kit")
        junction(self.target, real)
        self.assertEqual(remove_kit.Removal(), self.remove(self.target))
        self.assertTrue((real / "package.json").is_file())

    def test_a_folder_that_is_not_the_kit_is_left_alone(self):
        self.target.mkdir()
        (self.target / "package.json").write_text('{"name": "mine"}', encoding="utf-8")
        self.assertEqual(remove_kit.Removal(), self.remove(self.target))
        self.assertTrue((self.target / "package.json").is_file())

    def test_a_kit_another_account_owns_is_left_alone(self):
        a_kit_named(self.target)
        with mock.patch.object(winlock, "held_owner_sid", return_value="S-1-5-21-1-2-3-1001"):
            self.assertEqual(remove_kit.Removal(), self.remove(self.target))
        self.assertTrue((self.target / "package.json").is_file())

    def test_once_settled_under_its_new_name_no_one_else_can_move_the_kit(self):
        from stayawake.utils import folders
        a_kit_named(self.target)
        renamed = self.home / "renamed"
        with folders.hold(self.target) as held:
            os.rename(self.target, renamed)
            self.assertTrue(held.settle_at(renamed))
            with self.assertRaises(PermissionError):
                os.rename(renamed, self.home / "moved-away")
        self.assertTrue((renamed / "package.json").is_file())


if __name__ == "__main__":
    unittest.main()
