#!/usr/bin/env python3
"""On Windows, saw writes its own files where they were named, in one step or not at all: it holds
every folder on the way against anyone else moving it, refuses a link or junction on the way, and
follows a link at the file's name that is a symbolic link a trusted account owns."""
from __future__ import annotations

import errno
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from stayawake.utils import atomicwrite, pathsafe, winlock

WINDOWS_ONLY = unittest.skipUnless(os.name == "nt", "saw's Windows writer runs only on Windows")


def junction(link: Path, target: Path) -> None:
    subprocess.run(["cmd", "/c", "mklink", "/J", str(link), str(target)], check=True,
                   capture_output=True)


class _Sandbox(unittest.TestCase):

    def setUp(self):
        self.base = Path(tempfile.mkdtemp(prefix="saw-writes-"))
        self.addCleanup(shutil.rmtree, self.base, True)
        self.elsewhere = self.base / "elsewhere"
        self.elsewhere.mkdir()

    def landed_elsewhere(self) -> list[str]:
        return sorted(str(p.relative_to(self.elsewhere)) for p in self.elsewhere.rglob("*"))

    def staging_left_in(self, folder: Path) -> list[str]:
        return sorted(p.name for p in folder.iterdir() if p.name.startswith(".saw-"))


@WINDOWS_ONLY
class TestTheWindowsFoldersAreTheOnesInUse(unittest.TestCase):

    def test_folders_on_windows_are_held_handles(self):
        from stayawake.utils import folders, folders_windows
        self.assertIs(folders_windows.Folder, folders.Folder)
        self.assertIs(folders_windows.open_folder, folders.open_folder)
        self.assertIs(folders, atomicwrite.folders)


@WINDOWS_ONLY
class TestAHeldFolderStaysWhereItIs(_Sandbox):

    def test_no_one_else_can_rename_or_delete_a_folder_on_the_way_while_it_is_held(self):
        from stayawake.utils import folders
        inner = self.base / "state" / "inner"
        inner.mkdir(parents=True)
        with folders.open_folder(inner):
            for attempt in (lambda: os.rename(self.base / "state", self.base / "moved"),
                            lambda: os.rename(inner, self.base / "state" / "moved"),
                            lambda: os.rmdir(inner)):
                with self.assertRaises(PermissionError):
                    attempt()
            self.assertTrue(atomicwrite.replace(inner / "record.json", "{}"))
            atomicwrite.rename_in(inner, "record.json", "kept.json")
            atomicwrite.new_folder(inner, "run")
        self.assertEqual(b"{}", (inner / "kept.json").read_bytes())
        os.rename(self.base / "state", self.base / "moved")


@WINDOWS_ONLY
class TestAFileIsWrittenInOneStep(_Sandbox):

    def test_a_file_is_written_then_replaced(self):
        record = self.base / "state" / "record.json"
        self.assertTrue(atomicwrite.replace(record, "{}"))
        self.assertEqual(b"{}", record.read_bytes())
        self.assertTrue(atomicwrite.replace(record, '{"seen": 1}'))
        self.assertEqual(b'{"seen": 1}', record.read_bytes())
        self.assertEqual([], self.staging_left_in(record.parent))

    def test_text_is_written_as_given(self):
        record = self.base / "settings.toml"
        with atomicwrite.staged(record) as handle:
            handle.write("a = 1\nb = 2\n")
        self.assertEqual(b"a = 1\nb = 2\n", record.read_bytes())

    def test_a_write_that_fails_leaves_the_file_as_it_was(self):
        record = self.base / "record.json"
        record.write_bytes(b"old")
        with self.assertRaises(RuntimeError):
            with atomicwrite.staged(record, binary=True) as handle:
                handle.write(b"new")
                raise RuntimeError("stopped")
        self.assertEqual(b"old", record.read_bytes())
        self.assertEqual([], self.staging_left_in(self.base))


@WINDOWS_ONLY
class TestAFileIsReadBack(_Sandbox):

    def test_what_was_written_reads_back(self):
        record = self.base / "record.json"
        self.assertTrue(atomicwrite.replace(record, "0123456789"))
        self.assertEqual(b"0123456789", atomicwrite.read_back(record, 100))
        self.assertEqual(b"01234", atomicwrite.read_back(record, 4))

    def test_a_folder_or_a_missing_file_reads_back_as_nothing(self):
        (self.base / "folder").mkdir()
        self.assertIsNone(atomicwrite.read_back(self.base / "folder", 100))
        self.assertIsNone(atomicwrite.read_back(self.base / "missing.json", 100))

    def test_a_link_at_the_name_reads_back_only_when_it_is_followed(self):
        (self.elsewhere / "planted.json").write_bytes(b"planted")
        (self.base / "record.json").symlink_to(self.elsewhere / "planted.json")
        for at_a_link in (atomicwrite.REFUSE_A_LINK, atomicwrite.REPLACE_A_LINK):
            self.assertIsNone(atomicwrite.read_back(self.base / "record.json", 100,
                                                    at_a_link=at_a_link), at_a_link)
        self.assertEqual(b"planted", atomicwrite.read_back(self.base / "record.json", 100,
                                                          at_a_link=atomicwrite.FOLLOW_A_TRUSTED_LINK))


@WINDOWS_ONLY
class TestALinkAtTheFilesName(_Sandbox):

    def test_a_symlink_at_the_name_is_refused_when_the_writer_refuses_links(self):
        (self.base / "record.json").symlink_to(self.elsewhere / "made-through-the-link")
        self.assertFalse(atomicwrite.replace(self.base / "record.json", "{}"))
        self.assertTrue((self.base / "record.json").is_symlink())
        self.assertEqual([], self.landed_elsewhere())

    def test_a_symlink_this_account_placed_is_written_through(self):
        (self.elsewhere / "dotfiles-record.json").write_bytes(b"old")
        (self.base / "record.json").symlink_to(self.elsewhere / "dotfiles-record.json")
        self.assertTrue(atomicwrite.replace(self.base / "record.json", "{}",
                                            at_a_link=atomicwrite.FOLLOW_A_TRUSTED_LINK))
        self.assertTrue((self.base / "record.json").is_symlink())
        self.assertEqual(b"{}", (self.elsewhere / "dotfiles-record.json").read_bytes())
        atomicwrite.set_mode(self.base / "record.json", 0o600)

    def test_a_symlink_another_account_owns_is_refused(self):
        (self.elsewhere / "dotfiles-record.json").write_bytes(b"old")
        (self.base / "record.json").symlink_to(self.elsewhere / "dotfiles-record.json")
        with mock.patch.object(winlock, "held_owner_sid", return_value="S-1-5-21-1-2-3-1001"):
            self.assertFalse(atomicwrite.replace(self.base / "record.json", "{}",
                                                 at_a_link=atomicwrite.FOLLOW_A_TRUSTED_LINK))
            with self.assertRaises(pathsafe.RedirectedPath):
                atomicwrite.set_mode(self.base / "record.json", 0o600)
        self.assertEqual(b"old", (self.elsewhere / "dotfiles-record.json").read_bytes())

    def test_a_junction_at_the_name_is_refused(self):
        junction(self.base / "record.json", self.elsewhere)
        self.assertFalse(atomicwrite.replace(self.base / "record.json", "{}",
                                             at_a_link=atomicwrite.FOLLOW_A_TRUSTED_LINK))
        self.assertEqual([], self.landed_elsewhere())

    def test_a_trusted_symlink_whose_target_is_reached_through_a_junction_is_refused(self):
        (self.elsewhere / "dotfiles-record.json").write_bytes(b"old")
        junction(self.base / "passage", self.elsewhere)
        (self.base / "record.json").symlink_to(self.base / "passage" / "dotfiles-record.json")
        self.assertFalse(atomicwrite.replace(self.base / "record.json", "{}",
                                             at_a_link=atomicwrite.FOLLOW_A_TRUSTED_LINK))
        self.assertEqual(b"old", (self.elsewhere / "dotfiles-record.json").read_bytes())

    def test_a_symlink_at_the_name_is_replaced_when_the_writer_asks(self):
        (self.base / "record.json").symlink_to(self.elsewhere / "made-through-the-link")
        self.assertTrue(atomicwrite.replace(self.base / "record.json", "{}",
                                            at_a_link=atomicwrite.REPLACE_A_LINK))
        self.assertFalse((self.base / "record.json").is_symlink())
        self.assertEqual(b"{}", (self.base / "record.json").read_bytes())
        self.assertEqual([], self.landed_elsewhere())

    def test_a_mode_is_given_only_to_a_regular_file_of_its_own(self):
        (self.base / "record.json").write_text("{}", encoding="utf-8")
        atomicwrite.set_mode(self.base / "record.json", 0o600)
        (self.base / "folder").mkdir()
        junction(self.base / "junction.json", self.base / "folder")
        with self.assertRaises(pathsafe.RedirectedPath):
            atomicwrite.set_mode(self.base / "junction.json", 0o600)
        with self.assertRaises(pathsafe.RedirectedPath):
            atomicwrite.set_mode(self.base / "folder", 0o600)


@WINDOWS_ONLY
class TestALinkOnTheWayIsRefused(_Sandbox):

    def assert_nothing_is_written_through(self, link: Path):
        for at_a_link in (atomicwrite.REFUSE_A_LINK, atomicwrite.FOLLOW_A_TRUSTED_LINK,
                          atomicwrite.REPLACE_A_LINK):
            self.assertFalse(atomicwrite.replace(link / "record.json", "{}", at_a_link=at_a_link),
                             at_a_link)
        (self.elsewhere / "kept.json").write_bytes(b"kept")
        (self.elsewhere / "other.json").write_bytes(b"other")
        (self.base / "outside.json").write_bytes(b"outside")
        for attempt in (lambda: atomicwrite.make_folder(link / "inner"),
                        lambda: atomicwrite.new_folder(link, "run"),
                        lambda: atomicwrite.set_mode(link / "kept.json", 0o600),
                        lambda: atomicwrite.rename_in(link, "kept.json", "renamed.json"),
                        lambda: atomicwrite.rename_beside(link, "kept.json", "beside.json"),
                        lambda: atomicwrite.move_into(link / "kept.json", self.base, "moved.json"),
                        lambda: atomicwrite.move_into(self.base / "outside.json", link, "moved.json")):
            with self.assertRaises(pathsafe.RedirectedPath):
                attempt()
        self.assertIsNone(atomicwrite.read_back(link / "kept.json", 100))
        self.assertEqual(["kept.json", "other.json"], self.landed_elsewhere())
        self.assertTrue((self.base / "outside.json").exists())

    def test_a_symlinked_folder_on_the_way_is_refused(self):
        (self.base / "state").symlink_to(self.elsewhere, target_is_directory=True)
        self.assert_nothing_is_written_through(self.base / "state")

    def test_a_junction_on_the_way_is_refused(self):
        junction(self.base / "state", self.elsewhere)
        self.assert_nothing_is_written_through(self.base / "state")

    def test_a_junction_further_up_is_refused(self):
        (self.elsewhere / "inner").mkdir()
        junction(self.base / "state", self.elsewhere)
        self.assertFalse(atomicwrite.replace(self.base / "state" / "inner" / "record.json", "{}"))
        with self.assertRaises(pathsafe.RedirectedPath):
            atomicwrite.make_folder(self.base / "state" / "inner" / "deeper")
        self.assertEqual(["inner"], self.landed_elsewhere())


@WINDOWS_ONLY
class TestFoldersAreMadeAndEntriesRenamed(_Sandbox):

    def test_every_missing_folder_is_made(self):
        atomicwrite.make_folder(self.base / "a" / "b" / "c")
        self.assertTrue((self.base / "a" / "b" / "c").is_dir())

    def test_a_new_folder_takes_the_first_free_name(self):
        self.assertEqual(self.base / "runs" / "run", atomicwrite.new_folder(self.base / "runs", "run"))
        self.assertEqual(self.base / "runs" / "run-1", atomicwrite.new_folder(self.base / "runs", "run"))
        self.assertTrue((self.base / "runs" / "run-1").is_dir())
        with self.assertRaises(FileExistsError):
            atomicwrite.new_folder(self.base / "runs", "run", tries=1)
        for not_one_entry in ("", "..", "a\\b", "a/b"):
            with self.assertRaises(pathsafe.RedirectedPath):
                atomicwrite.new_folder(self.base / "runs", not_one_entry)

    def test_rename_in_replaces_what_has_the_new_name(self):
        (self.base / "old.json").write_bytes(b"old")
        (self.base / "new.json").write_bytes(b"new")
        atomicwrite.rename_in(self.base, "old.json", "new.json")
        self.assertEqual(b"old", (self.base / "new.json").read_bytes())
        self.assertFalse((self.base / "old.json").exists())

    def test_rename_beside_never_replaces_what_is_there(self):
        (self.base / "a.json").write_bytes(b"a")
        (self.base / "b.json").write_bytes(b"b")
        with self.assertRaises(FileExistsError):
            atomicwrite.rename_beside(self.base, "a.json", "b.json")
        self.assertEqual(b"a", (self.base / "a.json").read_bytes())
        self.assertEqual(b"b", (self.base / "b.json").read_bytes())
        atomicwrite.rename_beside(self.base, "a.json", "c.json")
        self.assertEqual(b"a", (self.base / "c.json").read_bytes())
        self.assertFalse((self.base / "a.json").exists())

    def test_a_file_and_a_folder_are_moved_whole(self):
        (self.base / "hooks" / "inner").mkdir(parents=True)
        (self.base / "hooks" / "inner" / "pre-commit").write_bytes(b"#!/bin/sh\n")
        (self.base / "record.json").write_bytes(b"{}")
        (self.base / "kept").mkdir()
        atomicwrite.move_into(self.base / "hooks", self.base / "kept", "hooks-1")
        atomicwrite.move_into(self.base / "record.json", self.base / "kept", "record-1.json")
        self.assertEqual(b"#!/bin/sh\n",
                         (self.base / "kept" / "hooks-1" / "inner" / "pre-commit").read_bytes())
        self.assertEqual(b"{}", (self.base / "kept" / "record-1.json").read_bytes())
        self.assertFalse((self.base / "hooks").exists())
        self.assertFalse((self.base / "record.json").exists())


@WINDOWS_ONLY
class TestAMoveBetweenDisksCopiesWhole(_Sandbox):

    def across_disks(self):
        from stayawake.utils import folders_windows
        refused = OSError(errno.EXDEV, "not the same device", None, 17)
        return mock.patch.object(folders_windows.os, "replace", side_effect=refused)

    def test_a_folder_is_copied_with_its_times_and_the_source_removed(self):
        source = self.base / "hooks"
        (source / "inner").mkdir(parents=True)
        (source / "inner" / "pre-commit").write_bytes(b"#!/bin/sh\n")
        os.utime(source / "inner" / "pre-commit", (1_600_000_000, 1_600_000_000))
        (self.base / "kept").mkdir()
        with self.across_disks():
            atomicwrite.move_into(source, self.base / "kept", "hooks")
        moved = self.base / "kept" / "hooks" / "inner" / "pre-commit"
        self.assertFalse(source.exists())
        self.assertEqual(b"#!/bin/sh\n", moved.read_bytes())
        self.assertEqual(1_600_000_000, int(moved.stat().st_mtime))

    def test_a_folder_with_a_junction_inside_is_not_moved(self):
        source = self.base / "hooks"
        source.mkdir()
        (source / "pre-commit").write_bytes(b"#!/bin/sh\n")
        junction(source / "inner", self.elsewhere)
        (self.base / "kept").mkdir()
        with self.across_disks(), self.assertRaisesRegex(OSError, "is a link"):
            atomicwrite.move_into(source, self.base / "kept", "hooks")
        self.assertTrue((source / "pre-commit").exists())


if __name__ == "__main__":
    unittest.main()
