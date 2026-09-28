#!/usr/bin/env python3
"""Shared path-safety read primitives (utils.pathsafe): the FIFO-safe regular-file guard (#1226)
every arbitrary-file read now reuses instead of hand-rolling `stat + S_ISREG`."""
from __future__ import annotations

import os
import stat
import tempfile
import threading
import unittest
from pathlib import Path

from stayawake.utils import pathsafe


class TestRegularFileGuard(unittest.TestCase):
    def setUp(self):
        self.d = Path(tempfile.mkdtemp(prefix="pathsafe-"))
        self.addCleanup(lambda: __import__("shutil").rmtree(self.d, ignore_errors=True))

    def test_regular_file_reads(self):
        f = self.d / "f.txt"
        f.write_text("hi")
        self.assertTrue(pathsafe.is_regular_file(f))
        self.assertEqual(pathsafe.read_regular_text(f), "hi")
        self.assertEqual(pathsafe.read_regular_bytes(f), b"hi")

    def test_absent_and_dir_are_none(self):
        self.assertFalse(pathsafe.is_regular_file(self.d / "nope"))
        self.assertIsNone(pathsafe.read_regular_text(self.d / "nope"))
        self.assertFalse(pathsafe.is_regular_file(self.d))          # a directory is not a regular file
        self.assertIsNone(pathsafe.read_regular_bytes(self.d))

    def test_non_utf8_decodes_tolerantly(self):
        f = self.d / "b.bin"
        f.write_bytes(b"\xff\xfe ok")
        self.assertIsNotNone(pathsafe.read_regular_text(f))         # errors="replace" → never raises

    def test_fifo_is_never_opened_and_does_not_hang(self):
        if not hasattr(os, "mkfifo"):
            self.skipTest("no mkfifo")
        fifo = self.d / "pipe"
        os.mkfifo(fifo)
        box = {}
        t = threading.Thread(target=lambda: box.update(reg=pathsafe.is_regular_file(fifo),
                                                        txt=pathsafe.read_regular_text(fifo)),
                             daemon=True)
        t.start()
        t.join(5)
        self.assertFalse(t.is_alive(), "pathsafe opened/blocked on a FIFO (must never open a non-regular)")
        self.assertFalse(box["reg"])
        self.assertIsNone(box["txt"])


class TestGrade(unittest.TestCase):
    def setUp(self):
        self.d = Path(tempfile.mkdtemp(prefix="pathsafe-grade-"))
        self.addCleanup(lambda: __import__("shutil").rmtree(self.d, ignore_errors=True))

    def test_absent_is_absent(self):
        self.assertEqual(pathsafe.grade(self.d / "nope"), "absent")

    def test_readable_file_and_dir_are_ok(self):
        f = self.d / "f.txt"
        f.write_text("x")
        self.assertEqual(pathsafe.grade(f), "ok")
        self.assertEqual(pathsafe.grade(self.d), "ok")

    @unittest.skipIf(os.getuid() == 0, "root bypasses permission bits")
    def test_unreadable_dir_is_unverified(self):
        os.chmod(self.d, 0o000)
        try:
            self.assertEqual(pathsafe.grade(self.d), "unverified")
        finally:
            os.chmod(self.d, 0o700)

    @unittest.skipIf(os.getuid() == 0, "root bypasses permission bits")
    def test_unreadable_file_is_unverified(self):
        f = self.d / "secret"
        f.write_text("x")
        os.chmod(f, 0o000)
        try:
            self.assertEqual(pathsafe.grade(f), "unverified")
        finally:
            os.chmod(f, 0o644)

    @unittest.skipUnless(hasattr(os, "mkfifo"), "no mkfifo")
    def test_fifo_is_unverified_and_never_hangs(self):
        fifo = self.d / "pipe"
        os.mkfifo(fifo)
        box = {}
        t = threading.Thread(target=lambda: box.__setitem__("r", pathsafe.grade(fifo)), daemon=True)
        t.start()
        t.join(5)
        self.assertFalse(t.is_alive(), "grade opened/blocked on a FIFO")
        self.assertEqual(box["r"], "unverified")


class _Tree(unittest.TestCase):
    def setUp(self):
        self.d = Path(tempfile.mkdtemp(prefix="pathsafe-guards-")).resolve()
        self.addCleanup(lambda: __import__("shutil").rmtree(self.d, ignore_errors=True))


class TestTrustedAncestor(_Tree):
    """Check what is accepted as an ancestor."""

    def test_a_real_directory_is_trusted(self):
        (self.d / "real").mkdir()
        self.assertTrue(pathsafe.trusted_ancestor(self.d / "real"))

    def test_a_link_this_user_could_have_planted_is_not(self):
        (self.d / "real").mkdir()
        (self.d / "link").symlink_to(self.d / "real")
        self.assertFalse(pathsafe.trusted_ancestor(self.d / "link"))

    def test_a_file_is_not_an_ancestor(self):
        (self.d / "f").write_text("x")
        self.assertFalse(pathsafe.trusted_ancestor(self.d / "f"))

    def test_a_missing_path_is_not_trusted(self):
        self.assertFalse(pathsafe.trusted_ancestor(self.d / "nope"))

    def test_a_dangling_link_is_not_trusted(self):
        (self.d / "dangling").symlink_to(self.d / "nope")
        self.assertFalse(pathsafe.trusted_ancestor(self.d / "dangling"))


class TestReachedWhereItWasNamed(_Tree):
    """Check a path whose ancestors are plain, and one redirected partway."""

    def test_a_plain_chain_is_reached(self):
        (self.d / "a" / "b").mkdir(parents=True)
        self.assertTrue(pathsafe.reached_where_it_was_named(self.d / "a" / "b" / "c"))

    def test_a_link_partway_along_redirects_it(self):
        (self.d / "real").mkdir()
        (self.d / "a").symlink_to(self.d / "real")
        self.assertFalse(pathsafe.reached_where_it_was_named(self.d / "a" / "b"))


class TestEveryFileArrived(_Tree):
    """Check what a complete and an incomplete copy report."""

    def _pair(self):
        src, dst = self.d / "s", self.d / "d"
        (src / "a").mkdir(parents=True)
        (dst / "a").mkdir(parents=True)
        (src / "a" / "f.txt").write_text("x")
        return src, dst

    def test_a_complete_copy_arrived(self):
        src, dst = self._pair()
        (dst / "a" / "f.txt").write_text("x")
        self.assertTrue(pathsafe.every_file_arrived(src, dst))

    def test_a_partial_copy_did_not(self):
        src, dst = self._pair()
        self.assertFalse(pathsafe.every_file_arrived(src, dst))

    def test_a_symlink_missing_from_the_copy_is_not_counted(self):
        src, dst = self._pair()
        (dst / "a" / "f.txt").write_text("x")
        (src / "link").symlink_to(src / "a" / "f.txt")
        self.assertTrue(pathsafe.every_file_arrived(src, dst))

    def test_a_source_it_could_not_read_is_never_called_arrived(self):
        src, dst = self._pair()
        (dst / "a" / "f.txt").write_text("x")
        self.assertTrue(pathsafe.every_file_arrived(src, dst))
        os.chmod(src / "a", 0)
        self.addCleanup(os.chmod, src / "a", stat.S_IRWXU)
        self.assertFalse(pathsafe.every_file_arrived(src, dst))

    def test_a_source_that_is_not_there_is_never_called_arrived(self):
        _src, dst = self._pair()
        self.assertFalse(pathsafe.every_file_arrived(self.d / "missing", dst))


if __name__ == "__main__":
    unittest.main()
