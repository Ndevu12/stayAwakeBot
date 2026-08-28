#!/usr/bin/env python3
"""Shared path-safety read primitives (utils.pathsafe): the FIFO-safe regular-file guard (#1226)
every arbitrary-file read now reuses instead of hand-rolling `stat + S_ISREG`."""
from __future__ import annotations

import os
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


if __name__ == "__main__":
    unittest.main()
