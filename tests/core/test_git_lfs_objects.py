#!/usr/bin/env python3
"""A Git LFS pointer is resolved to the object the repository keeps, and only to that object."""
from __future__ import annotations

import hashlib
import os
import subprocess
import tempfile
import unittest
from pathlib import Path

from stayawake.lib.git import lfs


def pointer(content: bytes) -> bytes:
    return (b"version https://git-lfs.github.com/spec/v1\n"
            b"oid sha256:" + hashlib.sha256(content).hexdigest().encode() + b"\n"
            b"size " + str(len(content)).encode() + b"\n")


def keep(store: Path, content: bytes) -> Path:
    oid = hashlib.sha256(content).hexdigest()
    path = store / oid[:2] / oid[2:4] / oid
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(content)
    return path


class TestPointers(unittest.TestCase):

    def test_pointers_are_recognised_as_git_lfs_reads_them(self):
        tail = b"\noid sha256:" + b"0" * 64 + b"\nsize 12\n"
        for header in (b"version https://git-lfs.github.com/spec/v1",
                       b"version https://hawser.github.com/spec/v1",
                       b"\n\nversion https://git-lfs.github.com/spec/v1"):
            self.assertTrue(lfs.is_pointer(header + tail), header)
        self.assertFalse(lfs.is_pointer(b"version 1.2.3\n"))
        self.assertFalse(lfs.is_pointer(
            b"version https://git-lfs.github.com/spec/v1" + tail + b"x" * 2000))

    def test_a_pointer_names_its_object(self):
        self.assertEqual((hashlib.sha256(b"abc").hexdigest(), 3), lfs.pointed_object(pointer(b"abc")))
        for bad in (b"oid sha256:" + b"g" * 64, b"oid sha256:../../etc", b"oid sha1:" + b"0" * 64):
            data = b"version https://git-lfs.github.com/spec/v1\n" + bad + b"\nsize 3\n"
            self.assertIsNone(lfs.pointed_object(data), bad)


class TestLocalObjects(unittest.TestCase):

    def setUp(self):
        self.store = Path(tempfile.mkdtemp(prefix="saw-lfs-"))
        self.addCleanup(subprocess.run, ["rm", "-rf", str(self.store)])

    def test_the_object_a_pointer_names_is_found(self):
        path = keep(self.store, b"payload")
        self.assertEqual(path, lfs.local_object(self.store, pointer(b"payload")))

    def test_an_object_that_does_not_match_its_pointer_is_not_used(self):
        path = keep(self.store, b"payload")
        path.write_bytes(b"pAyload")
        self.assertIsNone(lfs.local_object(self.store, pointer(b"payload")))
        path.write_bytes(b"payload!")
        self.assertIsNone(lfs.local_object(self.store, pointer(b"payload")))

    def test_a_missing_or_linked_object_is_not_used(self):
        self.assertIsNone(lfs.local_object(self.store, pointer(b"absent")))
        real = self.store / "real"
        real.write_bytes(b"payload")
        oid = hashlib.sha256(b"payload").hexdigest()
        link = self.store / oid[:2] / oid[2:4] / oid
        link.parent.mkdir(parents=True)
        os.symlink(real, link)
        self.assertIsNone(lfs.local_object(self.store, pointer(b"payload")))

    def test_a_repository_names_its_store(self):
        repo = self.store / "repo"
        subprocess.run(["git", "init", "-q", str(repo)], check=True)
        self.assertEqual((repo / ".git" / "lfs" / "objects").resolve(),
                         lfs.store_of(repo).resolve())


if __name__ == "__main__":
    unittest.main()
