#!/usr/bin/env python3
"""A file checkout skips only content scanned clean at the same path, under the same policy."""
from __future__ import annotations

import json
import os
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from stayawake.bots.security import clean_contents

_POLICY = "policy-a"
_LARGEST = 1024


class _Tree(unittest.TestCase):
    def setUp(self):
        self.base = Path(tempfile.mkdtemp(prefix="clean-contents-")).resolve()
        self.addCleanup(shutil.rmtree, self.base, ignore_errors=True)
        cache = mock.patch.dict(os.environ, {"XDG_CACHE_HOME": str(self.base / "cache")})
        cache.start()
        self.addCleanup(cache.stop)
        self.root = self.base / "tree"
        self.root.mkdir()

    def _write(self, rel: str, text: str = "x\n") -> None:
        (self.root / rel).write_text(text)

    def _scanned_clean(self, *paths: str) -> None:
        _, checked = clean_contents.unknown(self.root, paths, _LARGEST, _POLICY)
        self.assertTrue(clean_contents.remember(self.root, checked, _POLICY))

    def _left(self, *paths: str, policy: str = _POLICY) -> tuple[str, ...]:
        return clean_contents.unknown(self.root, paths, _LARGEST, policy)[0]


class TestWhatAFileCheckoutLeavesToScan(_Tree):
    def test_content_scanned_clean_at_the_same_path_is_set_aside(self):
        self._write("a.js")
        self._write("b.js")
        self._scanned_clean("a.js")
        self.assertEqual(self._left("a.js", "b.js"), ("b.js",))

    def test_other_content_at_that_path_is_scanned(self):
        self._write("a.js")
        self._scanned_clean("a.js")
        self._write("a.js", "changed\n")
        self.assertEqual(self._left("a.js"), ("a.js",))

    def test_the_same_content_at_another_path_is_scanned(self):
        self._write("a.js")
        self._scanned_clean("a.js")
        self._write("b.js")
        self.assertEqual(self._left("b.js"), ("b.js",))

    def test_content_scanned_under_another_policy_is_scanned(self):
        self._write("a.js")
        self._scanned_clean("a.js")
        self.assertEqual(self._left("a.js", policy="policy-b"), ("a.js",))

    def test_a_link_is_always_scanned(self):
        self._write("a.js")
        os.symlink("a.js", self.root / "link.js")
        self._scanned_clean("a.js", "link.js")
        self.assertEqual(self._left("a.js", "link.js"), ("link.js",))

    def test_a_file_larger_than_a_scan_reads_is_always_scanned(self):
        self._write("big.js", "x" * (_LARGEST + 1))
        self._scanned_clean("big.js")
        self.assertEqual(self._left("big.js"), ("big.js",))

    def test_a_fifo_is_scanned_without_being_read(self):
        os.mkfifo(self.root / "pipe")
        self.assertEqual(self._left("pipe"), ("pipe",))

    def test_a_file_changed_while_it_was_read_is_scanned(self):
        self._write("a.js")
        self._scanned_clean("a.js")
        known = clean_contents.hookscript.digest_file(self.root / "a.js", _LARGEST)

        def read_then_changed(path, limit):
            os.utime(path, ns=(1, 1))
            return known

        with mock.patch.object(clean_contents.hookscript, "digest_file", side_effect=read_then_changed):
            self.assertEqual(self._left("a.js"), ("a.js",))

    def test_a_damaged_store_sets_nothing_aside(self):
        self._write("a.js")
        self._scanned_clean("a.js")
        for damaged in ("{", "[]", json.dumps({"version": 1, "policy": _POLICY, "clean": {"a.js": 7}})):
            clean_contents.store_path(self.root).write_text(damaged)
            self.assertEqual(self._left("a.js"), ("a.js",))


class TestWhatACleanScanRecords(_Tree):
    def test_a_file_changed_while_it_was_scanned_is_not_recorded(self):
        self._write("a.js")
        _, checked = clean_contents.unknown(self.root, ("a.js",), _LARGEST, _POLICY)
        os.utime(self.root / "a.js", ns=(1, 1))
        clean_contents.remember(self.root, checked, _POLICY)
        self.assertEqual(self._left("a.js"), ("a.js",))

    def test_a_path_gone_from_disk_is_forgotten(self):
        self._write("a.js")
        self._write("b.js")
        self._scanned_clean("a.js", "b.js")
        (self.root / "a.js").unlink()
        self._scanned_clean()
        self.assertEqual(set(clean_contents.held(self.root, _POLICY)), {"b.js"})


if __name__ == "__main__":
    unittest.main()
