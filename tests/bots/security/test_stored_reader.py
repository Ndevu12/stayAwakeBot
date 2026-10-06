#!/usr/bin/env python3
"""A stored version is read the way the same bytes on disk are read."""
from __future__ import annotations

import random
import subprocess
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

from stayawake.bots.security import version_scan
from stayawake.bots.security.remediation import oracle
from stayawake.bots.security.signatures import load_signatures
from stayawake.bots.security.targets import ScanOptions
from stayawake.bots.security.targets.base import Target
from stayawake.bots.security.targets.history import HistoryTarget

LOADER = "global['_V']=function(x){return x};require('child_process').exec('id');\n"
FILLER = "// " + "a" * 96 + "\n"


class _Store(unittest.TestCase):

    def setUp(self):
        self.root = Path(tempfile.mkdtemp(prefix="saw-stored-reader-"))
        self.addCleanup(subprocess.run, ["rm", "-rf", str(self.root)])
        self.repo = self.root / "repo"
        self.repo.mkdir()
        self.git("init", "-q")
        self.git("config", "user.email", "t@example.com")
        self.git("config", "user.name", "t")

    def git(self, *args) -> str:
        return subprocess.run(["git", "-C", str(self.repo), *args], check=True,
                              capture_output=True, text=True).stdout

    def store(self, files: dict[str, bytes]) -> dict[str, str]:
        for path, data in files.items():
            (self.repo / path).parent.mkdir(parents=True, exist_ok=True)
            (self.repo / path).write_bytes(data)
        self.git("add", "-A")
        self.git("commit", "-qm", "store")
        return {path: self.git("rev-parse", f"HEAD:{path}").strip() for path in files}


class TestLargeStoredCode(_Store):

    def _large_code(self) -> bytes:
        half = FILLER * (1_500_000 // len(FILLER))
        return (half + LOADER + half).encode()

    def test_a_large_stored_file_of_any_kind_is_read_in_full(self):
        sigs = load_signatures()
        for path in ("app.js", "blob.dat", "bin/tool"):
            with self.subTest(path=path):
                oids = self.store({path: self._large_code()})
                batch = [SimpleNamespace(path=path, oid=oids[path], link=False)]
                found = version_scan.scan_batch(self.repo, "repo", batch, [],
                                                oracle.payload_matchers(sigs), [], ScanOptions())
                self.assertEqual([path], [f.path for f, _e in found.findings
                                          if f.confidence == "confirmed"][:1])
                self.assertFalse(found.unread)


class TestTheSameWindowsOnDiskAndInTheStore(_Store):

    def test_stored_and_checkout_windows_are_the_same(self):
        rng = random.Random(1688)
        opts = ScanOptions()
        opts.max_file_bytes = 4096
        for n in (4097, 6143, 6144, 6145, 8192, 20481, 2048 * 37 + 1):
            data = bytes(rng.choice(b"ab\n\x00c{}();\xff") for _ in range(n))
            oids = self.store({"f.js": data})
            on_disk = list(Target(self.repo, "repo", opts).read_source_windows("f.js"))
            stored = list(HistoryTarget(self.repo, "repo", opts, {"f.js": [oids["f.js"]]})
                          .read_source_windows("f.js"))
            self.assertEqual(on_disk, stored, n)
            self.assertGreater(len(stored), 1)


class TestWindowsCoverTheWholeFile(unittest.TestCase):

    def test_windows_overlap_and_the_last_is_a_full_window_at_the_end(self):
        from io import BytesIO
        from stayawake.bots.security.targets import base
        rng = random.Random(315)
        window = 4096
        overlap = min(base._SOURCE_WINDOW_OVERLAP, window // 2)
        for n in (4096, 4097, 6144, 6145, 8192, 20481):
            data = "".join(rng.choice("ab\nc{}();") for _ in range(n))
            got = list(base.stream_windows(BytesIO(data.encode()).read, n, window))
            starts, at = [], 0
            for offset, text in got:
                at = data.index(text, at)
                self.assertEqual(data.count("\n", 0, at), offset, (n, at))
                starts.append(at)
            ends = [s + len(t) for s, (_o, t) in zip(starts, got)]
            self.assertEqual(0, starts[0], n)
            self.assertEqual((n, min(n, window)), (ends[-1], len(got[-1][1])), n)
            for k in range(1, len(got)):
                self.assertGreaterEqual(ends[k - 1] - starts[k], overlap, (n, k))


class TestAStoredReadCutShortIsUnread(unittest.TestCase):

    def test_a_stream_that_ends_early_is_recorded_unread(self):
        from io import BytesIO
        from unittest import mock

        class Proc:
            returncode = 0

            def __init__(self):
                self.stdout = BytesIO(b"x" * 5000)

            def kill(self):
                pass

            def __enter__(self):
                return self

            def __exit__(self, *exc):
                return False

        opts = ScanOptions()
        opts.max_file_bytes = 4096
        target = HistoryTarget(Path("/repo"), "repo", opts, {"f.js": ["a" * 40]})
        target.sizes = {"a" * 40: 10_000}
        with mock.patch.object(HistoryTarget, "_cat_file", side_effect=lambda _sha: Proc()):
            list(target.read_source_windows("f.js"))
        self.assertIn("f.js", target.read_errors)


class TestTheStoreIsAskedOnlyAboutLargeVersions(_Store):

    def test_a_small_version_is_read_without_asking_its_size(self):
        from unittest import mock
        oids = self.store({"a.js": b"var a = 1;\n"})
        target = HistoryTarget(self.repo, "repo", ScanOptions(), {"a.js": [oids["a.js"]]})
        with mock.patch.object(HistoryTarget, "_size", side_effect=AssertionError("asked")):
            self.assertEqual([(0, "var a = 1;\n")], list(target.read_source_windows("a.js")))

    def test_a_large_version_of_unknown_size_is_recorded_unread(self):
        from unittest import mock
        opts = ScanOptions()
        opts.max_file_bytes = 4096
        oids = self.store({"big.js": b"// pad\n" * 2000})
        target = HistoryTarget(self.repo, "repo", opts, {"big.js": [oids["big.js"]]})
        with mock.patch.object(HistoryTarget, "_size", return_value=None):
            list(target.read_source_windows("big.js"))
        self.assertIn("big.js", target.read_errors)


class TestGitLfsPointers(unittest.TestCase):

    def test_pointers_are_recognised_as_git_lfs_reads_them(self):
        tail = b"\noid sha256:" + b"0" * 64 + b"\nsize 12\n"
        for header in (b"version https://git-lfs.github.com/spec/v1",
                       b"version https://hawser.github.com/spec/v1",
                       b"\n\nversion https://git-lfs.github.com/spec/v1"):
            self.assertTrue(version_scan.is_lfs_pointer(header + tail), header)
        self.assertFalse(version_scan.is_lfs_pointer(b"version 1.2.3\n"))
        self.assertFalse(version_scan.is_lfs_pointer(
            b"version https://git-lfs.github.com/spec/v1" + tail + b"x" * 2000))


if __name__ == "__main__":
    unittest.main()
