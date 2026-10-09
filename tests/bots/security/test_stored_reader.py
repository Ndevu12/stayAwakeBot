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


def _lfs_pointer(content: bytes) -> str:
    import hashlib
    return ("version https://git-lfs.github.com/spec/v1\noid sha256:"
            + hashlib.sha256(content).hexdigest() + "\nsize " + str(len(content)) + "\n")


def _keep_lfs_object(git_dir: Path, content: bytes) -> None:
    import hashlib
    oid = hashlib.sha256(content).hexdigest()
    path = Path(git_dir) / "lfs" / "objects" / oid[:2] / oid[2:4] / oid
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(content)


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


class TestABinaryIsReadAtItsEnds(_Store):

    def test_a_large_binary_is_read_at_its_ends_and_text_in_full(self):
        opts = ScanOptions()
        opts.max_file_bytes = 4096
        binary = b"\x89PNG\x00\x00" + b"ab\n" * 6000
        text = b"ab\n" * 6000
        oids = self.store({"img.dat": binary, "notes.dat": text})
        for rel, many in (("img.dat", False), ("notes.dat", True)):
            on_disk = list(Target(self.repo, "repo", opts).read_source_windows(rel))
            stored = list(HistoryTarget(self.repo, "repo", opts, {rel: [oids[rel]]})
                          .read_source_windows(rel))
            self.assertEqual(many, len(on_disk) > 1, rel)
            self.assertEqual(on_disk, stored, rel)


class TestGitLfsContentIsRead(_Store):

    def _scan(self, path, kept):
        content = (FILLER * 15_000 + LOADER + FILLER * 15_000).encode()
        if kept:
            _keep_lfs_object(self.repo / ".git", content)
        oids = self.store({path: _lfs_pointer(content).encode()})
        batch = [SimpleNamespace(path=path, oid=oids[path], link=False)]
        sigs = load_signatures()
        return version_scan.scan_batch(self.repo, "repo", batch, [], oracle.payload_matchers(sigs),
                                       [], ScanOptions())

    def test_a_version_kept_in_git_lfs_here_is_read_in_full(self):
        found = self._scan("assets/app.js", kept=True)
        self.assertEqual(["assets/app.js"], [f.path for f, _e in found.findings
                                             if f.confidence == "confirmed"][:1])
        self.assertFalse(found.outside_git)

    def test_a_version_kept_in_git_lfs_elsewhere_is_named(self):
        found = self._scan("assets/app.js", kept=False)
        self.assertFalse(found.findings)
        self.assertEqual({"assets/app.js"}, found.outside_git)

    def test_a_pointer_carrying_more_lines_is_read_as_itself(self):
        clean = (FILLER * 50).encode()
        _keep_lfs_object(self.repo / ".git", clean)
        oids = self.store({"bin/run": _lfs_pointer(clean).encode() + LOADER.encode()})
        batch = [SimpleNamespace(path="bin/run", oid=oids["bin/run"], link=False)]
        found = version_scan.scan_batch(self.repo, "repo", batch, [],
                                        oracle.payload_matchers(load_signatures()), [], ScanOptions())
        self.assertIn("bin/run", [f.path for f, _e in found.findings if f.confidence == "confirmed"])
        self.assertFalse(found.outside_git)

    def test_each_form_git_lfs_reads_has_its_object_read(self):
        bad = (FILLER * 50 + LOADER).encode()
        _keep_lfs_object(self.repo / ".git", bad)
        crlf = _lfs_pointer(bad).replace("\n", "\r\n").encode()
        larger = _lfs_pointer(bad).encode() + b"\n" * 1100 + FILLER.encode()
        both = _lfs_pointer(bad).encode() + LOADER.encode()
        oids = self.store({"assets/a.js": crlf, "assets/b.js": larger, "assets/c.js": both})
        batch = [SimpleNamespace(path=p, oid=oids[p], link=False) for p in oids]
        found = version_scan.scan_batch(self.repo, "repo", batch, [],
                                        oracle.payload_matchers(load_signatures()), [], ScanOptions())
        self.assertEqual({"assets/a.js", "assets/b.js", "assets/c.js"},
                         {f.path for f, _e in found.findings if f.confidence == "confirmed"})
        pairs = [(f.signature_id, f.path) for f, _e in found.findings]
        self.assertEqual(len(set(pairs)), len(pairs))

    def test_the_same_stored_bytes_are_read_at_every_path(self):
        clean = (FILLER * 50).encode()
        _keep_lfs_object(self.repo / ".git", clean)
        both = _lfs_pointer(clean).encode() + LOADER.encode()
        oids = self.store({"assets/a.js": both, "assets/b.js": both})
        batch = [SimpleNamespace(path=p, oid=oids[p], link=False) for p in oids]
        found = version_scan.scan_batch(self.repo, "repo", batch, [],
                                        oracle.payload_matchers(load_signatures()), [], ScanOptions())
        self.assertEqual({"assets/a.js", "assets/b.js"},
                         {f.path for f, _e in found.findings if f.confidence == "confirmed"})

    def test_a_second_read_that_fails_keeps_the_first_and_is_named(self):
        from unittest import mock
        from stayawake.bots.security.targets import history
        bad = (FILLER * 50 + LOADER).encode()
        _keep_lfs_object(self.repo / ".git", bad)
        oids = self.store({"assets/c.js": _lfs_pointer(bad).encode() + b"// more\n"})
        batch = [SimpleNamespace(path="assets/c.js", oid=oids["assets/c.js"], link=False)]
        with mock.patch.object(history._ReadBeside, "read_source_windows",
                               side_effect=RuntimeError("stopped")):
            found = version_scan.scan_batch(self.repo, "repo", batch, [],
                                            oracle.payload_matchers(load_signatures()), [],
                                            ScanOptions())
        self.assertIn("assets/c.js", [f.path for f, _e in found.findings if f.confidence == "confirmed"])
        self.assertIn("assets/c.js", found.unread)

    def test_a_form_git_lfs_reads_is_named_when_its_object_is_elsewhere(self):
        crlf = _lfs_pointer(b"elsewhere").replace("\n", "\r\n").encode()
        quoted = b"# Notes\n\n" + _lfs_pointer(b"elsewhere").encode()
        oids = self.store({"assets/a.js": crlf, "assets/b.js": crlf + b"\n" * 5000 + b"x",
                           "docs/lfs.md": quoted})
        batch = [SimpleNamespace(path=p, oid=oids[p], link=False) for p in oids]
        opts = ScanOptions()
        opts.max_file_bytes = 4096
        found = version_scan.scan_batch(self.repo, "repo", batch, [],
                                        oracle.payload_matchers(load_signatures()), [], opts)
        self.assertEqual({"assets/a.js", "assets/b.js"}, found.outside_git)

    def test_a_history_scan_reads_what_lfs_keeps_here_and_names_the_rest(self):
        from stayawake.bots.security import scanner
        content = (LOADER + FILLER).encode()
        _keep_lfs_object(self.repo / ".git", content)
        self.store({"kept.js": _lfs_pointer(content).encode(),
                    "absent.js": _lfs_pointer(b"elsewhere").encode()})
        note = scanner.history_residue_note(self.repo, ScanOptions(history=True),
                                            load_signatures(), [])
        self.assertIn("kept.js", note)
        self.assertIn("1 stored version(s) are kept in Git LFS", note)

    def test_a_history_scan_that_fails_is_never_reported_read(self):
        from unittest import mock
        from stayawake.bots.security import scanner
        from stayawake.bots.security.models import ScanResult
        self.store({"a.js": b"var a = 1;\n"})
        failed = ScanResult(target="repo", source="history", error="stopped")
        with mock.patch.object(scanner, "scan_target", return_value=failed):
            note = scanner.history_residue_note(self.repo, ScanOptions(history=True),
                                                load_signatures(), [])
        self.assertIn("UNKNOWN", note)


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
        for rel in ("f.js", "f.dat"):
            target = HistoryTarget(Path("/repo"), "repo", opts, {rel: ["a" * 40]})
            target.sizes = {"a" * 40: 10_000}
            with mock.patch.object(HistoryTarget, "_cat_file", side_effect=lambda _sha: Proc()):
                list(target.read_source_windows(rel))
            self.assertIn(rel, target.read_errors)


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


if __name__ == "__main__":
    unittest.main()
