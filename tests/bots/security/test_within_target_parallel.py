#!/usr/bin/env python3
"""Within-target file parallelism (#1325): scanning ONE big repo across file-chunks must be
byte-identical to a sequential scan, must fail CLOSED on an unreadable file even through the pool,
and must stay sequential below the file-count floor.
"""
from __future__ import annotations

import io
import json
import os
import shutil
import subprocess
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

from stayawake.bots.security import service
from stayawake.bots.security.service import run as run_mod

_LOADER = "var _$_ab12 = 1;\n"          # confirmed `loader-seed-var`


def _big_repo(base: str, n_files: int, infected_every: int = 12) -> str:
    """A git repo with `n_files` source files; every `infected_every`-th carries a loader payload
    (pass `infected_every=0` for a fully clean tree)."""
    d = os.path.join(base, "repo")
    subprocess.run(["git", "init", "-q", d], check=True)
    for i in range(n_files):
        sub = os.path.join(d, f"pkg{i % 20}", "src")
        os.makedirs(sub, exist_ok=True)
        body = "export const a = () => 1;\nfunction f(){return 2;}\n"
        if infected_every and i % infected_every == 0:
            body = _LOADER + body
        (Path(sub) / f"m{i}.js").write_text(body)
    return d


def _scan_json(path: str, jobs) -> dict:
    buf = io.StringIO()
    with redirect_stdout(buf), redirect_stderr(io.StringIO()):
        service.scan(None, paths=[path], json_out=True, no_stream=True, jobs=jobs)
    payload = json.loads(buf.getvalue())
    payload.pop("generated_at", None)
    return payload


class TestWithinTargetDeterminism(unittest.TestCase):
    def test_parallel_single_target_is_byte_identical_to_sequential(self):
        base = tempfile.mkdtemp(prefix="wt-det-")
        self.addCleanup(lambda: shutil.rmtree(base, ignore_errors=True))
        # Above the 256-file floor so -j>1 actually decomposes into file-chunks.
        repo = _big_repo(base, 320)
        seq = _scan_json(repo, jobs=1)
        par = _scan_json(repo, jobs=8)
        self.assertEqual(json.dumps(seq, sort_keys=True), json.dumps(par, sort_keys=True))
        total = sum(len(r["findings"]) for r in seq["results"])
        self.assertGreater(total, 0, "fixture must actually produce findings to be a real test")


class TestWithinTargetFailClosed(unittest.TestCase):
    @unittest.skipIf(getattr(os, "geteuid", lambda: 1)() == 0, "root can read mode-000 files")
    def test_unreadable_file_fails_closed_through_the_chunk_pool(self):
        base = tempfile.mkdtemp(prefix="wt-fail-")
        self.addCleanup(lambda: shutil.rmtree(base, ignore_errors=True))
        repo = _big_repo(base, 300, infected_every=0)   # CLEAN, so the only signal is the read GAP
        blocked = Path(repo) / "pkg0" / "src" / "secret.js"
        blocked.write_text("export const ok = 1;\n")
        os.chmod(blocked, 0o000)
        try:
            with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
                rc = service.scan(None, paths=[repo], no_stream=True, jobs=8)
            self.assertEqual(rc, 2)   # a gap in one chunk → whole target fails closed (not clean)
        finally:
            os.chmod(blocked, 0o644)


class TestThresholdAndChunking(unittest.TestCase):
    def test_below_floor_stays_sequential_but_still_detects(self):
        base = tempfile.mkdtemp(prefix="wt-small-")
        self.addCleanup(lambda: shutil.rmtree(base, ignore_errors=True))
        repo = _big_repo(base, 30)                 # < 256 → sequential path even at -j 8
        payload = _scan_json(repo, jobs=8)
        total = sum(len(r["findings"]) for r in payload["results"])
        self.assertGreater(total, 0)               # detection still works on the sequential path

    def test_balanced_chunks_cover_every_file_exactly_once(self):
        base = tempfile.mkdtemp(prefix="wt-chunk-")
        self.addCleanup(lambda: shutil.rmtree(base, ignore_errors=True))
        for i in range(50):
            (Path(base) / f"f{i}.js").write_text("x" * (i * 10))   # varied sizes
        files = [f"f{i}.js" for i in range(50)]
        chunks = run_mod._balanced_chunks(base, files, nchunks=4)
        flat = [f for c in chunks for f in c]
        self.assertEqual(sorted(flat), sorted(files))              # no file lost or duplicated
        self.assertLessEqual(len(chunks), 4)
        self.assertTrue(all(c for c in chunks))                    # no empty chunk returned

    def test_file_workers_resolution(self):
        self.assertEqual(run_mod._file_workers(1), 1)              # -j 1 → sequential
        self.assertEqual(run_mod._file_workers(3), 3)              # explicit cap
        self.assertGreaterEqual(run_mod._file_workers(None), 1)    # auto → >=1 (cores)

    def test_balanced_chunks_spread_zero_and_uniform_size_files(self):
        # Regression: with the size-only heap key, equal/zero-size files all piled onto chunk 0 (no
        # parallelism). The file-count tiebreaker must spread them evenly across chunks.
        base = tempfile.mkdtemp(prefix="wt-uniform-")
        self.addCleanup(lambda: shutil.rmtree(base, ignore_errors=True))
        for i in range(40):
            (Path(base) / f"e{i}.js").write_text("")              # all 0 bytes
        files = [f"e{i}.js" for i in range(40)]
        chunks = run_mod._balanced_chunks(base, files, nchunks=4)
        self.assertEqual(len(chunks), 4)                          # all 4 used, not piled on one
        self.assertEqual(sorted(f for c in chunks for f in c), sorted(files))
        sizes = [len(c) for c in chunks]
        self.assertLessEqual(max(sizes) - min(sizes), 1)         # evenly spread


class TestReadErrorMessageDeterminism(unittest.TestCase):
    def test_finalize_read_errors_message_is_dedup_sorted_and_order_independent(self):
        from stayawake.bots.security import scanner
        # A file is read-attempted by several matchers (duplicates); parallel chunks accumulate in a
        # different order than a sequential walk. The message must be identical regardless.
        seq_order = ["a.js: PermissionError", "b.js: PermissionError", "c.js: PermissionError"]
        par_order = ["b.js: PermissionError", "b.js: PermissionError",   # dup, out of order
                     "c.js: PermissionError", "a.js: PermissionError"]
        r_seq = scanner.finalize("t", "local", {}, [], seq_order, [], None, None, [], [])
        r_par = scanner.finalize("t", "local", {}, [], par_order, [], None, None, [], [])
        self.assertEqual(r_seq.error, r_par.error)               # order/dup-independent
        self.assertIn("3 file(s) unreadable", r_seq.error)       # DISTINCT-file count, not attempts
        self.assertLess(r_seq.error.index("a.js"), r_seq.error.index("b.js"))  # sorted sample


if __name__ == "__main__":
    unittest.main()
