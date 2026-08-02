#!/usr/bin/env python3
"""Parallel scanning (#1205): a `-j` sweep must be byte-identical to a sequential one, must fail
CLOSED if a worker dies, and a worker's stray output must never escape to corrupt the live board.
"""
from __future__ import annotations

import io
import json
import os
import subprocess
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest import mock

from stayawake.bots.security import service
from stayawake.bots.security.service import workers as scan_workers
from stayawake.bots.security.service.workers import WorkerScan, LocalScanJob
from stayawake.bots.security.models import ScanResult


def _make_repo(base: str, name: str, body: str) -> str:
    d = os.path.join(base, name)
    os.makedirs(d)
    subprocess.run(["git", "init", "-q", d], check=True)
    (Path(d) / "index.js").write_text(body)
    return d


# `var _$_ab12 = 1;` is the confirmed `loader-seed-var` signature — repeating it across files/repos
# produces many findings that TIE on (severity, path), the case a clean-only fixture can't exercise.
_LOADER = "var _$_ab12 = 1;\nvar _$_cd34 = 2;\n"


def _make_infected_repo(base: str, name: str) -> str:
    d = os.path.join(base, name)
    os.makedirs(d)
    subprocess.run(["git", "init", "-q", d], check=True)
    for fn in ("a.js", "b.js", "c.js"):
        (Path(d) / fn).write_text(_LOADER)
    return d


def _scan_json(paths, jobs) -> dict:
    buf = io.StringIO()
    with redirect_stdout(buf), redirect_stderr(io.StringIO()):
        service.scan(None, paths=paths, json_out=True, no_stream=True, jobs=jobs)
    payload = json.loads(buf.getvalue())
    payload.pop("generated_at", None)          # the only field that legitimately varies per run
    return payload


class TestDeterminism(unittest.TestCase):
    def test_parallel_scan_is_byte_identical_to_sequential(self):
        base = tempfile.mkdtemp(prefix="par-det-")
        self.addCleanup(lambda: __import__("shutil").rmtree(base, ignore_errors=True))
        paths = [_make_repo(base, f"repo-{c}",
                            f"// {c}\nconsole.log('{c}');\nmodule.exports = {{}};\n")
                 for c in "abcdef"]
        sequential = _scan_json(paths, jobs=1)
        parallel_ = _scan_json(paths, jobs=3)
        self.assertEqual(json.dumps(sequential, sort_keys=True),
                         json.dumps(parallel_, sort_keys=True))
        # ordering preserved (discovery order), independent of worker completion order
        self.assertEqual([r["target"] for r in sequential["results"]],
                         [r["target"] for r in parallel_["results"]])

    def test_findings_with_ties_are_byte_identical(self):
        # Clean repos can't catch a tie-ordering regression; this fleet has many findings that TIE
        # on (severity, path) plus a clean repo, so any non-deterministic tie order would diverge.
        base = tempfile.mkdtemp(prefix="par-ties-")
        self.addCleanup(lambda: __import__("shutil").rmtree(base, ignore_errors=True))
        paths = [_make_infected_repo(base, f"inf-{c}") for c in "abcd"]
        paths.append(_make_repo(base, "clean-z", "console.log('ok');\n"))
        seq = _scan_json(paths, jobs=1)
        par = _scan_json(paths, jobs=5)
        self.assertEqual(json.dumps(seq, sort_keys=True), json.dumps(par, sort_keys=True))
        self.assertTrue(any(r["findings"] for r in seq["results"]))   # the fixture really did fire


class TestWorkerOutputDiscipline(unittest.TestCase):
    def test_stray_worker_output_is_captured_not_leaked(self):
        d = tempfile.mkdtemp(prefix="par-silence-")
        self.addCleanup(lambda: __import__("shutil").rmtree(d, ignore_errors=True))

        import sys

        def noisy(target, sigs, allow):
            print("STRAY-STDOUT-LINE")
            print("STRAY-STDERR-LINE", file=sys.stderr)
            return ScanResult(target="t", source="local")

        real_err = io.StringIO()
        with mock.patch.object(scan_workers, "scan_target", side_effect=noisy), \
             redirect_stderr(real_err), redirect_stdout(io.StringIO()):
            ws = scan_workers.scan_local(
                LocalScanJob(root=d, display="t", opts=_opts(), signatures={}, allowlist=[]))
        # The stray output is captured on the result, NOT written to the real streams (which would
        # corrupt the parent's live progress board).
        self.assertIn("STRAY-STDOUT-LINE", ws.diagnostics)
        self.assertIn("STRAY-STDERR-LINE", ws.diagnostics)
        self.assertNotIn("STRAY", real_err.getvalue())


class TestFailClosed(unittest.TestCase):
    def test_worker_exception_becomes_error_result_and_exit_2(self):
        base = tempfile.mkdtemp(prefix="par-fail-")
        self.addCleanup(lambda: __import__("shutil").rmtree(base, ignore_errors=True))
        repo = _make_repo(base, "repo-x", "console.log('ok');\n")
        # One target → inline path → the patch applies in-process; a raising worker must fail CLOSED.
        with mock.patch.object(scan_workers, "scan_local",
                               side_effect=RuntimeError("worker exploded")), \
             redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            rc = service.scan(None, paths=[repo], no_stream=True, jobs=1)
        self.assertEqual(rc, 2)                    # errored target never reads as clean

    @unittest.skipIf(getattr(os, "geteuid", lambda: 1)() == 0, "root can read mode-000 files")
    def test_unreadable_file_fails_closed_through_the_real_pool(self):
        # A scan GAP (unreadable file) must fail closed even on the multi-worker PROCESS path — the
        # committed single-target test only exercises the inline path. Two targets force the pool.
        base = tempfile.mkdtemp(prefix="par-unread-")
        self.addCleanup(lambda: __import__("shutil").rmtree(base, ignore_errors=True))
        good = _make_repo(base, "good", "console.log('ok');\n")
        bad = _make_repo(base, "bad", "console.log('ok');\n")
        blocked = Path(bad) / "loader.js"
        blocked.write_text("var _$_ab12 = 1;\n")
        os.chmod(blocked, 0o000)
        try:
            with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
                rc = service.scan(None, paths=[good, bad], no_stream=True, jobs=2)
            self.assertEqual(rc, 2)                 # unreadable file → gap → fail closed via the pool
        finally:
            os.chmod(blocked, 0o644)


def _opts():
    from stayawake.bots.security.targets import ScanOptions
    return ScanOptions()


if __name__ == "__main__":
    unittest.main()
