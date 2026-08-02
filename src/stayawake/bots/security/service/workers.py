#!/usr/bin/env python3
"""Module-level, picklable worker functions for the parallel scan pool.

`utils.parallel`'s PROCESS backend uses a `spawn` context, so the mapped function must be
importable by qualified name and its arguments picklable — hence plain module-level functions
here (not closures in the orchestrator).

Each worker scans ONE target and returns a `WorkerScan`: the `ScanResult` plus any text the
scan wrote to stdout/stderr, CAPTURED. Capture matters because a pool worker inherits the
parent's stderr, so a stray diagnostic print inside a matcher (e.g. the obfuscation
delta-analysis skip notes) would otherwise corrupt the parent's live progress board. The
orchestrator replays the captured text to stderr AFTER the board closes — so nothing is lost,
the board is never corrupted, and the report on stdout stays byte-identical.

Capture uses `contextlib.redirect_*`, which swaps the process-global `sys.stdout`/`sys.stderr`;
that is safe here because each PROCESS worker is single-threaded (and the jobs<=1 inline path
runs one at a time on the main thread). These workers must NOT be reused under a THREAD backend,
where the redirect would race across threads.
"""
from __future__ import annotations

import io
from contextlib import redirect_stderr, redirect_stdout
from dataclasses import dataclass, field

from stayawake.bots.security.models import ScanResult
from stayawake.bots.security.scanner import scan_target
from stayawake.bots.security.targets import LocalRepoTarget, RemoteRepoTarget


@dataclass
class WorkerScan:
    """One target's scan result plus any stdout/stderr it emitted (to be replayed by the
    orchestrator after the progress board closes)."""
    result: ScanResult
    diagnostics: str = ""


@dataclass
class LocalScanJob:
    """Picklable descriptor for scanning one on-disk repo."""
    root: str
    display: str
    opts: object              # ScanOptions (dataclass; picklable)
    signatures: dict
    allowlist: list = field(default_factory=list)


@dataclass
class RemoteScanJob:
    """Picklable descriptor for cloning + scanning one GitHub repo."""
    slug: str
    opts: object
    token: str | None
    signatures: dict
    allowlist: list = field(default_factory=list)


def scan_local(job: LocalScanJob) -> WorkerScan:
    buf = io.StringIO()
    with redirect_stdout(buf), redirect_stderr(buf):
        with LocalRepoTarget(job.root, job.display, job.opts) as target:
            result = scan_target(target, job.signatures, job.allowlist)
    return WorkerScan(result, buf.getvalue())


def scan_remote(job: RemoteScanJob) -> WorkerScan:
    buf = io.StringIO()
    with redirect_stdout(buf), redirect_stderr(buf):
        target = RemoteRepoTarget(job.slug, job.opts, job.token)
        try:
            result = (scan_target(target, job.signatures, job.allowlist) if target.clone()
                      else ScanResult(target=job.slug, source="remote", error="clone failed"))
        finally:
            target.cleanup()
    return WorkerScan(result, buf.getvalue())
