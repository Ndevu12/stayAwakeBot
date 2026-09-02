#!/usr/bin/env python3
"""Module-level, picklable worker functions for the parallel scan pool."""
from __future__ import annotations

import io
from contextlib import redirect_stderr, redirect_stdout
from dataclasses import dataclass, field

from stayawake.bots.security.models import Finding, ScanResult
from stayawake.bots.security.scanner import attach_history_note, run_matchers, scan_target
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
    opts: object
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
        attach_history_note(result, job.root, job.opts, job.signatures, job.allowlist)
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


#
# A single big LOCAL target is decomposed into MatcherJobs run in parallel and merged back into one
# ScanResult via scanner.finalize. Two shapes of job, ONE worker (`collect_partial`):
#   * a FILE-CHUNK job — `include` set → the partitionable (per-file) matchers over just those files;
#   * a WHOLE-MATCHER job — `include` None → one whole-target matcher (git history / lockfile audit /
#     symlink walk) over the FULL target, run exactly once.
# Each returns RAW per-matcher findings + the chunk's read_errors/coverage_notes; the orchestrator
# concatenates them and calls scanner.finalize ONCE — so a parallel scan is byte-identical to a


@dataclass
class RawPartial:
    """One job's contribution to a target's scan: raw findings keyed by matcher (no allowlist/
    confidence/sort applied — that's finalize's job), plus the read_errors / coverage_notes the job's
    Target accumulated, plus any captured stray output to replay."""
    by_matcher: dict[str, list[Finding]]
    read_errors: list[str] = field(default_factory=list)
    coverage_notes: list[str] = field(default_factory=list)
    diagnostics: str = ""


@dataclass
class MatcherJob:
    """A unit of within-target work: run `matcher_names` over the target. `include` None = the FULL
    target (whole-target matchers); a tuple of relpaths = just that file-chunk (partitionable
    matchers). Picklable (spawn)."""
    root: str
    display: str
    opts: object
    matcher_names: tuple[str, ...]
    include: tuple[str, ...] | None
    signatures: dict
    all_sigs: list


def collect_partial(job: MatcherJob) -> RawPartial:
    buf = io.StringIO()
    with redirect_stdout(buf), redirect_stderr(buf):
        target = LocalRepoTarget(job.root, job.display, job.opts, include_only=job.include)
        by_matcher = run_matchers(target, list(job.matcher_names), job.signatures, job.all_sigs)
    return RawPartial(by_matcher, list(target.read_errors), list(target.coverage_notes),
                      buf.getvalue())
