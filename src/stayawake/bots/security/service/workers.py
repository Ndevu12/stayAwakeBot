#!/usr/bin/env python3
"""Module-level, picklable worker functions for the parallel scan pool."""
from __future__ import annotations

import io
import os
import stat as _stat
from contextlib import redirect_stderr, redirect_stdout
from dataclasses import dataclass, field

from stayawake.bots.security.models import Finding, ScanResult
from stayawake.bots.security.scanner import attach_history_note, run_matchers, scan_target
from stayawake.bots.security.targets import LocalRepoTarget, RemoteRepoTarget
from stayawake.bots.security.matchers import REGISTRY
from stayawake.bots.security.resolution import LocalTarget


@dataclass
class WorkerScan:
    """One target's scan result plus any stdout/stderr it emitted (to be replayed by the
    orchestrator after the progress board closes)."""
    result: ScanResult
    diagnostics: str = ""


@dataclass
class LocalScanJob:
    """Picklable descriptor for scanning one on-disk target: the scope, and how to report it.

    The scope travels whole. Carried as loose fields beside it, each consumer re-derived what to
    run and what to disclose, and they disagreed.
    """
    scope: LocalTarget
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


NOTHING_TO_READ = (
    "nothing here could be read, so this target carries no verdict — a gap, not a clean result. "
    "The coverage notes say what was skipped and why"
)

def _holds_content(p) -> bool:
    """Whether an entry is something a scan can read or grade.

    A FIFO or a device `exists()`, so a directory holding only those read as CLEAN while nothing
    had been opened. A symlink counts: the matcher grades it without reading it.
    """
    try:
        st = os.lstat(p)
    except OSError:
        return False
    return _stat.S_ISREG(st.st_mode) or _stat.S_ISLNK(st.st_mode)


# The workflow matcher anchors on this pair in code rather than in the signature data, so it is
# named here; everything else is read from whatever signatures are loaded.
_ANCHORS_IN_CODE = frozenset({".github", "workflows"})


def anchored_segments(signatures: dict) -> frozenset[str]:
    """Directory names a signature's path anchor keys on."""
    out = set(_ANCHORS_IN_CODE)
    for group in signatures.values():
        for sig in group or []:
            for glob in (sig.get("file_globs") or []):
                parts = glob.split("/")
                out.update(p for p in parts[:-1] if p and "*" not in p)
    return frozenset(out)


def unsure_reason(scope: LocalTarget, signatures: dict) -> str | None:
    """Why this scope cannot assert `clean`, or None when it can.

    A check that keys on where a file sits is measured from the scan's root. With no project above
    the named path, that root is the named path — and if the path it sits in still carries one of
    those directory names, the anchor was cut and those checks could not be evaluated. A note
    beside `clean` does not carry that; the exit code has to.
    """
    if scope.paths_are_project_relative:
        return None
    cut = sorted(anchored_segments(signatures) & set(scope.scan_root.parts))
    if not cut:
        return None
    return (f"this path sits inside `{'`, `'.join(cut)}` and nothing above it is a repository, so "
            "the checks that key on where a file sits in a project could not be evaluated here — "
            "scan the folder the project starts at to get them")


def notes_for(scope: LocalTarget, pruned: set[str]) -> list[str]:
    """Every disclosure a scope owes the operator, for both scan paths.

    Composed once: the sequential path and the parallel one each used to assemble their own list,
    and the parallel one was missing a rule every time a rule was added.
    """
    return [n for n in (scope.unlooked_at(), scope.where_paths_are_from(),
                        scope.destination_note(),
                        None if scope.is_repo else pruning_note(pruned)) if n]


def pruning_note(pruned: set[str]) -> str | None:
    """What a named directory's own walk skipped by name.

    Inside a repository these are the standard exclusions and the scan says so elsewhere; when the
    operator named the directory itself, a `dist` under a `dist` is dropped in silence otherwise.
    """
    if not pruned:
        return None
    return (f"Directories named {', '.join(sorted(pruned))} under this one were not walked "
            "(the standard exclusions), so nothing inside them was read.")



# Not partitionable, but it judges a file ENTRY, so it answers about a named file — and dropping it
# would lose a write-redirect link that IS the named path.
_ANSWERS_ABOUT_ONE_FILE = frozenset({"symlink", "dependency-audit"})

_ASKS_GIT_ABOUT_THE_TREE = frozenset({"git-history"})


def matchers_for_target(signatures: dict, scope: LocalTarget) -> dict:
    """The signatures whose matchers may run over a target of this shape.

    A link into a write-sink is not special-cased here: `Target` refuses to open one, so a matcher
    that tries reads nothing. Two authorities for one decision is what this scope object exists to
    stop.
    """
    if scope.names_one_file:
        return {k: v for k, v in signatures.items()
                if k in REGISTRY and (REGISTRY[k].partitionable or k in _ANSWERS_ABOUT_ONE_FILE)}
    if not scope.is_repo:
        return {k: v for k, v in signatures.items() if k not in _ASKS_GIT_ABOUT_THE_TREE}
    return signatures


def read_as(scope: LocalTarget, display: str, opts, *,
            include_only: tuple[str, ...] | None) -> LocalRepoTarget:
    """The reader a scope is scanned through — the one place a scope becomes a Target.

    `include_only` is passed explicitly because a within-target chunk overrides it: None there
    means the full walk, not the scope's own file list.
    """
    target = LocalRepoTarget(str(scope.root), display, opts,
                             include_only=include_only, within=scope.within)
    target.is_repo = scope.is_repo
    target.names_one_file = scope.names_one_file
    return target


def scan_local(job: LocalScanJob) -> WorkerScan:
    scope = job.scope
    buf = io.StringIO()
    with redirect_stdout(buf), redirect_stderr(buf):
        with read_as(scope, job.display, job.opts, include_only=scope.include_only) as target:
            nothing_to_read = not scope.is_repo and not any(
                _holds_content(target.root / rel) for rel in target.iter_files())
            result = scan_target(target, matchers_for_target(job.signatures, scope), job.allowlist)
            pruned = set(target.pruned_dirs)
        if scope.is_repo and not scope.names_one_file:
            attach_history_note(result, str(scope.root), job.opts, job.signatures, job.allowlist)
        # Two independent reasons a target carries no verdict. Chained onto the history branch they
        # silently replaced it, which is how the note went missing for every repository scan.
        if nothing_to_read and not result.findings:
            result.error = NOTHING_TO_READ
        elif not result.error:
            result.error = unsure_reason(scope, job.signatures)
        # Attached either way: a target where EVERYTHING was skipped is the one that owes the
        # operator the reason, and it was the one branch that dropped it.
        result.notes.extend(notes_for(scope, pruned))
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
    scope: LocalTarget
    display: str
    opts: object
    matcher_names: tuple[str, ...]
    include: tuple[str, ...] | None
    signatures: dict
    all_sigs: list


def collect_partial(job: MatcherJob) -> RawPartial:
    buf = io.StringIO()
    with redirect_stdout(buf), redirect_stderr(buf):
        target = read_as(job.scope, job.display, job.opts, include_only=job.include)
        by_matcher = run_matchers(target, list(job.matcher_names), job.signatures, job.all_sigs)
    return RawPartial(by_matcher, list(target.read_errors), list(target.coverage_notes),
                      buf.getvalue())
