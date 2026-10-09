#!/usr/bin/env python3
"""`saw fix amend` — replace past commits that still carry the payload and force-update
each branch they sat on. Never `--pr`. Never moves a tag. Bare `saw fix` is unchanged.
"""
from __future__ import annotations

import contextlib
import time
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Callable, NamedTuple

from stayawake.bots.security import version_scan
from stayawake.bots.security.models import CONFIRMED
from stayawake.utils import scratch
from stayawake.bots.security.pr import arrival_questions, arrival_record
from stayawake.bots.security.pr.resolve import REMOVE, RESTORE, SUPPLY
from stayawake.bots.security.remediation import (delivery, changes, footprint, installed, live,
                                                 oracle, preserve)
from stayawake.bots.security.pr.fix_verdict import Checkout, checkout_clauses, checkout_of
from stayawake.bots.security.scanner import scan_target
from stayawake.bots.security.targets import LocalRepoTarget
from stayawake.bots.security.targets.base import is_source_path
from stayawake.lib.git.auth import run_remote_git
from stayawake.lib.git.borrowed import BorrowError, borrow
from stayawake.lib.git.objects import read_blobs
from stayawake.lib.git import remote as gitremote
from stayawake.lib.git.run import LOCAL_TIMEOUT, UNTRUSTED
from stayawake.bots.security.pr.outcome import (AmendOutcome, BranchResult, Cause, Reason,
                                                amended, names_that_fit, refused,
                                                render_amend_line, with_checkout)
from stayawake.lib.git import authority
from stayawake.lib.git import pushed
from stayawake.lib.git.write import amend as gitamend
from stayawake.lib.git.write import rebuild as gitrebuild
from stayawake.lib.git.write.capture import capture_bundle
from stayawake.lib.git.write.push import PushResult, force_update_head, publish_head
from stayawake.lib.git.write import sign
from stayawake.lib.git.write.replace import replacement_tree, write_blob_bytes
from stayawake.lib import git as gitutil


def _payload_left(repo: Path, olds, rebuilt, rewritten: list[tuple[str, str]],
                  path_checks: dict, remove=()) -> tuple[list[str], list[str]]:
    """What the rebuilt objects still leave reaching the payload, checked before any reference
    moves. `olds` are the pre-rewrite carrying commits; `rewritten` pairs each branch to deliver with
    its rebuilt tip; `path_checks` maps each corrected path to its own check, answering True, False
    or None when it could not tell; `remove` maps a path to the foreign blob that must be gone from
    the tree. Returns what still reaches it, and what could not be confirmed either way."""
    left, unsure = [], []
    remove = remove or {}
    for old in sorted(olds):
        for name, tip in sorted(rewritten):
            known = gitutil.ancestry(repo, old, tip)
            if known is None:
                unsure.append(f"the rewritten branch {name}")
            elif known:
                left.append(f"{old[:12]} is still reachable from the rebuilt history")
    for sha in sorted(set(rebuilt.mapping.values())):
        for path in sorted(path_checks):
            verdict = path_checks[path](sha, path)
            if verdict is None:
                unsure.append(f"the rewritten {path}")
            elif verdict:
                left.append(f"{sha[:12]} still carries {path}")
        for path in sorted(remove):
            verdict = _holds(repo, sha, path, remove[path])
            if verdict is None:
                unsure.append(f"the rewritten {path}")
            elif verdict:
                left.append(f"{sha[:12]} still holds {path}")
    return left, unsure


def _judged(verdict) -> bool | None:
    """Read the `survives` oracle's answer as carries, clean, or not known. Takes the answer.
    Returns True, False, or None for a version it could not judge."""
    return None if oracle.could_not_judge(verdict) else bool(verdict)


def _unread(path: str) -> gitutil.Unread:
    return gitutil.Unread(f"every copy of {path}")


def _stored_entry(repo: Path, treeish: str, path: str) -> tuple[str, str] | None:
    """The `(mode, oid)` a commit stores at a path, or None when nothing is there. Raises `Unread`
    naming every copy of the path when git could not answer."""
    answered, entry = gitutil.entry_at(repo, treeish, path)
    if not answered:
        raise _unread(path)
    return entry


def _stored_text(repo: Path, treeish: str, path: str) -> str:
    """The text of the file a commit stores at a path, "" when no file is there. Raises `Unread`
    naming every copy of the path when git could not read it."""
    found = gitutil.file_text_at(repo, treeish, path)
    if found is None:
        raise _unread(path)
    return found[1]


@contextlib.contextmanager
def _naming_unread(unread: list[str]):
    """Run one path's step; when git could not read what it needs, name that in `unread` and go on."""
    try:
        yield
    except gitutil.Unread as missed:
        if missed.subject not in unread:
            unread.append(missed.subject)


def _carries_in(repo: Path, treeish: str, path: str, carries) -> bool | None:
    """Ask whether a stored version of a file carries a footprint. Takes the repo, the commit, the
    path and the footprint check. Returns the answer, False when no file is there, or None when git
    could not read it."""
    found = gitutil.file_text_at(repo, treeish, path)
    if found is None:
        return None
    return bool(found[0]) and bool(carries(found[1]))


def _holds(repo: Path, treeish: str, path: str, oid: str) -> bool | None:
    """Ask whether a commit holds exactly one blob at a path. Takes the repo, the commit, the path
    and the blob id. Returns the answer, or None when git could not read the tree."""
    answered, entry = gitutil.entry_at(repo, treeish, path)
    if not answered:
        return None
    return entry is not None and entry[1] == oid


def _payload_blobs(repo: Path, remove: dict, substitute: dict, purge_holders: dict, clean: dict,
                   clean_shas, merge_payload: tuple[set[str], list[str]]) -> tuple[set[str], list[str]]:
    """Collect the payload versions this run takes out of history. Takes the repo, the blobs removed
    and substituted, the commits holding each purged path, the excised paths with their footprint
    checks, the commits carrying those footprints, and the payload versions of the paths merge
    sweeps remove with what git could not walk for them. Returns their blob ids, and the paths whose
    version git could not read."""
    oids = set(remove.values()) | {fo for fo, _e in substitute.values()} | merge_payload[0]
    unsure: list[str] = list(merge_payload[1])
    held = [(path, sha) for path, holders in purge_holders.items() for sha in holders]
    for path, sha in held:
        answered, entry = gitutil.entry_at(repo, sha, path)
        if not answered:
            unsure.append(f"every copy of {path}")
        elif entry is not None:
            oids.add(entry[1])
    for path, (carries, _c) in clean.items():
        for sha in clean_shas:
            found = gitutil.file_text_at(repo, sha, path)
            if found is None:
                unsure.append(f"every copy of {path}")
            elif found[0] and carries(found[1]):
                oids.add(found[0])
    return oids, unsure


def _merge_payload(repo: Path, swept: dict, anchored: dict, survives) -> tuple[set[str], list[str]]:
    """Find the payload versions of the paths merge sweeps remove. Takes the repo, each merge with
    its swept paths, each merge with its confirmed payload paths, and the `survives` oracle. Returns
    their blob ids, and what git could not walk; when the history could not be walked, each swept
    path's version at its merge counts."""
    paths = sorted({p for ps in swept.values() for p in ps})
    oids: set[str] = set()
    unread: list[str] = []
    if not paths:
        return oids, unread
    at_merge = [(p, merge) for merge, ps in anchored.items() for p in ps]
    try:
        versions = gitutil.path_versions(repo, paths)
    except gitutil.Unread as missed:
        versions = None
        unread.append(missed.subject)
    if versions is None:
        if not unread:
            unread.extend(f"every copy of {p}" for p in paths)
        at_merge = [(p, merge) for merge, ps in swept.items() for p in ps]
    else:
        for path, by_blob in versions.items():
            oids.update(blob for blob, commit in by_blob.items() if survives(commit, path))
    for path, merge in at_merge:
        answered, entry = gitutil.entry_at(repo, merge, path)
        if not answered:
            unread.append(f"every copy of {path}")
        elif entry is not None:
            oids.add(entry[1])
    return oids, unread


def _arrived_versions(repo: Path, swept: dict, payload_oids: set[str]) -> tuple[set[str], list[str]]:
    """Find the versions merge sweeps remove that are neither a confirmed payload nor empty. Takes the
    repo, each merge with its swept paths, and the payload's blob ids. Returns their blob ids, and
    what git could not read."""
    oids: set[str] = set()
    unread: list[str] = []
    for merge, paths in swept.items():
        for path in paths:
            answered, entry = gitutil.entry_at(repo, merge, path)
            if not answered:
                unread.append(f"every copy of {path}")
            elif (entry is not None and not entry[0].startswith(("040", "160"))
                  and entry[1] not in payload_oids):
                oids.add(entry[1])
    if oids:
        _bodies, sizes = read_blobs(repo, sorted(oids), max_each=0, max_total=0)
        oids = {oid for oid in oids if sizes.get(oid, 1) > 0}
    return oids, unread


_REWRITTEN_VERSIONS = "the versions the rewritten history holds"
_PAST_VERSIONS = "the repository's past commits"
_PAST_VERSIONS_READ = 5_000


@dataclass
class _HistoryPayloads:
    """Hold what reading the versions in a rewrite's history found.

    `take_out` maps each confirmed whole-file version, as `(path, blob)`, to the commits that add
    it; `excise` maps each path whose confirmed versions are repaired in place to its
    `(carries, corrector)`; `repaired` are the `(path, blob)` versions either step repairs; `manual`
    names the confirmed versions no step repairs, kept as `(path, blob)` in `named`; `judged` are the
    versions read and `confirmed` those found malicious; `region` maps the commits read to their
    parents; `unread`
    names what could not be read; `partly_read` are the paths read only in part or kept outside
    git, and `runnable` those of them that run as programs; `submodules` counts the submodule
    versions read past; `on_other_refs` are the confirmed blobs found only in commits that refs and
    checkouts other than branches reach; `cut_at` is the number of versions a bounded read stopped
    at, or 0.
    """

    take_out: dict = field(default_factory=dict)
    excise: dict = field(default_factory=dict)
    repaired: set = field(default_factory=set)
    manual: list = field(default_factory=list)
    named: set = field(default_factory=set)
    judged: set = field(default_factory=set)
    confirmed: set = field(default_factory=set)
    region: dict = field(default_factory=dict)
    unread: list = field(default_factory=list)
    partly_read: set = field(default_factory=set)
    runnable: set = field(default_factory=set)
    submodules: int = 0
    on_other_refs: set = field(default_factory=set)
    cut_at: int = 0


def _rewrite_boundary(plan) -> list[str]:
    """List the commits just before a rewrite. Takes the `(commit, parents)` plan. Returns the
    parents of each plan commit none of whose parents is in the plan."""
    inside = {sha for sha, _ps in plan}
    return sorted({p for _sha, ps in plan if not any(q in inside for q in ps) for p in ps})


def _note_decided(repo: Path, treeish: str, path: str, decided: set, undecided: set,
                  unread: list[str]) -> None:
    """Record the version of a file another step decides about. Takes the repo, the commit that step
    reads, the path, the `(path, blob)` set to fill, the set of paths whose version git could not
    read, and the list naming what could not be read."""
    try:
        entry = _stored_entry(repo, treeish, path)
    except gitutil.Unread as missed:
        undecided.add(path)
        if missed.subject not in unread:
            unread.append(missed.subject)
        return
    if entry is not None:
        decided.add((path, entry[1]))


def _confirmed_versions(repo: Path, display: str, tips, boundary, signatures, allowlist, opts,
                        skip, out: _HistoryPayloads, *, subject: str = _REWRITTEN_VERSIONS,
                        limit: int | None = None) -> list:
    """Read every version the history from a boundary to some tips adds, except those `skip(path,
    oid)` leaves to another step. Takes the repo, how it is shown, the tips, the boundary commits,
    the signatures, allowlist and scan options, the skip check, the `_HistoryPayloads` to fill, what
    to call the history when it cannot be read, and a bound on the newest versions read. Returns
    each confirmed finding with its version."""
    commits = pushed.commits_between(repo, list(tips), list(boundary))
    listed = (pushed.history_entries(repo, commits, **({"limit": limit} if limit else {}))
              if commits is not None else None)
    if listed is None:
        out.unread.append(subject)
        return []
    out.region.update(commits)
    entries, submodules, whole = listed
    out.submodules += submodules
    if not whole and limit:
        out.cut_at = limit
    elif not whole:
        out.unread.append(subject)
    return _scan_versions(repo, display, entries, signatures, allowlist, opts, skip, out)


def _scan_versions(repo: Path, display: str, entries, signatures, allowlist, opts, skip,
                   out: _HistoryPayloads) -> list:
    """Scan stored versions for confirmed payloads, except those `skip(path, oid)` leaves to another
    step. Takes the repo, how it is shown, the versions, the signatures, allowlist and scan options,
    the skip check and the `_HistoryPayloads` whose `judged`, `confirmed`, `unread`, `partly_read`
    and `runnable` it fills. Returns each confirmed finding with its version."""
    fresh = [e for e in entries if not skip(e.path, e.oid)]
    out.judged |= {(e.path, e.oid) for e in fresh}
    payload = oracle.payload_matchers(signatures)
    confirmed = []
    for batch in version_scan.batches(fresh):
        result = version_scan.scan_batch(repo, display, batch, [], payload, allowlist, opts)
        out.unread += [f"every copy of {p}" for p in sorted(result.unread)]
        found_here: set[str] = set()
        for finding, entry in result.findings:
            if (getattr(finding, "confidence", None) != CONFIRMED
                    or getattr(finding, "advisory_only", False)):
                continue
            if entry is None:
                out.unread.append(f"every copy of {getattr(finding, 'path', '') or '?'}")
            else:
                found_here.add(entry.path)
                out.confirmed.add((entry.path, entry.oid))
                confirmed.append((finding, entry))
        out.partly_read |= (result.in_part - found_here) | result.outside_git
        out.runnable |= result.runnable - found_here
    return confirmed


def _partly_read_reasons(partly: set[str], runnable: set[str], found_at: set[str],
                         submodules: int) -> list[Reason]:
    """Name the past versions read only in part or not at all. Takes their paths, those of them that
    run as programs, the paths where malware was found and the count of submodule versions. Returns
    a reason for those to review and one for the rest."""
    to_review = sorted(p for p in partly if p in found_at or is_source_path(p) or p in runnable)
    noted = sorted(partly - set(to_review))
    reasons = [Reason(Cause.SUBMODULES_NOT_READ, str(submodules))] if submodules else []
    if to_review:
        reasons.append(Reason(Cause.HISTORY_PARTLY_READ, str(len(to_review)),
                              names_that_fit(to_review)))
    if noted:
        reasons.append(Reason(Cause.LARGE_FILES_NOT_READ_IN_FULL, str(len(noted)),
                              names_that_fit(noted)))
    return reasons


def _read_past_commits(repo: Path, display: str, signatures, allowlist, opts, skip,
                       owned_paths: set[str], out: _HistoryPayloads) -> None:
    """Read the repository's past commits, newest first and up to a bound, and place each confirmed
    version a branch holds. Takes the repo, how it is shown, the signatures, allowlist and scan
    options, the skip check, the paths another step already rewrites and the `_HistoryPayloads` to
    fill. A version the checkout still holds is named for recovery by hand, and one only other refs
    or checkouts hold is recorded in `on_other_refs`."""
    listed = gitutil.listed_branch_refs(repo)
    if listed is None:
        out.unread.append(_PAST_VERSIONS)
        return
    tips = [ref for _n, ref in listed]
    _read_other_refs(repo, display, signatures, allowlist, opts, skip, out)
    if not tips:
        return
    for finding, entry in _confirmed_versions(repo, display, tips, [],
                                              signatures, allowlist, opts, skip, out,
                                              subject=_PAST_VERSIONS, limit=_PAST_VERSIONS_READ):
        try:
            held = _stored_entry(repo, "HEAD", entry.path)
        except gitutil.Unread as missed:
            out.unread.append(missed.subject)
            continue
        if held is not None and held[1] == entry.oid:
            out.manual.append(f"{entry.path} in {entry.commit[:12]}")
            out.named.add((entry.path, entry.oid))
            continue
        _place_history_finding(repo, finding, entry, signatures, allowlist, opts, owned_paths, out)


def _read_other_refs(repo: Path, display: str, signatures, allowlist, opts, skip,
                     out: _HistoryPayloads) -> None:
    """Read what only refs and checkouts other than branches reach: their past commits, and the
    files a ref pointing at a tree or a file holds. Takes the repo, how it is shown, the signatures,
    allowlist and scan options, the skip check and the `_HistoryPayloads` whose `on_other_refs`,
    `unread`, `partly_read`, `runnable`, `submodules` and `cut_at` it fills."""
    listed = gitutil.listed_branch_refs(repo)
    candidates, unsure = _candidate_refs(repo)
    if listed is None:
        out.unread.append(_PAST_VERSIONS)
        return
    out.unread += unsure
    tips = [ref for _n, ref in listed]
    others = sorted({tip for _n, tip in candidates} - set(tips))
    if not others:
        return
    targets = pushed.tip_versions(repo, others, limit=_PAST_VERSIONS_READ)
    if targets is None:
        out.unread.append(_PAST_VERSIONS)
        return
    commits, held, submodules, whole = targets
    elsewhere = _HistoryPayloads(submodules=submodules, cut_at=0 if whole else _PAST_VERSIONS_READ)
    found = (_confirmed_versions(repo, display, commits, tips, signatures, allowlist, opts, skip,
                                 elsewhere, subject=_PAST_VERSIONS, limit=_PAST_VERSIONS_READ)
             if commits else [])
    found += _scan_versions(repo, display, held, signatures, allowlist, opts, skip, elsewhere)
    out.on_other_refs |= {entry.oid for _finding, entry in found}
    out.unread += elsewhere.unread
    out.partly_read |= elsewhere.partly_read
    out.runnable |= elsewhere.runnable
    out.submodules += elsewhere.submodules
    out.cut_at = out.cut_at or elsewhere.cut_at


def _place_history_finding(repo: Path, finding, entry, signatures, allowlist, opts,
                           owned_paths: set[str], out: _HistoryPayloads) -> None:
    """Decide how a confirmed version in history is repaired: in place when a repair leaves it clean,
    or taken out whole. Takes the repo, the finding, the version, the signatures, allowlist
    and scan options, the paths another step already rewrites, and the `_HistoryPayloads` to fill."""
    key = (entry.path, entry.oid)
    repair = changes.repair_for(finding)
    if footprint.foreign_path(finding) or (repair is not None and repair.action == "remove"):
        out.take_out.setdefault(key, set()).add(entry.commit)
        out.repaired.add(key)
        return
    text = gitutil.blob_text(repo, entry.oid)
    flat = _flat(signatures)
    known = out.excise.get(entry.path)
    fixes = ([Repair(*known)] if known is not None else
             [_repair_checks(finding, flat),
              Repair(footprint.carries_code_loader(flat),
                     footprint.code_loader_corrector(entry.path, flat))])
    for fix in fixes:
        if (entry.path in owned_paths or fix.corrector is None or fix.carries is None
                or text is None or not fix.carries(text)):
            continue
        cleaned = fix.corrector(text)
        if (cleaned is not None and not fix.carries(cleaned)
                and not oracle.content_confirms(cleaned.encode("utf-8", "surrogateescape"),
                                                entry.path, oracle.payload_matchers(signatures),
                                                allowlist, opts)):
            out.excise[entry.path] = (fix.carries, fix.corrector)
            out.repaired.add(key)
            return
    if entry.path in owned_paths or entry.path in out.excise:
        out.manual.append(f"{entry.path} in {entry.commit[:12]}")
        out.named.add(key)
        return
    out.take_out.setdefault(key, set()).add(entry.commit)
    out.repaired.add(key)


def _reached_from(graph: list[tuple[str, list[str]]], tips) -> set[str]:
    """Find the commits of a graph that some tips reach. Takes the `(commit, parents)` graph and the
    tips. Returns their ids."""
    parents = dict(graph)
    seen: set[str] = set()
    stack = [tip for tip in tips if tip in parents]
    while stack:
        sha = stack.pop()
        if sha not in seen:
            seen.add(sha)
            stack.extend(parents.get(sha, ()))
    return seen


def _branches_carrying_any(repo: Path, infected) -> list[tuple[str, str, str]] | None:
    """Every branch that reaches ANY of the infected commits, each named once.

    A branch is rebuilt from the oldest payload it carries, so a branch reaching two of them is
    still one branch to move. None when git could not tell which branches reach one of them.
    """
    heads: dict[str, tuple[str, str, str]] = {}
    for sha in infected:
        carrying = gitutil.branches_carrying(repo, sha)
        if carrying is None:
            return None
        for name, tip, cas_old in carrying:
            heads.setdefault(name, (name, tip, cas_old))
    return list(heads.values())


def _flat(signatures) -> list:
    """The signature list, whether given as the by-matcher map or already flat."""
    if isinstance(signatures, dict):
        return [s for group in signatures.values() for s in group]
    return list(signatures or [])


def _committed_anywhere(repo: Path, path: str) -> bool:
    """Whether any commit a branch reaches holds `path`. Takes the repository and the path. Returns
    True when that cannot be established."""
    found = gitutil.run(repo, ["rev-list", "--all", "-n", "1", "--", path])
    return found is None or found.returncode != 0 or bool(found.stdout.strip())


def _same_checkout(holder: Path, repo: Path) -> bool:
    """Whether two paths name the same working tree. Takes both. Returns the answer."""
    try:
        return Path(holder).resolve() == Path(repo).resolve()
    except OSError:
        return False


def _committed_scan(repo: Path, opts, signatures, allowlist):
    """A scan of the files HEAD records, written out exactly as stored. Takes the repository, the
    scan options, the signatures and the allowlist. Returns the result, or None when HEAD could
    not be written out."""
    head = gitutil.stdout(repo, ["rev-parse", "--verify", "--quiet", "HEAD^{commit}"]).strip()
    if not head:
        return None
    dest = scratch.new_dir("the files HEAD records")
    try:
        with borrow(repo) as borrowed:
            if not borrowed.materialise(head, dest):
                return None
        target = LocalRepoTarget(dest, str(repo), opts)
        target.is_repo = False
        return scan_target(target, signatures, allowlist)
    except BorrowError:
        return None
    finally:
        scratch.release_path(dest)


def _add_file_findings(scan, committed) -> None:
    """Add to `scan` each file finding `committed` makes that `scan` does not. Takes both
    results."""
    seen = {(f.path, f.signature_id) for f in scan.findings}
    scan.findings.extend(f for f in committed.findings
                         if not getattr(f, "commit_sha", None)
                         and (f.path, f.signature_id) not in seen)


class Repair(NamedTuple):
    """How a finding's file is made clean in place: `carries(text)` says the payload is present,
    `corrector(text)` returns the cleaned text. Both are None when the finding has no such repair."""

    carries: Callable[[str], bool] | None
    corrector: Callable[[str], str | None] | None


class ContentTarget(NamedTuple):
    """A confirmed finding this verb excises in place, with its repair and the cleaned HEAD text."""

    finding: object
    carries: Callable[[str], bool]
    corrector: Callable[[str], str | None]
    cleaned: str


class Operator(NamedTuple):
    """How this amend reaches the operator and the remote: the push callback, the session credential
    for the authority gate, where the operator's own git config lives, and the interactive resolver."""

    pusher: Callable | None = None
    identity_fallback: str | None = None
    operator_context: Path | None = None
    resolver: Callable | None = None


def _repair_checks(finding, flat) -> Repair:
    """The in-place repair for a finding this verb edits, or an empty `Repair`. Takes the finding
    and the flat signatures. The footprint's own excision comes first; otherwise the text repair the
    working-tree fix makes."""
    corrector = footprint.corrector_for(finding, flat)
    carries = footprint.carries_footprint(finding, flat)
    if corrector is not None and carries is not None:
        return Repair(carries, corrector)
    repair = changes.repair_for(finding)
    edit = changes.text_repair(repair.action) if repair is not None else None
    if edit is None:
        return Repair(None, None)
    return Repair(lambda text: edit(text) is not None, edit)


def _content_targets(repo: Path, scan, signatures, unread: list[str]) -> list[ContentTarget]:
    """Confirmed file findings this verb can excise, one per path and only where the corrector clears
    the footprint at HEAD. A path git could not read is named in `unread`."""
    flat = _flat(signatures)
    out: list[ContentTarget] = []
    seen: set[str] = set()
    for f in scan.findings:
        if getattr(f, "confidence", None) != CONFIRMED or getattr(f, "advisory_only", False):
            continue
        path = getattr(f, "path", "") or ""
        if not path or path in seen or getattr(f, "commit_sha", None):
            continue
        repair = _repair_checks(f, flat)
        if repair.corrector is None or repair.carries is None:
            continue
        with _naming_unread(unread):
            head = _stored_text(repo, "HEAD", path)
            if not repair.carries(head):
                continue
            cleaned = repair.corrector(head)
            if cleaned is None or repair.carries(cleaned):
                continue
            seen.add(path)
            out.append(ContentTarget(f, repair.carries, repair.corrector, cleaned))
    return out


def _predates_content_targets(repo: Path, scan, signatures, allowlist, opts,
                              already: set[str], unread: list[str]) -> list[tuple]:
    """Confirmed commit-finding payload paths a code-loader corrector provably clears, as
    `(path, carries, corrector)`. The corrector is derived from the path, not the finding's category,
    and proven on the flagged commit's own blob; a path it cannot clear is left out. The cleaned blob
    is then re-scanned in full, so a path whose file carries a second, co-resident payload of another
    class is left out too. `already` are the paths the HEAD content and remove lanes own; a path git
    could not read is named in `unread`."""
    flat = _flat(signatures)
    payload = oracle.payload_matchers(signatures)
    out = []
    seen: set[str] = set()
    for finding, anchors in delivery.confirmed_commits(scan.findings):
        sha = getattr(finding, "commit_sha", None)
        if not sha:
            continue
        carries = footprint.carries_code_loader(flat)
        for path in anchors:
            if not path or path in already or path in seen:
                continue
            with _naming_unread(unread):
                blob = _stored_text(repo, sha, path)
                if not carries(blob):
                    continue
                corrector = footprint.code_loader_corrector(path, flat)
                cleaned = corrector(blob)
                if cleaned is None or carries(cleaned):
                    continue
                if oracle.content_confirms(cleaned.encode("utf-8"), path, payload, allowlist, opts):
                    continue
                seen.add(path)
                out.append((path, carries, corrector))
    return out


def _delivered_removals(replacements: dict, delivered_reach: set[str],
                        remove_holders: dict[str, set[str]],
                        purge_holders: dict[str, set[str]] | None = None) -> set[str]:
    """Paths the delivered branches actually dropped: each delivered replacement's removed paths, plus
    every whole-file or carrying-version removal whose holding commits a delivered branch reaches.
    Names only what a delivered branch removed, never a path dropped solely on an isolated branch."""
    held = dict(remove_holders)
    for path, holders in (purge_holders or {}).items():
        held[path] = held.get(path, set()) | holders
    out = {p for p, holders in held.items() if holders & delivered_reach}
    for sha, repl in replacements.items():
        if sha in delivered_reach:
            out.update(repl.removed)
    return out


def _register_removal(repo: Path, path: str, remove: dict, remove_shas: set,
                      remove_holders: dict, treeish: str = "HEAD") -> str:
    """Schedule `path` to be dropped wherever history holds the blob it has at `treeish`, recording
    the commits that hold it. Takes the repo, the path, the three removal maps to fill, and the
    treeish to key on. Returns "too-large" when the history is too long to walk, else ""."""
    entry = _stored_entry(repo, treeish, path)
    if entry is None:
        return ""
    return _register_blob_removal(repo, path, entry[1], remove, remove_shas, remove_holders)


def _register_blob_removal(repo: Path, path: str, oid: str, remove: dict, remove_shas: set,
                           remove_holders: dict, delivered_in: tuple[str, ...] = ()) -> str:
    """Schedule `path` to be dropped wherever history holds it at blob `oid`, recording the commits
    that hold it. Takes the repo, the path, the blob id, the three removal maps to fill, and
    optionally every id of the commit that delivered it, limiting the drop to that commit and the
    commits after it. Returns "too-large" when the history is too long to walk, else "". Raises
    `Unread` when git could not tell which copies came after the delivery, and `_DeliveryGone` when
    none of its ids is in history."""
    hist = _foreign_history(repo, path, oid)
    if hist is None:
        return "too-large"
    _holders, foreign = hist
    if delivered_in:
        foreign = _after_delivery(repo, path, foreign, delivered_in)
    if not foreign:
        return ""
    remove[path] = oid
    remove_shas.update(foreign)
    remove_holders[path] = set(foreign)
    return ""


class _DeliveryGone(Exception):
    """The commit that added a file has left history. Carries the file's path."""

    def __init__(self, path: str):
        super().__init__(path)
        self.path = path


def _after_delivery(repo: Path, path: str, holders, delivered_in) -> list[str]:
    """Keep the holders that are a delivery commit or come after one. Takes the repo, the path, the
    holders and every id of the delivery commit. Returns them. Raises `Unread` when git could not
    tell, and `_DeliveryGone` when none of the ids is in history."""
    after = []
    for sha in holders:
        answers = [gitutil.ancestry(repo, c, sha) for c in delivered_in]
        if True in answers:
            after.append(sha)
        elif None in answers:
            raise gitutil.Unread(f"which copies of {path} came with the malware")
    if not after:
        present = [gitutil.branches_carrying(repo, c) for c in delivered_in]
        if any(found is None for found in present):
            raise gitutil.Unread(f"which copies of {path} came with the malware")
        if not any(present):
            raise _DeliveryGone(path)
    return after


def _commits_after(repo: Path, plan, forms) -> set[str] | None:
    """Find the commits of a rebuild plan that are a delivery commit or come after one. Takes the
    repo, the `(commit, parents)` plan in parents-first order and every id of the delivery commit.
    Returns them, or None when git could not tell."""
    inside = {sha for sha, _ps in plan}
    out: set[str] = set()
    for sha, parents in plan:
        if sha in forms or any(p in out for p in parents):
            out.add(sha)
            continue
        for parent in parents:
            if parent in inside:
                continue
            answers = [gitutil.ancestry(repo, c, parent) for c in forms]
            if True in answers:
                out.add(sha)
                break
            if None in answers:
                return None
    return out


def _purge_carriers(repo: Path, path: str, survives) -> set[str] | None:
    """Walk `path`'s history and collect the commits whose version of it carries a payload. Takes the
    repo, the path, and the `survives` oracle that judges each version. Returns those commits, or None
    when the history is too long to walk."""
    found = delivery.commits_carrying(repo, path, survives)
    return None if found is None else set(found)


def _register_purge(repo: Path, path: str, purge: set, purge_shas: set, survives,
                    purge_holders: dict | None = None) -> str:
    """Schedule `path` to be dropped from every commit whose version of it carries a payload. Takes
    the repo, the path, the purge set and carrier set to fill, the `survives` oracle, and optionally a
    map recording which commits carried it. Returns "too-large" when the history is too long to walk,
    else ""."""
    carriers = _purge_carriers(repo, path, survives)
    if carriers is None:
        return "too-large"
    if not carriers:
        return ""
    purge.add(path)
    purge_shas.update(carriers)
    if purge_holders is not None:
        purge_holders[path] = set(carriers)
    return ""


def _register_merge_file_removal(repo: Path, merge: str, path: str, survives, purge: set,
                                 purge_shas: set, taken: dict, taken_shas: set,
                                 taken_holders: dict) -> tuple[str, bool]:
    """Schedule the removal an operator asked for of one file of a merge. Takes the repo, the merge,
    the path, the `survives` oracle, the purge set and carriers to fill, and the map, commits and
    holders to fill for the merge's own version. Returns "too-large" when the history is too long
    to walk, else "", and whether the merge's own version is scheduled."""
    entry = _stored_entry(repo, merge, path)
    if entry is None:
        return "", False
    carriers: dict[str, set[str]] = {}
    outcome = _register_purge(repo, path, purge, purge_shas, survives, carriers)
    if outcome or merge in carriers.get(path, ()):
        return outcome, not outcome
    outcome = _register_blob_removal(repo, path, entry[1], taken, taken_shas, taken_holders,
                                     (merge,))
    return outcome, not outcome and taken.get(path) == entry[1] \
        and merge in taken_holders.get(path, ())


def _register_operator_removal(repo: Path, path: str, remove: dict, remove_shas: set,
                               remove_holders: dict, purge: set, purge_shas: set, survives,
                               treeish: str = "HEAD", purge_holders: dict | None = None) -> str:
    """Schedule the removal an operator asked for: the version they were shown, and every other
    version of `path` that still carries a payload. Takes the repo, the path, the removal and purge
    collections to fill, the `survives` oracle, and the treeish they judged. Returns "too-large" when
    the history is too long to walk, else ""."""
    outcome = _register_removal(repo, path, remove, remove_shas, remove_holders, treeish)
    if outcome:
        return outcome
    return _register_purge(repo, path, purge, purge_shas, survives, purge_holders)


def _clean_ancestor(repo: Path, path: str, survives) -> tuple[tuple[str, str], str] | None:
    """Search `path`'s first-parent history, newest first, for the closest earlier version that
    differs from HEAD and carries no payload. Takes the repo, the path, and the `survives` oracle.
    Returns that version's tree entry with the short id of the commit it came from, or None when the
    history holds no such version."""
    head = _stored_entry(repo, "HEAD", path)
    head_oid = head[1] if head else None
    for sha in delivery.history_of(repo, path, first_parent=True) or ():
        answered, entry = gitutil.entry_at(repo, sha, path)
        if not answered or entry is None or entry[1] == head_oid:
            continue
        if not survives(sha, path):
            return entry, sha[:12]
    return None


def _register_substitute(repo: Path, path: str, entry: tuple[str, str], substitute: dict,
                         substitute_shas: set, treeish: str = "HEAD",
                         holders: dict | None = None) -> str:
    """Schedule `entry` to be put back wherever history holds `path` at the blob it has at `treeish`,
    recording the commits that hold it. Takes the repo, the path, the replacement tree entry, the two
    substitution maps to fill, the treeish to key on, and optionally a map recording which commits
    held it. Returns "too-large" when the history is too long to walk, else ""."""
    current = _stored_entry(repo, treeish, path)
    if current is None:
        return ""
    hist = _foreign_history(repo, path, current[1])
    if hist is None:
        return "too-large"
    _holders, foreign = hist
    if not foreign:
        return ""
    substitute[path] = (current[1], entry)
    substitute_shas.update(foreign)
    if holders is not None:
        holders[path] = set(foreign)
    return ""


def _register_supply(repo: Path, path: str, content: bytes, substitute: dict, substitute_shas: set,
                     payload, allowlist, opts, holders: dict | None = None) -> str:
    """Scan operator-supplied `content` and, when it carries no payload, schedule it to replace `path`
    wherever history holds the blob `path` has at HEAD. Takes the repo, the path, the content, the two
    substitution maps to fill, the scan inputs, and optionally a map recording which commits held
    it. Returns "carries" when the content itself carries a payload, "unwritable" when its blob
    cannot be written, "too-large" when the history is too long to walk, else ""."""
    if oracle.content_confirms(content, path, payload, allowlist, opts):
        return "carries"
    current = _stored_entry(repo, "HEAD", path)
    if current is None:
        return ""
    blob = write_blob_bytes(repo, content)
    if blob is None:
        return "unwritable"
    return _register_substitute(repo, path, (current[0], blob), substitute, substitute_shas,
                                holders=holders)


def _unhandled_items(repo: Path, scan, unhandled: set[str], survives=None, *,
                     unread: list[str]) -> list:
    """Build the operator's list of confirmed payloads saw could not remediate on its own, each
    offered for removal, restore, or replacement. Takes the repo, the scan, those paths, and
    optionally the `survives` oracle. Returns one `UncertainItem` per path present at HEAD, carrying
    the nearest clean version to restore when `survives` is given and one exists. A path git could
    not read is named in `unread`."""
    from stayawake.bots.security.pr.resolve import UncertainItem
    out: list = []
    seen: set[str] = set()
    for f in scan.findings:
        path = getattr(f, "path", "") or ""
        if path not in unhandled or path in seen:
            continue
        with _naming_unread(unread):
            entry = _stored_entry(repo, "HEAD", path)
            if entry is None:
                continue
            seen.add(path)
            restorable = _clean_ancestor(repo, path, survives) if survives is not None else None
            out.append(UncertainItem(
                path=path, category=getattr(f, "category", "") or "",
                signature_id=getattr(f, "signature_id", "") or "",
                description=getattr(f, "description", "") or "",
                preview=gitutil.blob(repo, entry[1]) or b"",
                confirmed=True, keep_content=True,
                restore_candidate=(restorable[0] if restorable else None),
                restore_source=(restorable[1] if restorable else "")))
    return out


def _path_items(repo: Path, paths, treeish: str, introduced_by: str = "", *,
                unread: list[str]) -> list:
    """Build the operator's list for the files a commit injected, each offered for removal. Takes the
    repo, the paths, the treeish to read them from, and the short id of the merge that introduced
    them. Returns one `UncertainItem` per path present at `treeish`; a path git could not read is
    named in `unread`."""
    from stayawake.bots.security.pr.resolve import UncertainItem
    out: list = []
    for path in paths:
        with _naming_unread(unread):
            entry = _stored_entry(repo, treeish, path)
            if entry is None:
                continue
            out.append(UncertainItem(
                path=path, category="evil-merge", signature_id="",
                description="injected by a merge saw could not model",
                preview=gitutil.blob(repo, entry[1]) or b"",
                introduced_by=introduced_by, confirmed=True))
    return out


def _uncertain_items(repo: Path, scan, taken: set[str],
                     origin: Callable[[str], delivery.Origin], *, unread: list[str]) -> list:
    """Build the operator's list of heuristic file findings this verb would otherwise leave untouched.
    Takes the repo, the scan, the paths the confirmed lanes already own, and `origin(path)`, which
    finds the delivery that added a file. Returns one `UncertainItem` per finding whose file is
    present at HEAD; a path git could not read is named in `unread`."""
    from stayawake.bots.security.models import HEURISTIC
    from stayawake.bots.security.pr.resolve import UncertainItem
    out = []
    seen: set[str] = set()
    for f in scan.findings:
        if getattr(f, "confidence", None) != HEURISTIC or getattr(f, "advisory_only", False):
            continue
        path = getattr(f, "path", "") or ""
        if not path or path in taken or path in seen or getattr(f, "commit_sha", None):
            continue
        with _naming_unread(unread):
            entry = _stored_entry(repo, "HEAD", path)
            if entry is None:
                continue
            seen.add(path)
            came = origin(path)
            out.append(UncertainItem(
                path=path, category=getattr(f, "category", "") or "",
                signature_id=getattr(f, "signature_id", "") or "",
                description=getattr(f, "description", "") or "",
                preview=gitutil.blob(repo, entry[1]) or b"",
                introduced_by=came.commit[:12], arrived_with_removed=came.payloads,
                origin_unread=came.unread))
    return out


def _foreign_targets(scan) -> list[str]:
    """Paths of confirmed files to remove whole: wholly-foreign files, and files the working-tree
    fix removes."""
    out: list[str] = []
    for f in scan.findings:
        if getattr(f, "confidence", None) != CONFIRMED or getattr(f, "advisory_only", False):
            continue
        repair = changes.repair_for(f)
        path = footprint.foreign_path(f) or (repair.path if repair is not None
                                             and repair.action == "remove" else None)
        if path and path not in out:
            out.append(path)
    return out


def _unhandled_confirmed(scan, signatures, revert_paths: set[str],
                         cleaned_head: dict[str, str], remove_paths: set[str]) -> list[str]:
    """The paths of confirmed, non-advisory findings this verb neither reverts (a revert path),
    excises (its footprint gone from the cleaned HEAD of its path), nor removes whole. Each is a
    file the operator must recover by hand, so the caller can name them rather than count them."""
    flat = _flat(signatures)
    paths: list[str] = []
    for f in scan.findings:
        if getattr(f, "confidence", None) != CONFIRMED or getattr(f, "advisory_only", False):
            continue
        if getattr(f, "commit_sha", None) and getattr(f, "related_paths", None):
            continue
        path = getattr(f, "path", "") or ""
        if path in revert_paths or path in remove_paths:
            continue
        carries = _repair_checks(f, flat).carries
        if carries is not None and path in cleaned_head and not carries(cleaned_head[path]):
            continue
        if path and path not in paths:
            paths.append(path)
    return paths




def _carrying_commits(repo: Path, path: str, carries) -> list[str] | None:
    """Walk `path`'s history and collect the commits whose version of it carries the footprint.
    Takes the repo, the path, and the footprint check. Returns those commits, or None when the
    history is too long to walk."""
    return delivery.commits_carrying(repo, path, lambda sha, at: carries(_stored_text(repo, sha, at)))


def _foreign_history(repo: Path, path: str, oid: str) -> tuple[list[str], list[str]] | None:
    """Walk `path`'s history and separate the commits that hold it from those holding exactly `oid`.
    Takes the repo, the path, and that blob id. Returns `(holders, holders at oid)`, or None when the
    history is too long to walk."""
    changed = delivery.history_of(repo, path, all_branches=True)
    if changed is None:
        return None
    holders, foreign = [], []
    for sha in changed:
        entry = _stored_entry(repo, sha, path)
        if entry is None:
            continue
        holders.append(sha)
        if entry[1] == oid:
            foreign.append(sha)
    return holders, foreign


def _path_at(repo: Path, treeish: str, path: str) -> bool | None:
    """Tell whether a commit holds a path. Takes the repo, the commit and the path. Returns the
    answer, or None when git could not tell."""
    answered, entry = gitutil.entry_at(repo, treeish, path)
    return entry is not None if answered else None


def _branches_left(repo: Path, checks, covered: set[str]) -> tuple[list[str], list[str]]:
    """Find the branches this run would leave behind carrying the payload. Takes the repo, each
    corrected path paired with its check — answering True, False, or None when it could not tell —
    and the branch names the run already covers. Returns the names of the rest that still carry it,
    and what could not be confirmed either way."""
    if not checks:
        return [], []
    listed = gitutil.listed_branch_refs(repo)
    if listed is None:
        return [], ["the other branches"]
    out: set[str] = set()
    unsure: set[str] = set()
    for name, ref in listed:
        if name in covered:
            continue
        for path, check in checks:
            verdict = check(ref, path)
            if verdict is None:
                unsure.add(f"branch {name}")
            elif verdict:
                out.add(name)
                break
    return sorted(out), sorted(unsure)


def _answer(repo: Path, args: list[str]) -> str | None:
    """Run one read-only git command. Takes the repo and the arguments. Returns its output, or None
    when git could not answer."""
    res = gitutil.run(repo, args, context=UNTRUSTED)
    return None if res is None or res.returncode != 0 else (res.stdout or "")


_PER_CHECKOUT = ("refs/bisect/", "refs/worktree/", "refs/rewritten/")
_PSEUDO_REFS = ("ORIG_HEAD", "FETCH_HEAD", "MERGE_HEAD", "CHERRY_PICK_HEAD", "REVERT_HEAD",
                "REBASE_HEAD", "BISECT_HEAD", "AUTO_MERGE")


def _pseudo_refs_in(repo: Path, gitdir: Path) -> list[tuple[str, str]] | None:
    """List the pseudo-refs one checkout holds, such as `ORIG_HEAD`, with what they point at. Takes
    the repo and the directory git keeps that checkout's refs in. Returns `(name, object id)` for
    each present, or None when git could not answer."""
    res = gitutil.run(repo, [f"--git-dir={gitdir}", "cat-file", "--batch-check"],
                      context=UNTRUSTED, input_text="".join(f"{name}\n" for name in _PSEUDO_REFS))
    if res is None or res.returncode != 0:
        return None
    lines = (res.stdout or "").splitlines()
    if len(lines) != len(_PSEUDO_REFS):
        return None
    out = []
    for name, line in zip(_PSEUDO_REFS, lines):
        parts = line.split()
        if len(parts) == 3:
            out.append((name, parts[0]))
        elif parts[-1:] != ["missing"]:
            return None
    return out


def _refs_in(repo: Path, patterns: list[str], gitdir: Path | None = None) -> list[tuple[str, str]] | None:
    """List refs with their tips, leaving out a symbolic ref whose target is listed in its own right.
    Takes the repo, the ref patterns, and the directory git keeps one checkout's refs in when those
    are the ones asked for. Returns `(name, tip)` pairs, or None when git could not list them."""
    pinned = [f"--git-dir={gitdir}"] if gitdir is not None else []
    named = _answer(repo, [*pinned, "for-each-ref",
                           "--format=%(refname)%00%(objectname)%00%(symref)", *patterns])
    if named is None:
        return None
    rows = [parts for parts in (line.split("\0") for line in named.splitlines())
            if len(parts) == 3 and parts[1]]
    listed = {name for name, _tip, _target in rows}
    return [(name, tip) for name, tip, target in rows if target not in listed]


def _checkout_dirs(repo: Path) -> list[tuple[str, Path]] | None:
    """Find the directory git keeps each checkout's own refs in. Takes the repo. Returns each as
    `(label, directory)`, labelled the way git addresses another checkout's refs, or None when they
    could not be found."""
    common = _answer(repo, ["rev-parse", "--path-format=absolute", "--git-common-dir"])
    if common is None or not common.strip():
        return None
    root = Path(common.strip())
    dirs = [("main-worktree", root)]
    try:
        dirs += [(f"worktrees/{d.name}", d) for d in sorted((root / "worktrees").iterdir())
                 if d.is_dir()]
    except FileNotFoundError:
        pass
    except OSError:
        return None
    return dirs


def _candidate_refs(repo: Path) -> tuple[list[tuple[str, str]], list[str]]:
    """List the refs and checkouts that can still reach a commit. Takes the repo. Returns each as
    `(name, tip)`, and what could not be listed."""
    out: list[tuple[str, str]] = []
    unsure: list[str] = []
    shared = _refs_in(repo, ["refs/"])
    if shared is None:
        unsure.append("the tags, stashes and other refs")
    else:
        out += [(name, tip) for name, tip in shared if not name.startswith(_PER_CHECKOUT)]
    checkouts = _checkout_dirs(repo)
    if checkouts is None:
        unsure.append("the other checkouts' own refs")
    for label, gitdir in checkouts or []:
        own = _refs_in(repo, list(_PER_CHECKOUT), gitdir)
        pseudo = _pseudo_refs_in(repo, gitdir)
        if own is None or pseudo is None:
            unsure.append(f"the refs of {label}")
        out += [(f"{label}/{name}", tip) for name, tip in (own or []) + (pseudo or [])]
    if any(name == "refs/stash" for name, _tip in out):
        entries = _answer(repo, ["rev-list", "-g", "refs/stash"])
        if entries is None:
            unsure.append("the stash entries")
        else:
            stashed = entries.split()
            out = [(name, tip) for name, tip in out if name != "refs/stash" or tip not in stashed]
            out += [(f"stash@{{{i}}}", sha) for i, sha in enumerate(stashed)]
    heads = _checkout_heads(repo)
    if heads is None:
        unsure.append("the other checkouts")
    return out + (heads or []), unsure


def _checkout_heads(repo: Path) -> list[tuple[str, str]] | None:
    """List the commit each checkout of the repository is on. Takes the repo. Returns the label and
    commit of each checkout on a commit, or None when git could not list them."""
    worktrees = _answer(repo, ["worktree", "list", "--porcelain"])
    if worktrees is None:
        return None
    heads, path = [], ""
    for line in worktrees.splitlines():
        if line.startswith("worktree "):
            path = line[len("worktree "):]
        elif line.startswith("HEAD ") and line[len("HEAD "):].strip().strip("0"):
            heads.append((f"worktree {path}", line[len("HEAD "):].strip()))
    return heads


def _refs_still_reaching(repo: Path, oids: set[str],
                         clean_tips: list[str]) -> tuple[list[str], list[str]]:
    """Name the refs from whose history any id in `oids` is still reachable, judging each ref by what
    it points at. Takes the repo, the payload's blob and commit ids, and the clean tips to exclude.
    Returns the names of the refs that still reach one, and what could not be established."""
    if not oids:
        return [], []
    candidates, unsure = _candidate_refs(repo)
    if not candidates:
        return [], unsure
    everything = gitutil.reachable_objects(repo, [s for _n, s in candidates], clean_tips)
    if everything is not None and not oids & everything:
        return [], unsure
    deadline = None if everything is not None else time.monotonic() + LOCAL_TIMEOUT
    holding = []
    for at, (name, sha) in enumerate(candidates):
        if deadline is not None and time.monotonic() > deadline:
            unsure.append(f"{len(candidates) - at} more refs")
            break
        reached = gitutil.reachable_objects(repo, [sha], clean_tips)
        if reached is None:
            unsure.append(name)
        elif oids & reached:
            holding.append(name)
    return sorted(set(holding)), unsure


_OID = set("0123456789abcdef")


def _is_oid(s: str) -> bool:
    s = (s or "").strip().lower()
    return len(s) == 40 and all(c in _OID for c in s)


def _read_remote_head(repo: Path, slug: str, branch: str,
                      token: str | None) -> tuple[bool, str | None]:
    """`(known, sha)`. `known` False means the lookup did not finish. `sha` None when
    `known` is True means the heads ref is absent."""
    res = run_remote_git(slug, token, lambda url, env: gitremote.ls_remote(
        url, ["--heads", f"refs/heads/{branch}"], env=env))
    if res is None or res.returncode != 0:
        return False, None
    # `ls-remote <pattern>` tail-matches at `/`, so a ref named `a/refs/heads/main` answers a query
    # for `main` and sorts first — anyone who can push could choose the SHA this returns.
    wanted = f"refs/heads/{branch}"
    for line in (res.stdout or "").splitlines():
        parts = line.split()
        if len(parts) < 2 or parts[1].strip() != wanted:
            continue
        sha = parts[0].strip()
        return (True, sha) if _is_oid(sha) else (False, None)
    return True, None


def _collect_remote_heads(repo: Path, slug: str, names: list[str],
                          token: str | None) -> tuple[dict[str, str | None] | None, str | None]:
    """Each branch's remote SHA (`None` if absent). `(None, name)` when `name` could not be read."""
    found: dict[str, str | None] = {}
    for name in names:
        known, sha = _read_remote_head(repo, slug, name, token)
        if not known:
            return None, name
        found[name] = sha
    return found, None


def _destination(slug: str, branch: str, token: str | None,
                 sha12: str) -> tuple[str, Reason | None]:
    """Where this branch's amended history goes, as `(branch, reason)`."""
    protection = authority.ref_protection(slug, branch, token)
    if protection.protected is False:
        return branch, None
    cause = Cause.BRANCH_PROTECTED if protection.protected else Cause.PROTECTION_UNKNOWN
    aside = f"security/amend-{sha12}"
    return aside, Reason(cause, aside)


def _push_to(repo: Path, slug: str, branch: str, dest: str, token: str | None,
             lease: str | None, pusher, *, force: bool) -> PushResult:
    """The transport, and the only part a caller may substitute.

    `force` is passed in rather than re-derived from `dest != branch`: a branch named exactly like
    the aside ref makes those two names equal, and the transport would then force-update the very
    ref the destination decision had just protected.
    """
    if pusher is not None:
        return pusher(branch, dest, lease)
    if not force or lease is None:
        return publish_head(repo, slug, branch, token, dest=dest)
    return force_update_head(repo, slug, branch, token, lease=lease)


def _force_update_branch(repo: Path, slug: str, branch: str, token: str | None, *,
                         pusher, lease: str | None = None,
                         sha12: str = "") -> BranchResult:
    dest, aside = _destination(slug, branch, token, sha12)
    result = _push_to(repo, slug, branch, dest, token, lease, pusher,
                      force=aside is None)
    if aside is not None:
        return BranchResult(branch, False,
                            aside if result.ok else Reason(Cause.PUSH_REFUSED, branch))
    if not result.ok:
        return BranchResult(branch, False, Reason(Cause.PUSH_REFUSED, branch))
    if pusher is not None:
        return BranchResult(branch, True)
    known, remote = _read_remote_head(repo, slug, branch, token)
    local = gitutil.stdout(repo, ["rev-parse", f"refs/heads/{branch}"]).strip()
    if known and remote and local and remote == local:
        return BranchResult(branch, True)
    if not known:
        # An accepted push whose result cannot be read back is not a refusal. Calling it one used
        # to send the local branch back to the payload tip, which GUARANTEES the divergence the
        # restore was meant to avoid: the remote most likely holds the replacement.
        return BranchResult(branch, False, Reason(Cause.PUSH_NOT_CONFIRMED, branch))
    return BranchResult(branch, False, Reason(Cause.REMOTE_DID_NOT_MOVE, branch))


def _capture_path(slug: str, sha12: str) -> Path:
    """Find where the objects a replacement orphans are captured before any ref moves. Takes the
    repository's slug and the short id of the oldest replaced commit. Returns the path."""
    return arrival_record.state_dir(slug) / sha12 / "capture.bundle"


_CAUSE_PER_REFUSAL_KIND = {
    "conflicted": Cause.MERGE_WOULD_NOT_RESOLVE,
    "shape": Cause.COMMIT_SHAPE_NOT_MODELLED,
    "submodule": Cause.PAYLOAD_IN_A_SUBMODULE,
    "unnamed": Cause.COMMIT_SHAPE_NOT_MODELLED,
    "not-applied": Cause.REPLACEMENT_DID_NOT_APPLY,
    "headers": Cause.COMMIT_RECORDS_MORE_THAN_A_REPLACEMENT_CARRIES,
    "message-encoding": Cause.COMMIT_RECORDS_MORE_THAN_A_REPLACEMENT_CARRIES,
    "message": Cause.REPLACEMENT_NOT_WRITTEN,
    "baseline-carries-payload": Cause.PAYLOAD_PREDATES_THIS_COMMIT,
    "changed-downstream": Cause.PAYLOAD_CHANGED_AFTER_THIS_COMMIT,
    "replacement-loses-more": Cause.REPLACEMENT_LOSES_MORE_THAN_THE_PAYLOAD,
    "unreadable": Cause.HISTORY_UNREADABLE,
}

_SUPPLY_REFUSALS = {
    "carries": Cause.SUPPLIED_CONTENT_REJECTED,
    "unwritable": Cause.SUPPLIED_CONTENT_UNWRITABLE,
}


def _supply_refusals(rejected: dict) -> tuple:
    """The reasons naming operator-supplied content the run could not use, one per cause. Takes the
    map of path to cause. Returns those reasons."""
    return tuple(Reason(cause, ", ".join(sorted(p for p, c in rejected.items() if c is cause)))
                 for cause in sorted(set(rejected.values()), key=lambda c: c.value))


def _tags_at(repo: Path, slug: str, olds: list[str], token: str | None) -> tuple[list[str], bool]:
    """Tag names still pointing at the replaced commit, and whether that could be established.

    Asked of the REMOTE, not of this clone. The refresh this run does is `--no-tags`, so a tag
    pushed since the operator last fetched is invisible here — and one `clone --branch <tag>` puts
    the payload back on disk. `ls-remote --tags` reports both the tag object and its peeled `^{}`
    line, so an annotated tag is matched by the commit it resolves to.
    """
    local = [name for sha in olds
             for name in gitutil.stdout(repo, ["for-each-ref", f"--points-at={sha}",
                                               "--format=%(refname:short)", "refs/tags"],
                                        context=UNTRUSTED).split()]
    res = run_remote_git(slug, token, lambda url, env: gitremote.ls_remote(
        url, ["--tags"], env=env))
    if res is None or res.returncode != 0:
        return sorted(set(local)), False
    remote = []
    for line in (res.stdout or "").splitlines():
        parts = line.split()
        if len(parts) == 2 and parts[0].strip() in set(olds) and parts[1].startswith("refs/tags/"):
            remote.append(parts[1][len("refs/tags/"):].removesuffix("^{}"))
    return sorted(set(local) | set(remote)), True


def _survivors(repo: Path, slug: str, olds: list[str], token: str | None) -> list[Reason]:
    """What the force-update leaves reachable. Each one makes the run need review.

    Forks are counted rather than assumed. Reporting "forks were not established" on every run
    made `needs_review` True for every outcome the module could produce, refused and completed
    alike — a flag that fires every time carries no information and hides the runs that really do
    need a person.
    """
    reasons = [Reason(Cause.PREVIOUS_OBJECTS_UNCOLLECTED)]
    tags, established = _tags_at(repo, slug, olds, token)
    if tags:
        reasons.append(Reason(Cause.TAGS_AT_REPLACED_COMMIT, ", ".join(sorted(tags))))
    elif not established:
        reasons.append(Reason(Cause.TAGS_NOT_ESTABLISHED))
    forks = authority.fork_count(slug, token)
    if forks is None:
        reasons.append(Reason(Cause.FORKS_NOT_ESTABLISHED))
    elif forks:
        reasons.append(Reason(Cause.FORKS_EXIST, str(forks)))
    return reasons


def _held_since_delivery(repo: Path) -> Callable[[tuple[str, ...], str, str], bool]:
    """Build a check of whether history after a delivery still holds a file. Takes the repo. Returns
    `held(forms, path, blob)`, which answers True when git could not tell."""
    holders: dict[tuple[str, str], list[str] | None] = {}
    reached: dict[str, bool | None] = {}

    def in_history(commit: str) -> bool | None:
        if commit not in reached:
            found = gitutil.branches_carrying(repo, commit)
            reached[commit] = None if found is None else bool(found)
        return reached[commit]

    def held(forms: tuple[str, ...], path: str, blob: str) -> bool:
        if (path, blob) not in holders:
            try:
                hist = _foreign_history(repo, path, blob)
            except gitutil.Unread:
                hist = None
            holders[(path, blob)] = None if hist is None else hist[1]
        found = holders[(path, blob)]
        if found is None:
            return True
        if not found:
            return False
        answers = [gitutil.ancestry(repo, c, sha) for sha in found for c in forms]
        if True in answers or None in answers:
            return True
        present = [in_history(c) for c in forms]
        return None in present or not any(present)

    return held


@dataclass
class _Arrivals:
    """What became of the files added beside the payloads this run removes: the files to drop with
    the commits holding each, the questions nobody answered that the run records, the reasons to
    report, and the decisions kept from earlier runs, or None when they could not be read."""

    arrived: dict[str, str] = field(default_factory=dict)
    holders: dict[str, set[str]] = field(default_factory=dict)
    to_record: list = field(default_factory=list)
    reasons: list[Reason] = field(default_factory=list)
    recorded: list = field(default_factory=list)
    decided: list | None = None
    forms: dict = field(default_factory=dict)


def _arrival_reasons(settled: arrival_questions.Settled, first_commits: list[str], unread: list[str],
                     too_large: list[str], records_unread: list[str] = (), gone: list[str] = (),
                     not_saved: int = 0) -> list[Reason]:
    """Name what the operator decided and what is left to decide about the files added beside a
    payload. Takes what was settled, the first commits that carry a payload with other files, what
    git could not read, the chosen files whose history is too long to walk, the earlier records that
    could not be read, the chosen files whose delivery commit has left history, and how many answers
    could not be saved. Returns the reasons."""
    reasons = []
    if gone:
        reasons.append(Reason(Cause.ARRIVALS_DELIVERY_GONE, names_that_fit(list(gone))))
    if not_saved:
        reasons.append(Reason(Cause.ARRIVALS_ANSWERS_NOT_SAVED, str(not_saved)))
    if records_unread:
        reasons.append(Reason(Cause.ARRIVALS_RECORD_UNREADABLE, names_that_fit(list(records_unread))))
    undecided = [f.path for q in settled.undecided for f in q.files]
    if undecided:
        reasons.append(Reason(Cause.ARRIVALS_UNDECIDED, str(len(undecided)),
                              names_that_fit(undecided)))
    if first_commits:
        reasons.append(Reason(Cause.ARRIVALS_IN_FIRST_COMMIT, names_that_fit(first_commits)))
    if unread:
        reasons.append(Reason(Cause.ARRIVALS_UNREAD, names_that_fit(unread)))
    if too_large:
        reasons.append(Reason(Cause.HISTORY_TOO_LARGE_TO_ENUMERATE, names_that_fit(too_large)))
    if settled.kept:
        kept = [f.path for f in settled.kept]
        reasons.append(Reason(Cause.ARRIVALS_KEPT, str(len(kept)), names_that_fit(kept)))
    return reasons


def _settle_arrivals(repo: Path, slug: str, deliveries: dict, brought: dict, excluded: set[str],
                     resolver, unread_deliveries: list[str], remove_shas: set,
                     unread: list[str]) -> _Arrivals:
    """Put the files each delivery added to the operator, with those an earlier run recorded, and
    schedule the ones taken out. Takes the repo, its slug, each delivery mapped to the payload paths
    saw removes from it, what each delivery brought, the paths to leave out, the resolver, what git
    could not read while finding the deliveries, the commits to rebuild, which it adds to, and
    where to name what git could not read. Returns the `_Arrivals`."""
    decided, decided_read = arrival_record.read_decisions(slug)
    seen: set[tuple[str, str]] = set()
    added_by: dict[tuple[str, str], set[str]] = {}
    live = arrival_questions.from_history(repo, deliveries, brought, excluded, seen, added_by)
    records, unreadable = arrival_record.read_all(slug)
    if not decided_read:
        unreadable = [*unreadable, str(arrival_record.state_dir(slug) / arrival_record.DECIDED_NAME)]
    held = _held_since_delivery(repo)
    recorded = [q for record in records for q in record.deliveries]
    every = live.asked + arrival_questions.from_records(recorded, excluded, seen, held, added_by)
    standing = arrival_questions.standing(decided, added_by)
    keeps = frozenset(pair for pair, d in standing.items()
                      if d.decision == arrival_record.KEEP_DECISION)
    questions = arrival_questions.without(every, standing)
    if resolver is not None:
        asked_now = arrival_questions.ASKED_PER_RUN
        questions = (arrival_questions.with_mentions(repo, questions[:asked_now])
                     + questions[asked_now:])
    settled = arrival_questions.ask(questions, resolver, added_by=added_by)
    out = _Arrivals(decided=decided if decided_read else None)
    answered = arrival_questions.decisions(settled)
    not_saved = len(answered) if answered and not (
        decided_read and arrival_record.add_decisions(slug, answered)) else 0
    for record in records:
        remaining = arrival_questions.still_to_ask(record.deliveries, settled, held, keeps)
        arrival_record.keep_only(record, remaining)
        out.recorded.append((record, remaining))
    too_large: list[str] = []
    gone: list[str] = []
    chosen_now = [(c.path, c.blob, settled.delivered_in.get((c.path, c.blob), ()))
                  for c in settled.take_out]
    chosen_before = [(path, blob, tuple(sorted(added_by[(path, blob)])))
                     for (path, blob), d in standing.items()
                     if d.decision == arrival_record.TAKE_OUT_DECISION]
    for path, blob, forms in [*chosen_now, *chosen_before]:
        try:
            with _naming_unread(unread):
                if _register_blob_removal(repo, path, blob, out.arrived, remove_shas,
                                          out.holders, forms) == "too-large":
                    too_large.append(path)
                elif out.arrived.get(path) == blob:
                    out.forms[(path, blob)] = forms
        except _DeliveryGone:
            gone.append(path)
    out.to_record = [q for q in settled.undecided if not q.recorded]
    out.reasons = _arrival_reasons(settled, live.first_commits,
                                   [*unread_deliveries, *live.unread], too_large, unreadable,
                                   gone, not_saved)
    return out


def amend_repo(repo: Path, opts, signatures, allowlist, token: str | None = None, *,
               pusher=None,
               identity_fallback: str | None = None,
               operator_context: Path | None = None, resolver=None) -> str:
    """Force-update every branch that still reaches a confirmed past-commit payload.

    The local rewrite is a step. The result is the remote refs moving. Returns one operator line.
    A confirmed wholly-foreign file is removed from history too. `resolver`, when given, is asked to
    keep or remove each heuristic file the verb would otherwise leave.
    """
    display = gitutil.origin_slug(repo) or str(repo).replace(str(Path.home()), "~")
    outcome = amend_outcome(repo, display, opts, signatures, allowlist, token, pusher=pusher,
                            identity_fallback=identity_fallback,
                            operator_context=operator_context, resolver=resolver)
    return render_amend_line(outcome)


@dataclass
class _Found:
    """What the history pass learned that the checkout pass acts on."""

    confirmed: bool = False


def amend_outcome(repo: Path, display: str, opts, signatures, allowlist, token, *,
                  pusher=None,
                  identity_fallback: str | None = None,
                  operator_context: Path | None = None, resolver=None,
                  operator_checkout: bool = False) -> AmendOutcome:
    """The act, as a structure. Prose is rendered from this and never parsed back out of it.

    `operator_context` is where the operator's own git config lives (signer, identity); it defaults
    to `repo`. `identity_fallback` is the operator's session credential for the authority gate. Both
    pass straight through to the gates. `operator_checkout` says `repo` is the checkout the operator
    works in: its own uncommitted changes are carried across the rewrite, and once history is done
    the checkout is cleaned as `saw fix` cleans it, the operator's uncommitted work saved first.
    """
    found = _Found()
    outcome = _history_outcome(
        repo, display, opts, signatures, allowlist, token,
        operator=Operator(pusher, identity_fallback, operator_context, resolver),
        keep_operator_changes=operator_checkout, found=found)
    if not operator_checkout or not gitutil.is_git_repo(repo):
        return outcome
    checkout = live.clean_checkout(repo, opts, signatures, allowlist,
                                   keep=getattr(opts, "keep_dirs", ()) or (),
                                   base_confirmed=found.confirmed,
                                   remove_lockfiles=not installed.lockfile_stays())
    state, detail = checkout_of(checkout)
    return with_checkout(outcome, checkout_clauses(state, detail),
                         settled=state in (Checkout.CLEAN, Checkout.CLEANED))


def _history_outcome(repo: Path, display: str, opts, signatures, allowlist, token, *,
                     operator: Operator, keep_operator_changes: bool,
                     found: _Found) -> AmendOutcome:
    """Rewrite the history that carries a confirmed payload and move each branch that reached it.
    Takes `amend_outcome`'s scan arguments, the operator context, whether the operator's own
    uncommitted changes in `repo` are carried across the move, and where to record what was found.
    Returns the outcome."""
    pusher, identity_fallback, operator_context, resolver = operator
    rejected_supply: dict[str, Cause] = {}
    arrival_reasons: list[Reason] = []

    def _refuse(cause: Cause, detail: str = "", subjects: str = "",
                recovery: str = "", named: tuple = ()) -> AmendOutcome:
        """Refuse, carrying any operator answer the run could not use, what is left to decide
        about the files added beside a payload, and any further reasons `named`."""
        return refused(display, cause, detail, subjects, recovery,
                       also=_supply_refusals(rejected_supply) + tuple(arrival_reasons) + named)

    if not gitutil.is_git_repo(repo):
        return _refuse(Cause.NOT_A_GIT_REPOSITORY)
    if not keep_operator_changes and gitamend.is_dirty(repo):
        return _refuse(Cause.WORKING_TREE_NOT_CLEAN)

    slug = gitutil.origin_slug(repo)
    if not slug:
        return _refuse(Cause.NO_REMOTE)
    if not (token or "").strip() and pusher is None:
        return _refuse(Cause.NO_CREDENTIAL)

    permitted = authority.may_rewrite(slug, token, identity_fallback=identity_fallback)
    if not permitted.permitted:
        return _refuse(Cause.NOT_PERMITTED_TO_REWRITE,
                       permitted.detail or permitted.reason)
    if not gitutil.holds_its_history(repo):
        return _refuse(Cause.HISTORY_INCOMPLETE)
    fetched = gitutil.fetch_refs(repo, token=token)
    if not fetched.ok:
        return _refuse(Cause.REMOTE_REFS_UNREADABLE, fetched.reason)
    broken = gitutil.unreadable_branch_refs(repo)
    if broken is None:
        return _refuse(Cause.HISTORY_UNREADABLE, "the branches of this repository")
    if broken:
        return _refuse(Cause.BRANCH_NAMES_NO_COMMIT, ", ".join(broken))
    unread: list[str] = []

    scan = scan_target(LocalRepoTarget(repo, str(repo), opts), signatures, allowlist)
    if scan.error is not None:
        return _refuse(Cause.SCAN_DID_NOT_FINISH)
    if gitamend.is_dirty(repo):
        committed = _committed_scan(repo, opts, signatures, allowlist)
        if committed is None or committed.error is not None:
            return _refuse(Cause.SCAN_DID_NOT_FINISH)
        _add_file_findings(scan, committed)
    found.confirmed = any(getattr(f, "confidence", None) == CONFIRMED
                          and not getattr(f, "advisory_only", False) for f in scan.findings)
    sweeps = delivery.sweep_merges(repo, scan.findings)
    if sweeps.failed:
        kind, detail = sweeps.failed[0]
        return _refuse(Cause.CONFIRMED_COMMIT_UNRESOLVED if kind == delivery.UNRESOLVED
                       else Cause.HISTORY_UNREADABLE, detail)
    infected = sweeps.swept
    uncharacterized: dict[str, tuple[str, str]] = {sha: ("shape", sha[:12])
                                                   for sha in sweeps.left_to_ask}
    uncharacterized_paths = sweeps.left_to_ask
    swept = {p for ps in infected.values() for p in ps}

    clean: dict[str, tuple] = {}
    clean_shas: set[str] = set()
    clean_holders: dict[str, set[str]] = {}
    cleaned_head: dict[str, str] = {}
    for finding, carries, corrector, head_clean in _content_targets(repo, scan, signatures, unread):
        with _naming_unread(unread):
            carrying = _carrying_commits(repo, finding.path, carries)
            if carrying is None:
                return _refuse(Cause.HISTORY_TOO_LARGE_TO_ENUMERATE, finding.path)
            if not carrying:
                return _refuse(Cause.CONFIRMED_COMMIT_UNRESOLVED, finding.path)
            clean[finding.path] = (carries, corrector)
            clean_shas.update(carrying)
            clean_holders[finding.path] = set(carrying)
            cleaned_head[finding.path] = head_clean

    for path, carries, corrector in _predates_content_targets(
            repo, scan, signatures, allowlist, opts, set(clean), unread):
        with _naming_unread(unread):
            carrying = _carrying_commits(repo, path, carries)
            if carrying is None:
                return _refuse(Cause.HISTORY_TOO_LARGE_TO_ENUMERATE, path)
            if not carrying:
                continue
            clean[path] = (carries, corrector)
            clean_shas.update(carrying)
            clean_holders[path] = set(carrying)

    remove: dict[str, str] = {}
    remove_shas: set[str] = set()
    remove_holders: dict[str, set[str]] = {}
    varied: list[str] = []
    for path in _foreign_targets(scan):
        if path in clean or path in {p for ps in infected.values() for p in ps}:
            continue
        with _naming_unread(unread):
            entry = _stored_entry(repo, "HEAD", path)
            if entry is None:
                continue
            hist = _foreign_history(repo, path, entry[1])
            if hist is None:
                return _refuse(Cause.HISTORY_TOO_LARGE_TO_ENUMERATE, path)
            holders, foreign = hist
            if not foreign:
                continue
            if set(holders) != set(foreign):
                varied.append(path)
                continue
            remove[path] = entry[1]
            remove_shas.update(foreign)
            remove_holders[path] = set(foreign)
            try:
                elsewhere = gitutil.blob_paths(repo, entry[1])
            except gitutil.Unread:
                return _refuse(Cause.HISTORY_UNREADABLE, f"every copy of {path}")
            if elsewhere is None:
                return _refuse(Cause.HISTORY_TOO_LARGE_TO_ENUMERATE, path)
            for former in elsewhere:
                if (former in remove or former in varied or former in clean
                        or former in {p for ps in infected.values() for p in ps}):
                    continue
                hist = _foreign_history(repo, former, entry[1])
                if hist is None:
                    return _refuse(Cause.HISTORY_TOO_LARGE_TO_ENUMERATE, former)
                former_holders, former_foreign = hist
                if not former_foreign:
                    return _refuse(Cause.PAYLOAD_STILL_REACHABLE, former)
                if set(former_holders) != set(former_foreign):
                    varied.append(former)
                    continue
                remove[former] = entry[1]
                remove_shas.update(former_foreign)
                remove_holders[former] = set(former_foreign)

    survives = oracle.survives(repo, signatures, allowlist, opts)
    substitute: dict[str, tuple[str, tuple[str, str]]] = {}
    substitute_shas: set[str] = set()
    supply_paths: set[str] = set()
    purge: set[str] = set()
    purge_shas: set[str] = set()
    purge_holders: dict[str, set[str]] = {}
    for path in varied:
        with _naming_unread(unread):
            if _register_purge(repo, path, purge, purge_shas, survives, purge_holders) == "too-large":
                return _refuse(Cause.HISTORY_TOO_LARGE_TO_ENUMERATE, path)

    deliveries: dict[str, tuple[str, ...]] = dict(infected)
    unread_deliveries: list[str] = []
    delivery.add_first_carriers(repo, {**clean_holders, **remove_holders, **purge_holders}, deliveries,
                    unread_deliveries)
    brought = delivery.brought_by_each(repo, deliveries)
    asked: set[str] = set()
    answered_holders: dict[str, set[str]] = {}
    substitute_holders: dict[str, set[str]] = {}

    if resolver is not None:
        held = set(clean) | set(remove) | {p for ps in infected.values() for p in ps}
        for item in _uncertain_items(repo, scan, held,
                                     lambda path: delivery.origin_of(path, deliveries, brought),
                                     unread=unread):
            asked.add(item.path)
            try:
                answer = resolver(item)
            except Exception:
                continue
            with _naming_unread(unread):
                if answer.action == REMOVE and _register_operator_removal(
                        repo, item.path, remove, remove_shas, remove_holders,
                        purge, purge_shas, survives,
                        purge_holders=purge_holders) == "too-large":
                    return _refuse(Cause.HISTORY_TOO_LARGE_TO_ENUMERATE, item.path)

    infected = {sha: tuple(p for p in ps if p not in clean and p not in remove)
                for sha, ps in infected.items()}
    infected = {sha: ps for sha, ps in infected.items() if ps}
    taken = {p for ps in infected.values() for p in ps}

    unhandled = _unhandled_confirmed(scan, signatures, taken, cleaned_head,
                                     set(remove) | set(purge))
    if keep_operator_changes:
        unhandled = [p for p in unhandled if _committed_anywhere(repo, p)]
    if resolver is not None and unhandled:
        for item in _unhandled_items(repo, scan, unhandled, survives, unread=unread):
            asked.add(item.path)
            try:
                answer = resolver(item)
            except Exception:
                continue
            with _naming_unread(unread):
                if answer.action == RESTORE and answer.restore is not None:
                    if _register_substitute(repo, item.path, answer.restore,
                                            substitute, substitute_shas,
                                            holders=substitute_holders) == "too-large":
                        return _refuse(Cause.HISTORY_TOO_LARGE_TO_ENUMERATE, item.path)
                elif answer.action == SUPPLY and isinstance(answer.supply, bytes):
                    refusal = _register_supply(repo, item.path, answer.supply, substitute,
                                               substitute_shas, oracle.payload_matchers(signatures),
                                               allowlist, opts, holders=substitute_holders)
                    if refusal == "too-large":
                        return _refuse(Cause.HISTORY_TOO_LARGE_TO_ENUMERATE, item.path)
                    if refusal:
                        rejected_supply[item.path] = _SUPPLY_REFUSALS[refusal]
                    elif item.path in substitute:
                        supply_paths.add(item.path)
                elif answer.action == REMOVE and _register_operator_removal(
                        repo, item.path, remove, remove_shas, remove_holders,
                        purge, purge_shas, survives,
                        purge_holders=purge_holders) == "too-large":
                    return _refuse(Cause.HISTORY_TOO_LARGE_TO_ENUMERATE, item.path)
            answered_holders[item.path] = (remove_holders.get(item.path, set())
                                           | purge_holders.get(item.path, set())
                                           | substitute_holders.get(item.path, set()))
        unhandled = _unhandled_confirmed(scan, signatures, taken, cleaned_head,
                                         set(remove) | set(substitute) | set(purge))
        if keep_operator_changes:
            unhandled = [p for p in unhandled if _committed_anywhere(repo, p)]
    if resolver is not None and uncharacterized:
        for sha in list(uncharacterized):
            with _naming_unread(unread):
                present = [p for p in uncharacterized_paths.get(sha, ())
                           if _stored_entry(repo, sha, p) is not None]
                if not present:
                    continue
                for item in _path_items(repo, present, sha, sha[:12], unread=unread):
                    asked.add(item.path)
                    try:
                        answer = resolver(item)
                    except Exception:
                        continue
                    if answer.action == REMOVE and _register_operator_removal(
                            repo, item.path, remove, remove_shas, remove_holders,
                            purge, purge_shas, survives, sha, purge_holders) == "too-large":
                        return _refuse(Cause.HISTORY_TOO_LARGE_TO_ENUMERATE, item.path)
                if all(p in remove for p in present):
                    del uncharacterized[sha]

    blocked_infected: dict[str, tuple[str, str]] = {}
    taken_from: dict[str, set[str]] = {}
    merge_taken: dict[str, str] = {}
    merge_taken_holders: dict[str, set[str]] = {}
    for sha in list(infected):
        rep = replacement_tree(repo, sha, infected[sha], survives)
        if not rep.ok:
            blocked_infected[sha] = (rep.kind or "replacement", rep.refusal or sha[:12])
    if resolver is not None and blocked_infected:
        for sha in blocked_infected:
            with _naming_unread(unread):
                present = [p for p in infected[sha] if _stored_entry(repo, sha, p) is not None]
                for item in _path_items(repo, present, sha, sha[:12], unread=unread):
                    asked.add(item.path)
                    try:
                        answer = resolver(item)
                    except Exception:
                        continue
                    if answer.action != REMOVE:
                        continue
                    outcome, taken = _register_merge_file_removal(
                        repo, sha, item.path, survives, purge, purge_shas, merge_taken,
                        remove_shas, merge_taken_holders)
                    if outcome == "too-large":
                        return _refuse(Cause.HISTORY_TOO_LARGE_TO_ENUMERATE, item.path)
                    if taken:
                        taken_from.setdefault(sha, set()).add(item.path)
    handled_blocked = {sha for sha in blocked_infected
                       if all(p in taken_from.get(sha, ()) for p in infected[sha])}

    delivery.add_first_carriers(repo, {p: h for p, h in answered_holders.items() if h}, deliveries,
                    unread_deliveries)
    for sha in [*uncharacterized, *(s for s in blocked_infected if s not in handled_blocked)]:
        deliveries.pop(sha, None)
    history = _HistoryPayloads()
    decided: set[tuple[str, str]] = set()
    undecided: set[str] = set()
    for f in scan.findings:
        if (getattr(f, "confidence", None) == CONFIRMED and not getattr(f, "advisory_only", False)
                and getattr(f, "path", "")):
            _note_decided(repo, "HEAD", f.path, decided, undecided, unread)
    owned_paths = set(clean) | set(substitute) | set(purge) | swept

    def left_to_another_step(path: str, oid: str) -> bool:
        if (path, oid) in decided or path in undecided or remove.get(path) == oid:
            return True
        if path in substitute and substitute[path][0] == oid:
            return True
        if path in clean:
            return bool(clean[path][0](gitutil.blob_text(repo, oid) or ""))
        return path in swept or path in purge

    infected_now = (set(infected) | clean_shas | remove_shas | substitute_shas | purge_shas
                    | set(uncharacterized))
    heads_now = _branches_carrying_any(repo, infected_now) if infected_now else []
    graph_now = (gitrebuild.ordered_graph(repo, [tip for _n, tip, _c in heads_now])
                 if heads_now else None)
    if not infected_now:
        _read_past_commits(repo, display, signatures, allowlist, opts, left_to_another_step,
                           owned_paths, history)
    elif heads_now is None or (heads_now and graph_now is None):
        history.unread.append(_REWRITTEN_VERSIONS)
    elif heads_now:
        for finding, entry in _confirmed_versions(
                repo, display, [tip for _n, tip, _c in heads_now],
                _rewrite_boundary(gitrebuild.commits_to_rebuild(graph_now, infected_now)),
                signatures, allowlist, opts, left_to_another_step, history):
            _place_history_finding(repo, finding, entry, signatures, allowlist, opts, owned_paths,
                                   history)
        _read_other_refs(repo, display, signatures, allowlist, opts, left_to_another_step, history)
    adding = pushed.adding_commits(repo, list(history.region.items()), set(history.take_out))
    if adding is None:
        history.unread.append(_REWRITTEN_VERSIONS)
    for key, commits in (adding or {}).items():
        history.take_out[key] |= commits
    for path, (carries, corrector) in history.excise.items():
        carrying = _carrying_commits(repo, path, carries)
        if carrying is None:
            return _refuse(Cause.HISTORY_TOO_LARGE_TO_ENUMERATE, path)
        within = [sha for sha in carrying if sha in history.region]
        clean[path] = (carries, corrector)
        clean_shas.update(within)
        clean_holders[path] = set(within)
    unhandled = [*unhandled, *history.manual]
    unread.extend(history.unread)
    in_history = ({path for path, _oid in history.take_out} | set(history.excise)
                  | {name.rsplit(" in ", 1)[0] for name in history.manual})

    with_a_finding = {getattr(f, "path", "") or "" for f in scan.findings}
    settled_arrivals = _settle_arrivals(
        repo, slug, deliveries, delivery.brought_by_each(repo, deliveries, brought),
        with_a_finding | asked | swept | set(clean) | set(remove) | set(purge) | set(substitute)
        | {p for ps in uncharacterized_paths.values() for p in ps} | in_history,
        resolver, unread_deliveries, remove_shas, unread)
    arrived = {**merge_taken, **settled_arrivals.arrived}
    taken_forms = {**{(p, b): (sha,) for sha, paths in taken_from.items() for p in paths
                      if (b := merge_taken.get(p))},
                   **settled_arrivals.forms}
    arrival_reasons.extend(settled_arrivals.reasons)

    if (not infected and not clean and not remove and not substitute and not purge and not arrived
            and not history.take_out):
        if unhandled:
            return _refuse(Cause.PAYLOAD_NEEDS_MANUAL_RECOVERY,
                           str(len(unhandled)), ", ".join(sorted(unhandled)))
        if unread:
            return _refuse(Cause.HISTORY_UNREADABLE, names_that_fit(sorted(set(unread))))
        partly = tuple(_partly_read_reasons(history.partly_read, history.runnable,
                                            {path for path, _oid in history.confirmed | decided},
                                            history.submodules))
        if history.on_other_refs:
            reaching, unsure_refs = _refs_still_reaching(repo, history.on_other_refs, [])
            cut = ((Reason(Cause.PAST_COMMITS_READ_IN_PART, str(history.cut_at)),)
                   if history.cut_at else ())
            return _refuse(Cause.PAYLOAD_REACHABLE_FROM_OTHER_REFS,
                           names_that_fit(reaching or unsure_refs or ["another ref"]),
                           named=cut + partly)
        if history.cut_at:
            return _refuse(Cause.PAST_COMMITS_READ_IN_PART, str(history.cut_at), named=partly)
        return _refuse(Cause.NO_CONFIRMED_PAYLOAD, named=partly)

    malicious_oids, unread_versions = _payload_blobs(
        repo, remove, substitute, purge_holders, clean, clean_shas,
        _merge_payload(repo, infected, sweeps.payload, survives))
    arrived_oids, unread_arrived = _arrived_versions(repo, infected, malicious_oids)
    unread_versions = [*unread_versions, *unread_arrived]

    all_infected = (set(infected) | clean_shas | remove_shas | substitute_shas | purge_shas
                    | set(uncharacterized) | set().union(*history.take_out.values()))
    malicious_oids |= all_infected
    heads = _branches_carrying_any(repo, all_infected)
    if heads is None:
        return _refuse(Cause.HISTORY_UNREADABLE, "the branches that reach the payload")
    if not heads:
        return _refuse(Cause.COMMIT_ON_NO_BRANCH,
                       ", ".join(sorted(s[:12] for s in all_infected)))
    covered = {n for n, _t, _c in heads}
    off_plan, unread_branches = _branches_left(repo, [
        *((p, lambda tr, pth, c=carries: _carries_in(repo, tr, pth, c))
          for p, (carries, _c) in clean.items()),
        *((p, lambda tr, pth, o=oid: _holds(repo, tr, pth, o)) for p, oid in remove.items()),
        *((p, lambda tr, pth, o=fo: _holds(repo, tr, pth, o)) for p, (fo, _e) in substitute.items()),
        *((p, lambda tr, pth: _judged(survives(tr, pth))) for p in purge),
    ], covered)
    if off_plan:
        return _refuse(Cause.PAYLOAD_STILL_REACHABLE, names_that_fit(off_plan))
    unconfirmed = [*unread, *unread_versions, *unread_branches]

    graph = gitrebuild.ordered_graph(repo, [tip for _n, tip, _c in heads])
    if graph is None:
        return _refuse(Cause.HISTORY_UNREADABLE, "the history to rewrite")
    plan = gitrebuild.commits_to_rebuild(graph, all_infected)
    uncovered = sorted(s for s in all_infected if s not in {sha for sha, _ps in plan})
    if uncovered:
        return _refuse(Cause.COMMIT_ON_NO_BRANCH,
                       ", ".join(s[:12] for s in uncovered))
    oldest = plan[0][0]
    remove_in: dict[tuple[str, str], set[str]] = {}
    unplaced: set[tuple[str, str]] = set()
    for (path, blob), forms in taken_forms.items():
        allowed = _commits_after(repo, plan, forms)
        if allowed is None:
            unconfirmed.append(f"which copies of {path} came with the malware")
            unplaced.add((path, blob))
        else:
            remove_in[(path, blob)] = allowed
    in_the_rewrite = {sha for sha, _ps in plan}
    for key in history.take_out:
        remove_in[key] = in_the_rewrite

    signing = sign.signing_status(
        operator_context or repo,
        history_is_signed=sign.any_signed(repo, [sha for sha, _ps in plan]),
        trust_local_programs=operator_context is None)
    if signing.must_refuse:
        return _refuse(Cause.SIGNING_UNAVAILABLE, signing.reason)
    if sign.committer_identity(repo) is None:
        return _refuse(Cause.NO_COMMITTER_IDENTITY)

    leases, unread = _collect_remote_heads(repo, slug, [n for n, _, _ in heads], token)
    if unread is not None:
        return _refuse(Cause.REMOTE_BRANCH_UNREADABLE, unread)
    ahead = {name: gitutil.ancestry(repo, leases[name], tip)
             for name, tip, _cas in heads if leases.get(name)}
    for name, answer in ahead.items():
        if answer is None and not gitutil.ref_exists(repo, f"{leases[name]}^{{commit}}"):
            ahead[name] = False
    unknown = sorted(name for name, answer in ahead.items() if answer is None)
    if unknown:
        return _refuse(Cause.HISTORY_UNREADABLE, ", ".join(f"branch {name}" for name in unknown))
    behind = sorted(name for name, answer in ahead.items() if answer is False)
    if behind:
        return _refuse(Cause.LOCAL_MISSING_REMOTE_COMMITS, ", ".join(behind))

    replacements = {}
    blocked_commits: dict[str, tuple[str, str]] = dict(uncharacterized)
    recovered_paths: set[str] = set()
    for sha, paths in infected.items():
        if sha in handled_blocked or all(p in purge for p in paths):
            continue
        replacement = gitamend.replacement_commit(repo, sha, paths, signing, survives)
        if not replacement.ok:
            blocked_commits[sha] = (replacement.kind or "replacement",
                                    replacement.refusal or sha[:12])
            continue
        lost = gitamend.discarded_delta(repo, sha, replacement.sha)
        if lost is None:
            blocked_commits[sha] = ("unreadable", f"{sha[:12]}: what it keeps could not be read")
            continue
        beyond = [p for p in lost if p not in paths]
        if beyond:
            blocked_commits[sha] = ("replacement-loses-more", ", ".join(sorted(beyond)[:5]))
            continue
        recovered_paths |= set(replacement.recovered)
        replacements[sha] = replacement

    rebuilt = gitrebuild.rebuild_without_payload(
        repo, plan, replacements,
        lambda sha, tree, new_parents: gitamend.rewrite_commit(repo, sha, tree, new_parents,
                                                               signing),
        survives, clean=clean, remove=remove, pre_blocked=blocked_commits,
        substitute=substitute, purge=purge, remove_in=remove_in)
    blocked = rebuilt.blocked

    new_tips = {tip: rebuilt.tip(tip) for _n, tip, _c in heads}
    payload_paths = ({p for paths in infected.values() for p in paths}
                     | set(clean) | set(remove) | set(substitute) | set(purge))
    flagged = payload_paths | set(arrived) | in_history

    deliverable: list[tuple[str, str, str]] = []
    isolated: list[BranchResult] = []
    for name, tip, cas in heads:
        if tip in blocked:
            kind, refusal = blocked[tip]
            isolated.append(BranchResult(name, False, Reason(
                _CAUSE_PER_REFUSAL_KIND.get(kind, Cause.REPLACEMENT_NOT_WRITTEN), refusal)))
            continue
        lost = gitamend.discarded_delta(repo, tip, new_tips[tip])
        if lost is None:
            isolated.append(BranchResult(name, False, Reason(Cause.HISTORY_UNREADABLE, name)))
            continue
        beyond = [p for p in lost if p not in flagged]
        if beyond:
            isolated.append(BranchResult(name, False, Reason(
                Cause.REPLAY_CHANGED_UNRELATED_COMMITS,
                f"{name}: " + ", ".join(sorted(beyond)[:3]))))
            continue
        deliverable.append((name, tip, cas))

    if not deliverable:
        reason = isolated[0].reason if isolated else Reason(Cause.PAYLOAD_STILL_REACHABLE)
        return _refuse(reason.cause, reason.detail, reason.subjects)

    delivered_tips = {tip: new_tips[tip] for _n, tip, _c in deliverable}
    delivered_reach = _reached_from(graph, [t for _n, t, _c in deliverable])
    oldest = next((sha for sha, _ps in plan
                   if sha in rebuilt.mapping and sha in delivered_reach), oldest)
    delivered_infected = [s for s in all_infected if s in rebuilt.mapping and s in delivered_reach]

    path_checks = {p: (lambda tr, pth: _judged(survives(tr, pth))) for p in payload_paths}
    path_checks.update({p: (lambda tr, pth, c=carries: _carries_in(repo, tr, pth, c))
                        for p, (carries, _c) in clean.items()})
    left, unread_rewrite = _payload_left(
        repo, all_infected, rebuilt, [(name, delivered_tips[tip]) for name, tip, _c in deliverable],
        path_checks, remove)
    if left:
        return _refuse(Cause.PAYLOAD_STILL_REACHABLE, "; ".join(left[:3]))
    unconfirmed += unread_rewrite
    covered_names = {n for n, _t, _c in heads}
    post_view = [(name, delivered_tips[tip]) for name, tip, _c in deliverable]
    others = gitutil.listed_branch_refs(repo)
    if others is None:
        unconfirmed.append("the other branches")
    for name, ref in others or []:
        if name in covered_names:
            continue
        tip = (_answer(repo, ["rev-parse", ref]) or "").strip()
        if tip:
            post_view.append((name, tip))
        else:
            unconfirmed.append(f"branch {name}")
    reached = gitutil.reachable_objects(repo, [tip for _n, tip in post_view])
    if reached is None:
        unconfirmed.append("every branch")
    elif malicious_oids & reached:
        holding, unread = [], []
        for name, tip in post_view:
            one = gitutil.reachable_objects(repo, [tip])
            if one is None:
                unread.append(name)
            elif malicious_oids & one:
                holding.append(name)
        return _refuse(Cause.PAYLOAD_STILL_REACHABLE, names_that_fit(sorted(holding or unread)))
    taken_out = {oid for _path, oid in history.take_out}
    rewritten = _HistoryPayloads()
    still_held = [f"{entry.path} in {entry.commit[:12]}" for _finding, entry in _confirmed_versions(
        repo, display, [delivered_tips[tip] for _n, tip, _c in deliverable],
        _rewrite_boundary(plan), signatures, allowlist, opts,
        lambda path, oid: (path, oid) not in history.repaired
        and (left_to_another_step(path, oid) or (path, oid) in history.named
             or ((path, oid) in history.judged and (path, oid) not in history.confirmed)),
        rewritten)]
    if still_held:
        return _refuse(Cause.PAYLOAD_STILL_REACHABLE, names_that_fit(sorted(set(still_held))))
    unconfirmed += rewritten.unread
    arrived_on: list[str] = []
    if reached is not None and arrived_oids & reached:
        for name, tip in post_view:
            one = gitutil.reachable_objects(repo, [tip])
            if one is None:
                unconfirmed.append(f"branch {name}")
            elif arrived_oids & one:
                arrived_on.append(name)

    keep: dict[str, frozenset[str]] = {}
    staging: dict[str, dict] = {}
    for name, tip, _c in deliverable:
        try:
            holder = gitamend.checkout_holding(repo, name)
        except OSError:
            return _refuse(Cause.WORKING_TREE_NOT_CLEAN)
        if holder is None:
            continue
        if keep_operator_changes and _same_checkout(holder, repo):
            in_way = gitamend.changes_in_the_way(holder, delivered_tips[tip])
            if in_way is None or in_way.blocking:
                return _refuse(Cause.WORKING_TREE_NOT_CLEAN, ", ".join(in_way.blocking[:3])
                               if in_way is not None else "")
            keep[name] = frozenset(in_way.carryable) | frozenset(in_way.already)
        elif gitamend.is_dirty(holder):
            return _refuse(Cause.WORKING_TREE_NOT_CLEAN)

    captured = capture_bundle(repo, [(tip, new_tips[tip]) for _n, tip, _c in deliverable],
                              _capture_path(slug, oldest[:12]))
    if not captured.ok:
        return _refuse(Cause.CAPTURE_FAILED, captured.reason)
    if settled_arrivals.to_record and arrival_record.write(
            _capture_path(slug, oldest[:12]).parent,
            arrival_questions.remapped(settled_arrivals.to_record, rebuilt.mapping)) is None:
        arrival_reasons[:] = [replace(r, cause=Cause.ARRIVALS_NOT_RECORDED)
                              if r.cause == Cause.ARRIVALS_UNDECIDED else r for r in arrival_reasons]

    try:
        moved = gitamend.point_branches(repo, deliverable, delivered_tips, keep, staging)
    except gitamend.AmendUnwindFailed as unwound:
        return _refuse(Cause.LEFT_PART_WAY, ", ".join(unwound.unrestored),
                       recovery=str(captured.path or ""))
    if moved is None:
        return _refuse(Cause.REPLAY_FAILED, ", ".join(n for n, _, _ in deliverable))

    results: list[BranchResult] = []
    failed: list[str] = []
    cleaned_here: list[str] = []
    for branch in moved:
        if branch.startswith(preserve.BRANCH_PREFIX) and not (leases or {}).get(branch):
            cleaned_here.append(branch)
            continue
        result = _force_update_branch(repo, slug, branch, token, pusher=pusher,
                                      lease=(leases or {}).get(branch),
                                      sha12=oldest[:12])
        results.append(result)
        cause = result.reason.cause if result.reason is not None else None
        if not result.force_updated and cause is not Cause.PUSH_NOT_CONFIRMED:
            failed.append(branch)
    survivors = _survivors(repo, slug, sorted(delivered_infected), token)
    refreshed = gitutil.fetch_refs(repo, token=token)
    if not refreshed.ok:
        survivors.append(Reason(Cause.REMOTE_COPY_NOT_REFRESHED, refreshed.reason))
    reachable_elsewhere, unread_refs = _refs_still_reaching(
        repo, malicious_oids | taken_out | history.on_other_refs, list(delivered_tips.values()))
    unconfirmed += unread_refs
    if reachable_elsewhere:
        survivors.append(Reason(Cause.PAYLOAD_REACHABLE_FROM_OTHER_REFS,
                                names_that_fit(reachable_elsewhere)))
    if history.cut_at:
        survivors.append(Reason(Cause.PAST_COMMITS_READ_IN_PART, str(history.cut_at)))
    survivors += _partly_read_reasons(history.partly_read | rewritten.partly_read,
                                      history.runnable | rewritten.runnable,
                                      {path for path, _oid in history.confirmed | decided},
                                      history.submodules)
    arrived_elsewhere, unread_arrived_refs = _refs_still_reaching(repo, arrived_oids,
                                                                  list(delivered_tips.values()))
    unconfirmed += unread_arrived_refs
    if arrived_on or arrived_elsewhere:
        survivors.append(Reason(Cause.ARRIVED_COPIES_REMAIN,
                                names_that_fit(sorted({*arrived_on, *arrived_elsewhere}))))
    delivered_sub = []
    for path in substitute:
        held = {_path_at(repo, t, path) for t in delivered_tips.values()}
        if True in held:
            delivered_sub.append(path)
        elif None in held:
            unconfirmed.append(f"the rewritten {path}")
    if unconfirmed:
        survivors.append(Reason(Cause.REMOVAL_NOT_CONFIRMED, names_that_fit(unconfirmed)))
    supplied = sorted(p for p in delivered_sub if p in supply_paths)
    restored = sorted(p for p in delivered_sub if p not in supply_paths)
    if supplied:
        survivors.insert(0, Reason(Cause.FILE_REPLACED_WITH_SUPPLIED_CONTENT, ", ".join(supplied)))
    if restored:
        survivors.insert(0, Reason(Cause.FILE_RESTORED_TO_A_CLEAN_VERSION, ", ".join(restored)))
    if recovered_paths:
        survivors.insert(0, Reason(Cause.FILE_RESTORED_FROM_A_PARENT,
                                   ", ".join(sorted(recovered_paths))))
    for reason in reversed(_supply_refusals(rejected_supply)):
        survivors.insert(0, reason)
    for reason in reversed(arrival_reasons):
        survivors.insert(0, reason)
    if unhandled:
        survivors.insert(0, Reason(Cause.PAYLOAD_NEEDS_MANUAL_RECOVERY,
                                   str(len(unhandled)), ", ".join(sorted(unhandled))))
    if cleaned_here:
        survivors.append(Reason(Cause.SAVED_WORK_CLEANED_HERE, ", ".join(cleaned_here)))
    recovery = ""
    if failed:
        try:
            unrestored = gitamend.restore_branches(repo, deliverable, moved, failed, keep, staging)
        except gitamend.AmendUnwindFailed as unwound:
            unrestored = unwound.unrestored
        if unrestored:
            survivors.insert(0, Reason(Cause.LEFT_PART_WAY, ", ".join(unrestored)))
            recovery = str(captured.path or "")
    held_now = _held_since_delivery(repo)
    for record, remaining in settled_arrivals.recorded:
        arrival_record.keep_only(record, arrival_questions.still_to_ask(
            arrival_questions.remapped(remaining, rebuilt.mapping), arrival_questions.Settled(),
            held_now))
    if settled_arrivals.decided is not None:
        decided_now, read_now = arrival_record.read_decisions(slug)
        kept_now = [d for d in arrival_questions.remapped_decisions(decided_now, rebuilt.mapping)
                    if d.decision == arrival_record.KEEP_DECISION
                    or held_now(d.forms, d.path, d.blob)]
        if not (read_now and arrival_record.keep_decisions(slug, kept_now)):
            survivors.append(Reason(Cause.ARRIVALS_ANSWERS_NOT_SAVED, str(len(decided_now))))
    placed_holders = {path: commits
                      for path, commits in {**merge_taken_holders,
                                            **settled_arrivals.holders}.items()
                      if (path, arrived.get(path)) not in unplaced}
    for (path, _oid), commits in history.take_out.items():
        placed_holders.setdefault(path, set()).update(commits)
    removed = _delivered_removals(replacements, delivered_reach,
                                  {**remove_holders, **placed_holders}, purge_holders)
    touched = len(delivered_infected)
    label = (oldest[:12] if touched == 1 else f"{touched} commits from {oldest[:12]}")
    if not results and not isolated:
        return AmendOutcome(repository=display, completed=False, commit=label,
                            reasons=tuple(survivors), removed=tuple(sorted(removed)),
                            recovery=recovery)
    return amended(display, label, tuple(results) + tuple(isolated), tuple(survivors),
                   sorted(removed), recovery=recovery)
