#!/usr/bin/env python3
"""`saw fix amend` — replace past commits that still carry the payload and force-update
each branch they sat on. Never `--pr`. Never moves a tag. Bare `saw fix` is unchanged.
"""
from __future__ import annotations

import contextlib
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, NamedTuple

from stayawake.bots.security.models import CONFIRMED
from stayawake.utils import scratch
from stayawake.bots.security.pr.resolve import REMOVE, RESTORE, SUPPLY
from stayawake.bots.security.remediation import (changes, footprint, installed, live, oracle,
                                                 preserve)
from stayawake.bots.security.pr.fix_verdict import Checkout, checkout_clauses, checkout_of
from stayawake.bots.security.scanner import scan_target
from stayawake.bots.security.targets import LocalRepoTarget
from stayawake.lib.git.auth import run_remote_git
from stayawake.lib.git.borrowed import BorrowError, borrow
from stayawake.lib.git import remote as gitremote
from stayawake.lib.git.run import LOCAL_TIMEOUT, UNTRUSTED
from stayawake.bots.security.pr.outcome import (AmendOutcome, BranchResult, Cause, Reason,
                                                amended, names_that_fit, refused,
                                                render_amend_line, with_checkout)
from stayawake.lib.git import authority
from stayawake.lib.git.merge import detect as mergedetect
from stayawake.lib.git.write import amend as gitamend
from stayawake.lib.git.write import rebuild as gitrebuild
from stayawake.lib.git.write.capture import capture_bundle
from stayawake.lib.git.write.push import PushResult, force_update_head, publish_head
from stayawake.lib.git.write import sign
from stayawake.lib.git.write.replace import replacement_tree, write_blob_bytes
from stayawake.lib import git as gitutil
from stayawake.utils import env


def _full(repo: Path, sha: str) -> str:
    return gitutil.stdout(repo, ["rev-parse", "--verify", f"{sha}^{{commit}}"]).strip()


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


def _history_of(repo: Path, path: str, **walk) -> list[str] | None:
    """The commits that changed a path, newest first. Takes the repo, the path and the walk's
    options. Returns them, or None when the history is too long to walk. Raises `Unread` naming
    every copy of the path when git could not walk it."""
    changed = gitutil.file_commits(repo, path, limit=_MAX_PATH_HISTORY, **walk)
    if changed is None:
        raise _unread(path)
    return None if len(changed) >= _MAX_PATH_HISTORY else changed


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
                   clean_shas, infected: dict) -> tuple[set[str], list[str]]:
    """Collect the stored versions this run takes out of history. Takes the repo, the blobs removed
    and substituted, the commits holding each purged path, the excised paths with their footprint
    checks, the commits carrying those footprints, and each confirmed commit with the paths it
    carries the payload at. Returns their blob ids, and the paths whose version git could not
    read."""
    oids = set(remove.values()) | {fo for fo, _e in substitute.values()}
    unsure: list[str] = []
    held = [(path, sha) for path, holders in purge_holders.items() for sha in holders]
    held += [(path, sha) for sha, paths in infected.items() for path in paths]
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


def _swept_paths(repo: Path, merge_sha: str, related, anchors) -> list[str]:
    """The paths to remove from `related`: a confirmed-payload path, or a path in a payload's
    entirely graft-introduced delivery tree. Takes the repo, the merge sha, the merge's introduced
    paths, and the confirmed-payload paths among them. Returns the subset to remove."""
    trees = {mergedetect.delivery_subtree(repo, merge_sha, a) for a in anchors}
    trees.discard(None)
    out = []
    for path in related:
        if path in anchors or any(path == d or path.startswith(d + "/") for d in trees):
            out.append(path)
    return out


def _confirmed_commits(scan) -> list:
    """Commit-carrying findings to act on, with the confirmed-payload paths in each. Takes the scan.
    Returns `(finding, anchors)` per commit that is itself confirmed, or that names a confirmed
    payload among its paths."""
    external = {getattr(f, "path", "") for f in scan.findings
                if getattr(f, "confidence", None) == CONFIRMED
                and not getattr(f, "advisory_only", False)
                and not getattr(f, "commit_sha", None)}
    found = []
    seen: set[str] = set()
    for f in scan.findings:
        related = getattr(f, "related_paths", None)
        sha = getattr(f, "commit_sha", None)
        if not related or not sha or sha in seen:
            continue
        confirmed = getattr(f, "confidence", None) == CONFIRMED
        ext = set(related) & external
        if not (confirmed or ext):
            continue
        own = set(getattr(f, "payload_paths", ()) or (related if confirmed else ()))
        anchors = tuple(sorted((own | ext) & set(related)))
        seen.add(sha)
        found.append((f, anchors))
    return found


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
    for finding, anchors in _confirmed_commits(scan):
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


def _blast_radius(repo: Path, path: str,
                  infected: dict[str, tuple[str, ...]]) -> tuple[str, tuple[str, ...]]:
    """`(introduced_by, arrived_with_removed)` tying `path` to a confirmed injection merge that
    brought it: the merge's short id and the confirmed paths saw is removing from it. `("", ())`
    when no known injection merge brought this path; never raises."""
    for sha, payloads in infected.items():
        try:
            born = mergedetect.born_at_merge(repo, sha, (path,))
        except Exception:
            continue
        if path in born:
            return sha[:12], tuple(payloads)
    return "", ()


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
    hist = _foreign_history(repo, path, entry[1])
    if hist is None:
        return "too-large"
    _holders, foreign = hist
    if not foreign:
        return ""
    remove[path] = entry[1]
    remove_shas.update(foreign)
    remove_holders[path] = set(foreign)
    return ""


def _purge_carriers(repo: Path, path: str, survives) -> set[str] | None:
    """Walk `path`'s history and collect the commits whose version of it carries a payload. Takes the
    repo, the path, and the `survives` oracle that judges each version. Returns those commits, or None
    when the history is too long to walk."""
    changed = _history_of(repo, path, all_branches=True)
    if changed is None:
        return None
    return {sha for sha in changed if survives(sha, path)}


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
    for sha in _history_of(repo, path, first_parent=True) or ():
        answered, entry = gitutil.entry_at(repo, sha, path)
        if not answered or entry is None or entry[1] == head_oid:
            continue
        if not survives(sha, path):
            return entry, sha[:12]
    return None


def _register_substitute(repo: Path, path: str, entry: tuple[str, str], substitute: dict,
                         substitute_shas: set, treeish: str = "HEAD") -> str:
    """Schedule `entry` to be put back wherever history holds `path` at the blob it has at `treeish`,
    recording the commits that hold it. Takes the repo, the path, the replacement tree entry, the two
    substitution maps to fill, and the treeish to key on. Returns "too-large" when the history is too
    long to walk, else ""."""
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
    return ""


def _register_supply(repo: Path, path: str, content: bytes, substitute: dict, substitute_shas: set,
                     payload, allowlist, opts) -> str:
    """Scan operator-supplied `content` and, when it carries no payload, schedule it to replace `path`
    wherever history holds the blob `path` has at HEAD. Takes the repo, the path, the content, the two
    substitution maps to fill, and the scan inputs. Returns "carries" when the content itself carries a
    payload, "unwritable" when its blob cannot be written, "too-large" when the history is too long to
    walk, else ""."""
    if oracle.content_confirms(content, path, payload, allowlist, opts):
        return "carries"
    current = _stored_entry(repo, "HEAD", path)
    if current is None:
        return ""
    blob = write_blob_bytes(repo, content)
    if blob is None:
        return "unwritable"
    return _register_substitute(repo, path, (current[0], blob), substitute, substitute_shas)


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
                     infected: dict[str, tuple[str, ...]], *, unread: list[str]) -> list:
    """Build the operator's list of heuristic file findings this verb would otherwise leave untouched.
    Takes the repo, the scan, the paths the confirmed lanes already own, and each injection merge
    mapped to the paths saw is removing from it, which tells the operator what a file arrived with.
    Returns one `UncertainItem` per finding whose file is present at HEAD; a path git could not read
    is named in `unread`."""
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
            introduced_by, arrived = _blast_radius(repo, path, infected)
            out.append(UncertainItem(
                path=path, category=getattr(f, "category", "") or "",
                signature_id=getattr(f, "signature_id", "") or "",
                description=getattr(f, "description", "") or "",
                preview=gitutil.blob(repo, entry[1]) or b"",
                introduced_by=introduced_by, arrived_with_removed=arrived))
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


_MAX_PATH_HISTORY = 100_000


def _carrying_commits(repo: Path, path: str, carries) -> list[str] | None:
    """Walk `path`'s history and collect the commits whose version of it carries the footprint.
    Takes the repo, the path, and the footprint check. Returns those commits, or None when the
    history is too long to walk."""
    changed = _history_of(repo, path, all_branches=True)
    if changed is None:
        return None
    return [sha for sha in changed if carries(_stored_text(repo, sha, path))]


def _foreign_history(repo: Path, path: str, oid: str) -> tuple[list[str], list[str]] | None:
    """Walk `path`'s history and separate the commits that hold it from those holding exactly `oid`.
    Takes the repo, the path, and that blob id. Returns `(holders, holders at oid)`, or None when the
    history is too long to walk."""
    changed = _history_of(repo, path, all_branches=True)
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
    """Every ref the repository keeps, each checkout's own refs, every stash entry and each
    checkout's HEAD, as `(name, tip)`. Takes the repo. Returns those it could list, and what it could
    not list."""
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
    worktrees = _answer(repo, ["worktree", "list", "--porcelain"])
    if worktrees is None:
        unsure.append("the other checkouts")
    path = ""
    for line in (worktrees or "").splitlines():
        if line.startswith("worktree "):
            path = line[len("worktree "):]
        elif line.startswith("HEAD "):
            out.append((f"worktree {path}", line[len("HEAD "):].strip()))
    return out, unsure


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
    """Where the objects the replacement orphans are captured before any ref moves.

    Outside the repository entirely. Inside the worktree a new file makes the tree dirty and the
    ref move is then refused; inside the git directory the capture dies with the checkout, and on
    `--remote` that checkout is a temporary clone deleted seconds after the remote refs move — so
    the evidence had a shorter life than the destruction it authorised. Cross-run state is the one
    place that outlives both.
    """
    safe = "".join(c if c.isalnum() or c in "-._" else "-" for c in slug) or "repository"
    return Path(env.xdg_state_home()) / "saw" / "amend" / safe / sha12 / "capture.bundle"


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

    def _refuse(cause: Cause, detail: str = "", subjects: str = "",
                recovery: str = "") -> AmendOutcome:
        """Refuse, carrying any operator answer the run could not use."""
        return refused(display, cause, detail, subjects, recovery,
                       also=_supply_refusals(rejected_supply))

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
    commits = _confirmed_commits(scan)
    infected: dict[str, tuple[str, ...]] = {}
    uncharacterized: dict[str, tuple[str, str]] = {}
    uncharacterized_paths: dict[str, tuple[str, ...]] = {}
    for finding, anchors in commits:
        reported = getattr(finding, "commit_sha", None) or ""
        sha = _full(repo, reported)
        if not sha:
            named = ", ".join(getattr(finding, "related_paths", ()) or ())
            return _refuse(Cause.CONFIRMED_COMMIT_UNRESOLVED,
                           f"{reported[:12]}: {named}" if named else (reported[:12] or "?"))
        related = tuple(getattr(finding, "related_paths", ()) or ())
        try:
            paths = tuple(_swept_paths(repo, sha, related, anchors))
            born = () if paths else tuple(sorted(mergedetect.born_at_merge(repo, sha, related)))
        except gitutil.Unread as missed:
            return _refuse(Cause.HISTORY_UNREADABLE, missed.subject)
        if not paths:
            uncharacterized[sha] = ("shape", sha[:12])
            uncharacterized_paths[sha] = born
            continue
        infected[sha] = tuple(dict.fromkeys(infected.get(sha, ()) + paths))

    clean: dict[str, tuple] = {}
    clean_shas: set[str] = set()
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

    if resolver is not None:
        held = set(clean) | set(remove) | {p for ps in infected.values() for p in ps}
        for item in _uncertain_items(repo, scan, held, infected, unread=unread):
            try:
                answer = resolver(item)
            except Exception:                  # a resolver fault leaves the file for review
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
            try:
                answer = resolver(item)
            except Exception:
                continue
            with _naming_unread(unread):
                if answer.action == RESTORE and answer.restore is not None:
                    if _register_substitute(repo, item.path, answer.restore,
                                            substitute, substitute_shas) == "too-large":
                        return _refuse(Cause.HISTORY_TOO_LARGE_TO_ENUMERATE, item.path)
                elif answer.action == SUPPLY and isinstance(answer.supply, bytes):
                    refusal = _register_supply(repo, item.path, answer.supply, substitute,
                                               substitute_shas, oracle.payload_matchers(signatures),
                                               allowlist, opts)
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
    for sha in list(infected):
        rep = replacement_tree(repo, sha, infected[sha], survives)
        if not rep.ok:
            blocked_infected[sha] = (rep.kind or "replacement", rep.refusal or sha[:12])
    if resolver is not None and blocked_infected:
        for sha in blocked_infected:
            with _naming_unread(unread):
                present = [p for p in infected[sha] if _stored_entry(repo, sha, p) is not None]
                for item in _path_items(repo, present, sha, sha[:12], unread=unread):
                    try:
                        answer = resolver(item)
                    except Exception:
                        continue
                    if answer.action == REMOVE and _register_purge(
                            repo, item.path, purge, purge_shas, survives) == "too-large":
                        return _refuse(Cause.HISTORY_TOO_LARGE_TO_ENUMERATE, item.path)

    if not infected and not clean and not remove and not substitute and not purge:
        if unhandled:
            return _refuse(Cause.PAYLOAD_NEEDS_MANUAL_RECOVERY,
                           str(len(unhandled)), ", ".join(sorted(unhandled)))
        return _refuse(Cause.NO_CONFIRMED_PAYLOAD)

    malicious_oids, unread_versions = _payload_blobs(repo, remove, substitute, purge_holders, clean,
                                                     clean_shas, infected)

    all_infected = (set(infected) | clean_shas | remove_shas | substitute_shas | purge_shas
                    | set(uncharacterized))
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
        # A confirmed commit no branch reaches is not amendable here, and counting it as replaced
        # would report commits the run never touched.
        return _refuse(Cause.COMMIT_ON_NO_BRANCH,
                       ", ".join(s[:12] for s in uncovered))
    oldest = plan[0][0]

    # Two sources: whether a signature is owed is read from the commits being replaced (`repo`);
    # the signer that produces it is read from the operator's own config context. `operator_context`
    # is not a context saw named, so its program keys are not trusted (see `signing_status`).
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
        if all(p in purge for p in paths):
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

    # Objects only — no reference moves until the capture below has been read back.
    rebuilt = gitrebuild.rebuild_without_payload(
        repo, plan, replacements,
        lambda sha, tree, new_parents: gitamend.rewrite_commit(repo, sha, tree, new_parents,
                                                               signing),
        survives, clean=clean, remove=remove, pre_blocked=blocked_commits,
        substitute=substitute, purge=purge)
    blocked = rebuilt.blocked

    new_tips = {tip: rebuilt.tip(tip) for _n, tip, _c in heads}
    flagged = ({p for paths in infected.values() for p in paths}
               | set(clean) | set(remove) | set(substitute) | set(purge))

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
    # Count and name only commits a delivered branch reaches, not ones rebuilt for an isolated one.
    delivered_reach = _reached_from(graph, [t for _n, t, _c in deliverable])
    oldest = next((sha for sha, _ps in plan
                   if sha in rebuilt.mapping and sha in delivered_reach), oldest)
    delivered_infected = [s for s in all_infected if s in rebuilt.mapping and s in delivered_reach]

    path_checks = {p: (lambda tr, pth: _judged(survives(tr, pth))) for p in flagged}
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
    reachable_elsewhere, unread_refs = _refs_still_reaching(repo, malicious_oids,
                                                            list(delivered_tips.values()))
    unconfirmed += unread_refs
    if reachable_elsewhere:
        survivors.append(Reason(Cause.PAYLOAD_REACHABLE_FROM_OTHER_REFS,
                                names_that_fit(reachable_elsewhere)))
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
            # The pre-push caller already reports this; reporting it here too is the point — the
            # same refused restore was silent on this side, and a local branch left on rewritten
            # history is the operator's problem whether or not any push succeeded.
            survivors.insert(0, Reason(Cause.LEFT_PART_WAY, ", ".join(unrestored)))
            recovery = str(captured.path or "")
    removed = _delivered_removals(replacements, delivered_reach, remove_holders, purge_holders)
    touched = len(delivered_infected)
    label = (oldest[:12] if touched == 1 else f"{touched} commits from {oldest[:12]}")
    if not results and not isolated:
        return AmendOutcome(repository=display, completed=False, commit=label,
                            reasons=tuple(survivors), removed=tuple(sorted(removed)),
                            recovery=recovery)
    return amended(display, label, tuple(results) + tuple(isolated), tuple(survivors),
                   sorted(removed), recovery=recovery)
