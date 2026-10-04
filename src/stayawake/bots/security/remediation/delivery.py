#!/usr/bin/env python3
"""What a commit that delivered a confirmed payload brought with it, read from the history."""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import Iterable, Mapping

from stayawake.bots.security.models import CONFIRMED
from stayawake.lib import git as gitutil
from stayawake.lib.git.merge import detect as mergedetect
from stayawake.lib.git.objects import read_blobs
from stayawake.lib.git.query import GITLINK_MODE, TREE_MODE, entries_at

MAX_PATH_HISTORY = 100_000


def history_of(repo: Path, path: str, **walk) -> list[str] | None:
    """List the commits that changed a path, newest first. Takes the repo, the path and the walk's
    options. Returns them, or None when the history is too long to walk. Raises `Unread` naming
    every copy of the path when git could not walk it."""
    changed = gitutil.file_commits(repo, path, limit=MAX_PATH_HISTORY, **walk)
    if changed is None:
        raise gitutil.Unread(f"every copy of {path}")
    return None if len(changed) >= MAX_PATH_HISTORY else changed



def came_after(repo: Path, path: str, forms, start: str = "") -> bool | None:
    """Tell whether the version of a file a commit holds was set by one of a delivery's ids or a
    commit after one. Takes the repo, the path, the ids, and the commit id, HEAD when "". Returns
    the answer, or None when git could not tell."""
    try:
        changed = history_of(repo, path, start=start) if start else history_of(repo, path)
    except gitutil.Unread:
        return None
    if not changed:
        return None
    answers = [c == changed[0] or gitutil.ancestry(repo, c, changed[0]) for c in forms]
    if True in answers:
        return True
    return None if None in answers else False

MENTIONS_COUNTED = 60
_MENTIONS_READ_EACH = 8 * 1024 * 1024
_MENTIONS_READ_TOTAL = 128 * 1024 * 1024
_BINARY_PROBE = 8000


def files_naming(repo: Path, paths) -> dict[str, frozenset[str]] | None:
    """Find, for each path, the text files of the checked-out commit that mention its file name.
    Takes the repo and the paths, at most `MENTIONS_COUNTED` of which are looked up. Returns each
    looked-up path mapped to the files naming it, or None when not every file could be read."""
    try:
        held = entries_at(repo, "HEAD")
    except gitutil.Unread:
        return None
    files = {path: oid for path, (mode, oid) in held.items()
             if mode not in (GITLINK_MODE, TREE_MODE)}
    bodies, _sizes = read_blobs(repo, list(files.values()), max_each=_MENTIONS_READ_EACH,
                                max_total=_MENTIONS_READ_TOTAL)
    if any(oid not in bodies for oid in files.values()):
        return None
    texts = {path: bodies[oid] for path, oid in files.items()
             if b"\0" not in bodies[oid][:_BINARY_PROBE]}
    out = {}
    for path in list(dict.fromkeys(paths))[:MENTIONS_COUNTED]:
        name = PurePosixPath(path).name.encode("utf-8", "surrogateescape")
        out[path] = frozenset(other for other, body in texts.items() if name and name in body)
    return out


def commits_carrying(repo: Path, path: str, carries) -> list[str] | None:
    """Walk a path's history and collect the commits whose version of it carries a payload. Takes
    the repo, the path and `carries(sha, path)`. Returns those commits, newest first, or None when
    the history is too long to walk."""
    changed = history_of(repo, path, all_branches=True)
    if changed is None:
        return None
    return [sha for sha in changed if carries(sha, path)]


def add_first_carriers(repo: Path, carriers: Mapping[str, Iterable[str]], deliveries: dict,
                       unread: list[str]) -> None:
    """Add the commits that first carry each path's payload to the deliveries. Takes the repo, each
    path mapped to the commits holding a payload version of it, the deliveries to add to, and where
    to name a path git could not read."""
    for path in sorted(carriers):
        try:
            found = first_carriers(repo, {path: carriers[path]})
        except gitutil.Unread as missed:
            if missed.subject not in unread:
                unread.append(missed.subject)
            continue
        for sha, paths in found.items():
            deliveries[sha] = tuple(dict.fromkeys(deliveries.get(sha, ()) + paths))


@dataclass(frozen=True)
class Brought:
    """What one commit brought.

    `added` pairs each file the commit added, present in none of its parents, with the blob it
    added; `changed` names every other path the commit gave content no parent had. `parentless` is
    True for a commit with no parent.
    """

    commit: str
    added: tuple[tuple[str, str], ...] = ()
    changed: tuple[str, ...] = ()
    parentless: bool = False

    def added_blobs(self) -> dict[str, str]:
        """Map each added file to the blob the commit added. Returns the map."""
        return dict(self.added)


@dataclass(frozen=True)
class Origin:
    """The delivery that added a file: its commit and the payload paths saw removes from it, both
    empty when no delivery added it. `unread` is True when git could not read what a delivery
    added."""

    commit: str = ""
    payloads: tuple[str, ...] = ()
    unread: bool = False


def confirmed_commits(findings) -> list:
    """Select the commit-carrying findings `saw fix amend` acts on, with the confirmed-payload paths
    in each. Takes the findings. Returns `(finding, anchors)` per commit that is itself confirmed,
    or that names a confirmed payload among its paths."""
    findings = list(findings)
    external = {getattr(f, "path", "") for f in findings
                if getattr(f, "confidence", None) == CONFIRMED
                and not getattr(f, "advisory_only", False)
                and not getattr(f, "commit_sha", None)}
    found = []
    seen: set[str] = set()
    for f in findings:
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


def swept_by(repo: Path, merge_sha: str, related, anchors) -> list[str]:
    """Select what a merge's removal takes out of the paths it introduced: each confirmed-payload
    path and the payload's delivery tree. Takes the repo, the merge, the merge's introduced paths,
    and the confirmed-payload paths among them. Returns the paths to remove. Raises `Unread` when
    git could not read the merge."""
    trees = {mergedetect.delivery_subtree(repo, merge_sha, a) for a in anchors}
    trees.discard(None)
    return [path for path in related
            if path in anchors or any(path == d or path.startswith(d + "/") for d in trees)]


UNRESOLVED = "unresolved"
UNREAD = "unread"


@dataclass
class MergeSweeps:
    """What removing an evil merge does with each commit a confirmed finding names.

    `swept` maps each commit to the paths taken out of it without asking, and `payload` to the
    confirmed payload paths among them. `left_to_ask` maps each
    commit with nothing to take out to the named files no parent of it holds, each put to the
    operator on its own. `failed` lists, in the findings' order, each reported commit that resolves
    to none, as `(UNRESOLVED, its id and files)`, and what git could not read, as
    `(UNREAD, what)`.
    """

    swept: dict[str, tuple[str, ...]] = field(default_factory=dict)
    payload: dict[str, tuple[str, ...]] = field(default_factory=dict)
    left_to_ask: dict[str, tuple[str, ...]] = field(default_factory=dict)
    failed: list[tuple[str, str]] = field(default_factory=list)


def sweep_merges(repo: Path, findings) -> MergeSweeps:
    """Work out what removing an evil merge takes out of each commit a confirmed finding names.
    Takes the repo and the scan's findings. Returns the `MergeSweeps`."""
    out = MergeSweeps()
    for finding, anchors in confirmed_commits(findings):
        reported = getattr(finding, "commit_sha", None) or ""
        related = tuple(getattr(finding, "related_paths", ()) or ())
        sha = gitutil.stdout(repo, ["rev-parse", "--verify", "--quiet",
                                    f"{reported}^{{commit}}"]).strip()
        if not sha:
            named = ", ".join(related)
            out.failed.append((UNRESOLVED, f"{reported[:12]}: {named}" if named
                               else (reported[:12] or "?")))
            continue
        try:
            taken = tuple(swept_by(repo, sha, related, anchors))
            born = () if taken else tuple(sorted(mergedetect.born_at_merge(repo, sha, related)))
        except gitutil.Unread as missed:
            out.failed.append((UNREAD, missed.subject))
            continue
        if taken:
            out.swept[sha] = tuple(dict.fromkeys(out.swept.get(sha, ()) + taken))
            out.payload[sha] = tuple(dict.fromkeys(
                out.payload.get(sha, ()) + tuple(p for p in taken if p in anchors)))
        else:
            out.left_to_ask[sha] = born
    return out


def _stored_blob(repo: Path, treeish: str, path: str) -> str | None:
    """Read the object a commit stores at a path. Takes the repo, the commit and the path. Returns
    its id, or None when nothing is there. Raises `Unread` when git could not answer."""
    answered, entry = gitutil.entry_at(repo, treeish, path)
    if not answered:
        raise gitutil.Unread(f"every copy of {path}")
    return entry[1] if entry is not None else None


def first_carriers(repo: Path, carriers: Mapping[str, Iterable[str]]) -> dict[str, tuple[str, ...]]:
    """Find the commits that first carry each path's payload. Takes the repo and each path mapped to
    the commits holding a payload version of it. Returns each such commit whose parents hold none of
    those versions, mapped to the paths it first carries. Raises `Unread` when git could not read a
    commit or its parents."""
    out: dict[str, list[str]] = {}
    for path in sorted(carriers):
        holders = sorted(set(carriers[path]))
        versions = {_stored_blob(repo, sha, path) for sha in holders} - {None}
        for sha in holders:
            parents = gitutil.parents(repo, sha)
            if parents is None:
                raise gitutil.Unread(f"the parents of {sha[:12]}")
            if any(_stored_blob(repo, parent, path) in versions for parent in parents):
                continue
            out.setdefault(sha, []).append(path)
    return {sha: tuple(paths) for sha, paths in out.items()}


def brought_by(repo: Path, commit: str) -> Brought:
    """Read what a commit added and changed against its parents. Takes the repo and the commit.
    Returns the `Brought`. Raises `Unread` when git could not read the commit or its parents."""
    parents = gitutil.parents(repo, commit)
    if parents is None:
        raise gitutil.Unread(f"what {commit[:12]} added")
    if not parents:
        held = entries_at(repo, commit)
        return Brought(commit, tuple(sorted((path, oid) for path, (mode, oid) in held.items()
                                            if mode not in (TREE_MODE, GITLINK_MODE))),
                       parentless=True)
    differing = gitutil.changed_paths(repo, parents[0], commit, "AMT", renames=False)
    for parent in parents[1:]:
        differing &= gitutil.changed_paths(repo, parent, commit, "AMT", renames=False)
    born = mergedetect.born_at_merge(repo, commit, differing)
    held = entries_at(repo, commit, sorted(differing))
    added = tuple((path, held[path][1]) for path in sorted(born)
                  if path in held and held[path][0] not in (TREE_MODE, GITLINK_MODE))
    taken = {path for path, _blob in added}
    return Brought(commit, added, tuple(sorted(differing - taken)))


def brought_by_each(repo: Path, commits: Iterable[str],
                    known: dict[str, Brought | None] | None = None) -> dict[str, Brought | None]:
    """Read what each of several commits brought, once each. Takes the repo, the commits and what
    is already known. Returns each commit mapped to its `Brought`, or None where git could not read
    it."""
    known = {} if known is None else known
    for commit in commits:
        if commit not in known:
            try:
                known[commit] = brought_by(repo, commit)
            except gitutil.Unread:
                known[commit] = None
    return known


def origin_of(path: str, deliveries: Mapping[str, tuple[str, ...]],
              brought: Mapping[str, Brought | None]) -> Origin:
    """Find the delivery that added a file. Takes the path, each delivery mapped to the payload
    paths saw removes from it, and what each delivery brought, None where git could not read it.
    Returns the `Origin`."""
    unread = False
    for commit, payloads in deliveries.items():
        found = brought.get(commit)
        if found is None:
            unread = True
        elif path in found.added_blobs():
            return Origin(commit, tuple(payloads))
    return Origin(unread=unread)
