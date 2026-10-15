#!/usr/bin/env python3
"""Decide whether a path the merge deviates on is a REAL evil-merge signal.

The evidence available depends on what git could have done at that path, so the two cases are judged
apart rather than by one heuristic:
"""
from __future__ import annotations

import re
from pathlib import Path

from stayawake.lib.git.objects import blob_sizes, decode_text, own_view, read_blobs
from stayawake.lib.git.query import (GITLINK_MODE, TREE_MODE, Unread, changed_paths, entries_at,
                                     file_text_at, introduced_added_text, stores_path)

CLEAN_DEVIATION = ("recorded content differs from the clean auto-merge at a path that did NOT "
                   "conflict — git cannot produce this, so it was edited during the merge")


def corroborated(repo: str | Path, base_tree: str, merge_sha: str, path: str,
                 parent_shas: list[str], *, conflicted: bool = True,
                 content_sig=None, obfuscation_reason=None) -> tuple[bool, str]:
    """(corroborated, reason) for one deviating path. `conflicted` says whether the auto-merge
    conflicted here; it defaults to True so an unknown conflict state demands content evidence
    rather than being handed the decisive verdict.

    Content and obfuscation checks are INJECTED as callables so this module (in `lib.git`) stays
    free of any `bots.security` import — a lower layer must never depend up on the security domain. `content_sig` is `callable(text) -> reason|None`; `obfuscation_reason` is
    `callable(path, delta, baseline_text) -> reason|None`. Absent → not evaluated. Raises `Unread`
    when git could not read what the decision rests on."""
    # A file no parent carries is review-evading whatever its content: no parent's diff shows it.
    if all(not stores_path(repo, p, path) for p in parent_shas):
        return True, "introduced file absent from every parent (review-evading)"

    pairs = _introduced(repo, base_tree, merge_sha, path, parent_shas)
    deltas = [d for _b, d in pairs]
    if not deltas:
        # A deviation that ADDS nothing injects nothing — it removed or reordered. Real, but a
        # different question from "what did this merge smuggle in", which is this detector's
        # contract; flagging it here reported an ordinary edit as a payload.
        return False, ""

    if content_sig is not None:
        for d in deltas:
            hit = content_sig(d)
            if hit:
                return True, f"merge-introduced hunk matches signature: {hit}"

    if not conflicted:
        return True, CLEAN_DEVIATION

    # Conflicted: the resolution legitimately rewrites this path, so only EXECUTABLE obfuscation
    # counts. Density/entropy is not consulted — a resolution that pulls a file in wholesale reads as
    # one long high-entropy hunk, which is how ordinary framework source read as a packed payload.
    if obfuscation_reason is not None:
        for b, d in pairs:
            baseline = file_text_at(repo, b, path)
            if baseline is None:
                raise Unread(path)
            reason = obfuscation_reason(path, d, baseline[1])
            if reason:
                return True, f"obfuscated merge-introduced hunk: {reason}"
    return False, ""


def carried_payloads(repo: str | Path, base_tree: str, merge_sha: str, paths: list[str],
                     parent_shas: list[str], payload_sig, budget: "ReadBudget"):
    """Find the known payload a merge brought into each path it deviates on. Takes the repo, the
    clean merge's tree, the merge, the paths, the merge's parents, `payload_sig` and the scan's read
    budget. `payload_sig(path, merged_text, earlier, held_by_a_parent) -> payload | None` names a
    payload the merge's version carries and the earlier versions do not; `earlier()` reads the clean
    merge's and each parent's version where they store the path, and `held_by_a_parent(text, scope,
    key)` tells whether a file a parent changed since the merge base, among those `scope(path)`
    accepts, holds that text, ignoring case and spacing. The merge's own versions are always read;
    only the earlier versions draw on the budget. A submodule or a directory carries no text. Returns
    the payload named per path, and the paths that could not be checked. Raises `Unread` when git
    could not list what the merge holds."""
    held = entries_at(repo, merge_sha, paths)
    blobs = {path: entry[1] for path, entry in held.items() if entry[0] not in (GITLINK_MODE, TREE_MODE)}
    unread = [path for path in paths if path not in held]
    read, _sizes = read_blobs(repo, list(dict.fromkeys(blobs.values())), max_each=_EACH_MAX,
                              max_total=_MERGE_BYTES_MAX)
    texts = {}
    for path, oid in blobs.items():
        if oid in read:
            texts[path] = decode_text(read[oid])
        else:
            unread.append(path)
    held_by_a_parent = _ParentsWrote(repo, parent_shas, budget)
    earlier = [_Versions(repo, treeish, list(texts), budget)
               for treeish in dict.fromkeys([base_tree, *parent_shas])]
    payloads: dict[str, object] = {}
    for path, text in texts.items():
        try:
            hit = payload_sig(path, text, lambda path=path: [held for versions in earlier for held in versions(path)],
                              held_by_a_parent)
        except Unread:
            unread.append(path)
            continue
        if hit:
            payloads[path] = hit
    return payloads, tuple(unread)


_EACH_MAX = 16_000_000
_MERGE_BYTES_MAX = 256_000_000
_SCAN_BYTES_MAX = 64_000_000
_SCAN_FILES_MAX = 20_000
_PARENT_FILES_MAX = 2_000
_SEARCHES_MAX = 64
_SPACING = re.compile(r"\s+")


class OverBudget(Unread):
    """The known-payload check has read as much as it reads in one scan."""


class ReadBudget:
    """Hold how much the known-payload check may still read of earlier versions in one scan. Takes
    the most bytes and the most files; once either runs out, every later read is refused."""

    def __init__(self, size: int | None = None, files: int | None = None):
        self.size = _SCAN_BYTES_MAX if size is None else size
        self.files = _SCAN_FILES_MAX if files is None else files

    def take(self, files: int, size: int, subject: str) -> None:
        if files > self.files or size > self.size:
            self.size = self.files = 0
            raise OverBudget(subject)
        self.files -= files
        self.size -= size


def _read_versions(repo: str | Path, treeish: str, paths, budget: ReadBudget) -> dict[str, str]:
    """Read the files a commit or tree stores at some paths, in one batch, within the budget. Takes
    the repo, the commit or tree, the paths (None for every file it stores) and the budget. Returns
    each file's text by path; a submodule or a directory has none. Raises `Unread` when git could not
    read one, and `OverBudget` when they are more than the budget covers."""
    held = entries_at(repo, treeish, paths)
    blobs = {path: oid for path, (mode, oid) in held.items() if mode not in (GITLINK_MODE, TREE_MODE)}
    if len(blobs) > _PARENT_FILES_MAX:
        raise OverBudget(f"the files of {treeish[:12]}")
    sizes = blob_sizes(repo, list(blobs.values()))
    if sizes is None:
        raise Unread(f"the files of {treeish[:12]}")
    wanted = set(blobs.values())
    if any(sizes.get(oid, 0) > _EACH_MAX for oid in wanted) or sum(sizes.get(oid, 0) for oid in wanted) > budget.size:
        raise OverBudget(f"the files of {treeish[:12]}")
    read, _ = read_blobs(repo, list(wanted), max_each=_EACH_MAX, max_total=budget.size)
    budget.take(len(read), sum(len(body) for body in read.values()), f"the files of {treeish[:12]}")
    out: dict[str, str] = {}
    for path, oid in blobs.items():
        if oid not in read:
            raise Unread(path)
        out[path] = decode_text(read[oid])
    return out


class _Versions:
    """Read, once and in one batch, the versions a commit or tree stores of several paths. Takes the
    repo, the commit or tree, the paths and the budget; `versions(path)` returns that path's text in a
    list, or an empty list where it stores none, and raises on every call when the read failed."""

    def __init__(self, repo: str | Path, treeish: str, paths: list[str], budget: ReadBudget):
        self.repo, self.treeish, self.paths, self.budget = repo, treeish, paths, budget
        self.texts: dict[str, str] | None = None
        self.missed: Unread | None = None

    def __call__(self, path: str) -> list[str]:
        if self.missed is not None:
            raise self.missed
        if self.texts is None:
            try:
                self.texts = _read_versions(self.repo, self.treeish, self.paths, self.budget)
            except Unread as missed:
                self.missed = missed
                raise
        return [self.texts[path]] if path in self.texts else []


class _ParentsWrote:
    """Answer whether a file a merge's parents changed since their merge base holds a piece of text,
    ignoring case and spacing, among the files a scope accepts. Takes the repo, the parents and the
    budget; lists what the parents changed once, reads each scope's files once, answers each text once
    per scope, and raises on every question about a scope whose files could not all be read."""

    def __init__(self, repo: str | Path, parent_shas: list[str], budget: ReadBudget):
        self.repo, self.parent_shas, self.budget = repo, parent_shas, budget
        self.changed: list[tuple[str, list[str] | None]] | None = None
        self.held: dict[str, str] = {}
        self.missed: dict[str, Unread] = {}
        self.answers: dict[tuple[str, str], bool] = {}

    def __call__(self, text: str, scope=None, key: str = "") -> bool:
        if key in self.missed:
            raise self.missed[key]
        wanted = _loosely(text)
        if (key, wanted) in self.answers:
            return self.answers[(key, wanted)]
        if len(self.answers) >= _SEARCHES_MAX:
            raise OverBudget("the texts a merge's parents wrote")
        if key not in self.held:
            try:
                self.held[key] = "\0".join(_loosely(held) for held in self._read(scope))
            except Unread as missed:
                self.missed[key] = missed
                raise
        self.answers[(key, wanted)] = bool(wanted) and wanted in self.held[key]
        return self.answers[(key, wanted)]

    def _read(self, scope) -> list[str]:
        if self.changed is None:
            self.changed = _changed_since_merge_base(self.repo, self.parent_shas)
        texts: list[str] = []
        for parent, paths in self.changed:
            if paths is None:
                paths = sorted(entries_at(self.repo, parent, None))
            chosen = [path for path in paths if scope is None or scope(path)]
            if len(texts) + len(chosen) > _PARENT_FILES_MAX:
                raise OverBudget(f"the files {parent[:12]} changed")
            texts += _read_versions(self.repo, parent, chosen, self.budget).values()
        return texts


def _loosely(text: str) -> str:
    """Fold a text's case and collapse its spacing, so a line re-wrapped or re-cased compares equal.
    Takes the text. Returns the folded text."""
    return _SPACING.sub(" ", text).strip().casefold()


def _changed_since_merge_base(repo: str | Path, parent_shas: list[str]) -> list[tuple[str, list[str] | None]]:
    """List the files each of a merge's parents changed since their merge base. Takes the repo and
    the parents. Returns each parent with its paths, or None for every file it stores when the parents
    share no merge base. Raises `Unread` when git could not list them."""
    res = own_view(repo, ["merge-base", "--octopus", *parent_shas])
    base = (res.stdout or "").strip().split("\n")[0] if res is not None and res.returncode == 0 else ""
    return [(parent, sorted(changed_paths(repo, base, parent, diff_filter="AM")) if base else None)
            for parent in parent_shas]


def _introduced(repo: str | Path, base_tree: str, merge_sha: str, path: str,
                parent_shas: list[str]) -> list[tuple[str, str]]:
    """List the text a merge added to a path against each baseline that stores it: the clean
    merge's tree, and the first parent when that differs. Takes the repo, the tree, the merge, the
    path and the parents. Returns `(baseline, added text)` pairs whose text is not blank. Raises
    `Unread` when git could not compare them."""
    first_parent = parent_shas[0]
    baselines = [base_tree] if first_parent == base_tree else [base_tree, first_parent]
    pairs = [(b, introduced_added_text(repo, b, merge_sha, path)) for b in baselines
             if stores_path(repo, b, path)]
    return [(b, d) for b, d in pairs if d.strip()]
