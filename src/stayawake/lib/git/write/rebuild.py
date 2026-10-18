#!/usr/bin/env python3
"""Rebuild a bounded stretch of history with every infected commit replaced at once.

The stretch runs from the oldest confirmed commit to the branch tips. Each commit keeps its own
recorded tree with the correction carried forward into it.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from stayawake.lib.git.objects import own_view
from stayawake.lib.git.query import entry_at
from stayawake.lib.git.write.replace import Replacement, carried_forward, merge_baseline

_BLOCKED = {
    "changed-downstream": "{sha} changed {path} and it still carries the payload — that commit needs "
                          "its own finding",
    "unreadable": "{sha}: {path} could not be read",
    "conflicted": "{sha} merges versions of {path} that git cannot combine on its own",
    "baseline-carries-payload": "{path} already carries the payload before {sha}",
    "shape": "{sha} has no earlier version of {path} to put back",
}


@dataclass(frozen=True)
class Rebuild:
    """What the rebuild produced.

    `mapping` is old sha -> new sha for every commit rebuilt clean; a commit absent from it was
    untouched or blocked. `blocked` maps each commit that could not be remediated — one whose own
    correction failed, and every descendant of it — to its `(kind, refusal)`.
    """

    mapping: dict[str, str] = field(default_factory=dict)
    blocked: dict[str, tuple[str, str]] = field(default_factory=dict)
    replaced: tuple[str, ...] = ()
    carried: tuple[str, ...] = ()

    def tip(self, old_tip: str) -> str:
        return self.mapping.get(old_tip, old_tip)


def _own_output(repo: str | Path, args: list[str]) -> str | None:
    """What git prints for `args`, read as the repository stores its objects, or None on failure."""
    res = own_view(repo, args)
    return res.stdout or "" if res is not None and res.returncode == 0 else None


def ordered_graph(repo: str | Path, tips: list[str]) -> list[tuple[str, list[str]]] | None:
    """`(sha, parents)` for everything reachable from `tips`, parents before children.

    The whole graph, not a range from the oldest infected commit. Excluding the parents of each
    infected commit looked like the bounded form and was wrong: excluding a LATER one's parents
    removes the earlier ones with them, so most of the history was skipped and the payloads in it
    survived — measured. The caller skips what neither carries a payload nor follows one, which
    is the same bound reached without a range expression that can silently drop commits.

    `--topo-order` rather than date order: a rewrite must see a parent before the child naming
    it, and commit dates do not order a graph. `--parents` makes it one subprocess for the graph.
    Returns None when git could not walk it.
    """
    if not tips:
        return []
    out = _own_output(repo, ["rev-list", "--reverse", "--topo-order", "--parents", *tips])
    if out is None:
        return None
    graph = []
    for line in out.splitlines():
        shas = line.split()
        if shas:
            graph.append((shas[0], shas[1:]))
    return graph


def commits_to_rebuild(graph: list[tuple[str, list[str]]],
                       infected: set[str]) -> list[tuple[str, list[str]]]:
    """The commits that must be written anew: an infected one, or one whose parent moved.

    This is the bound. Everything before the earliest infected commit keeps its identity, so a
    repository is rewritten from the oldest payload forward and no further — the same stretch a
    single replacement of that commit would already have re-identified.
    """
    moving: set[str] = set()
    plan = []
    for sha, ps in graph:
        if sha in infected or any(p in moving for p in ps):
            moving.add(sha)
            plan.append((sha, ps))
    return plan


def _removals_at(repo: str | Path, sha: str, remove, remove_in) -> dict[str, str]:
    """Collect the blobs to drop at one commit. Takes the repo, the commit and both removal maps.
    Returns each path mapped to its blob."""
    wanted: dict[str, set[str]] = {path: {oid} for path, oid in (remove or {}).items()}
    for (path, oid), commits in (remove_in or {}).items():
        if sha in commits:
            wanted.setdefault(path, set()).add(oid)
    out: dict[str, str] = {}
    for path, oids in wanted.items():
        if len(oids) > 1:
            answered, entry = entry_at(repo, sha, path)
            held = entry[1] if answered and entry is not None else None
            out[path] = held if held in oids else min(oids)
        else:
            out[path] = next(iter(oids))
    return out


def _inherited(corrections_of: dict, parents: list[str]) -> dict[str, dict]:
    """Merge the corrections a commit's parents carry. Takes every rebuilt commit's corrections and
    the commit's parents. Returns them by path and payload blob."""
    merged: dict[str, dict] = {}
    conflicted: set[tuple[str, str]] = set()
    for parent in parents:
        for path, versions in corrections_of.get(parent, {}).items():
            into = merged.setdefault(path, {})
            for blob, entry in versions.items():
                if (path, blob) in conflicted:
                    continue
                if blob in into and into[blob] != entry:
                    conflicted.add((path, blob))
                    del into[blob]
                    continue
                into[blob] = entry
    return merged


def _introduced(repo: str | Path, sha: str, parents: list[str], proven: dict[str, set[str]],
                corrections: dict[str, dict],
                mapping: dict[str, str]) -> tuple[list, tuple[str, str] | None]:
    """Find the proven payload versions a commit brings in on its own line, each with the version its
    rewritten parents give it. Takes the repo, the commit, its parents, the proven versions, the
    corrections it inherits and the rewrite so far. Returns `(path, blob, entry)` for each, and the
    `(kind, path)` that blocks the commit, or None."""
    found = []
    baseline = None
    for path in sorted(proven):
        answered, current = entry_at(repo, sha, path)
        if not answered:
            return [], ("unreadable", path)
        if current is None or current[1] not in proven[path] or current[1] in corrections.get(path, {}):
            continue
        if baseline is None:
            baseline = merge_baseline(repo, [mapping.get(parent, parent) for parent in parents])
        tree, conflicted = baseline
        if tree is None:
            return [], ("shape", path)
        if path in conflicted:
            return [], ("conflicted", path)
        answered, entry = entry_at(repo, tree, path)
        if not answered:
            return [], ("unreadable", path)
        if entry is not None and entry[1] in proven[path]:
            return [], ("baseline-carries-payload", path)
        found.append((path, current[1], entry))
    return found, None


def rebuild_without_payload(repo: str | Path, graph: list[tuple[str, list[str]]],
                            replacements: dict[str, Replacement],
                            write_commit, still_carries=None, clean=None, remove=None,
                            pre_blocked: dict[str, tuple[str, str]] | None = None,
                            substitute=None, purge=None, remove_in=None,
                            proven: dict[str, set[str]] | None = None) -> Rebuild:
    """Rebuild the commits in `graph` with the payload taken out of each infected commit and every
    commit after it. Takes the repo, the commits parents-first, each infected commit's replacement,
    `write_commit(commit, tree, new_parents) -> (sha, kind, refusal)`, the check `still_carries`, the
    removal steps `clean` (path to `(carries, corrector)`), `remove` (path to blob), `remove_in`
    (`(path, blob)` to commits), `substitute` (path to `(payload_blob, entry)`) and `purge` (paths),
    `pre_blocked`, the commits already known unrepairable, and `proven`, each path mapped to the
    payload blobs saw confirmed. Returns the rebuild, with each commit that could not be rebuilt in
    `blocked`."""
    mapping: dict[str, str] = {}
    proven = proven or {}
    corrections_of: dict[str, dict[str, dict]] = {}
    blocked: dict[str, tuple[str, str]] = dict(pre_blocked or {})
    replaced: list[str] = []
    carried: list[str] = []

    for sha, ps in graph:
        inherited = next((blocked[p] for p in ps if p in blocked), None)
        if sha in blocked or inherited is not None:
            blocked.setdefault(sha, inherited or blocked[sha])
            continue

        corrections = _inherited(corrections_of, ps)
        replacement = replacements.get(sha)
        if replacement is not None:
            if not replacement.ok:
                blocked[sha] = (replacement.kind or "replacement", replacement.refusal)
                continue
            unread = None
            for path, entry in replacement.plan:
                answered, current = entry_at(repo, sha, path)
                if not answered:
                    unread = path
                    break
                if current is not None:
                    corrections.setdefault(path, {})[current[1]] = entry
            if unread is not None:
                blocked[sha] = ("unreadable", _BLOCKED["unreadable"].format(sha=sha[:12], path=unread))
                continue
        else:
            introduced, stuck = _introduced(repo, sha, ps, proven, corrections, mapping)
            if stuck is not None:
                kind, path = stuck
                blocked[sha] = (kind, _BLOCKED[kind].format(sha=sha[:12], path=path))
                continue
            for path, blob, entry in introduced:
                corrections.setdefault(path, {})[blob] = entry
        corrections_of[sha] = corrections

        tree = None
        removing = _removals_at(repo, sha, remove, remove_in)
        if corrections or clean or removing or substitute or purge:
            tree, refusal = carried_forward(repo, sha, corrections, still_carries, clean,
                                            removing, substitute, purge)
            if refusal:
                kind, path = refusal
                blocked[sha] = (kind, _BLOCKED[kind].format(sha=sha[:12], path=path))
                continue
            if tree is None:
                blocked[sha] = ("not-applied",
                                f"{sha[:12]}: the correction could not be carried into this commit")
                continue
        if tree is None:
            tree = (_own_output(repo, ["rev-parse", f"{sha}^{{tree}}"]) or "").strip()
        if not tree:
            blocked[sha] = ("write", f"{sha[:12]}: its tree could not be read")
            continue

        new_sha, kind, refusal = write_commit(sha, tree, [mapping.get(p, p) for p in ps])
        if not new_sha:
            blocked[sha] = (kind or "write", f"{sha[:12]}: {refusal}")
            continue
        mapping[sha] = new_sha
        (replaced if replacement is not None else carried).append(sha)

    return Rebuild(mapping=mapping, blocked=blocked,
                   replaced=tuple(replaced), carried=tuple(carried))
