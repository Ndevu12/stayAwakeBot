#!/usr/bin/env python3
"""Rebuild a bounded stretch of history with every infected commit replaced at once.

Replacing one commit while others still carry the payload is not a partial fix — the repository
is still infected and the run reports success. The set is what the scan confirmed; the stretch
rebuilt is everything from the OLDEST of them to the branch tips, which is the same stretch a
single replacement of that oldest commit would already have re-identified. Cleaning five commits
instead of one is therefore the same rewrite, not five times the blast radius.

MEASURED, and it decided the mechanism. A tree is a SNAPSHOT: rebuilding a commit with remapped
parents but its recorded tree leaves the payload at the branch tip, because every later commit
records it again. `rebase` gets that right only because it replays DIFFS — and pays for it by
re-merging every merge in the stretch, which silently re-resolves a conflict someone settled by
hand. So each commit keeps its own recorded tree and the correction is carried forward into it,
which removes the payload everywhere AND leaves every merge exactly as it was recorded.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from stayawake.lib.git.run import stdout
from stayawake.lib.git.write.replace import Replacement, carried_forward, tree_entry


@dataclass(frozen=True)
class Rebuild:
    """What the rebuild produced, or the reason there is none.

    `mapping` is old sha -> new sha for every commit that had to change. A commit absent from it
    was not touched and keeps its identity.
    """

    mapping: dict[str, str] = field(default_factory=dict)
    replaced: tuple[str, ...] = ()
    carried: tuple[str, ...] = ()
    kind: str = ""
    refusal: str = ""

    @property
    def ok(self) -> bool:
        return not self.kind

    def tip(self, old_tip: str) -> str:
        return self.mapping.get(old_tip, old_tip)


def _refused(kind: str, refusal: str) -> Rebuild:
    return Rebuild(kind=kind, refusal=refusal)


def ordered_graph(repo: str | Path, tips: list[str]) -> list[tuple[str, list[str]]]:
    """`(sha, parents)` for everything reachable from `tips`, parents before children.

    The whole graph, not a range from the oldest infected commit. Excluding the parents of each
    infected commit looked like the bounded form and was wrong: excluding a LATER one's parents
    removes the earlier ones with them, so most of the history was skipped and the payloads in it
    survived — measured. The caller skips what neither carries a payload nor follows one, which
    is the same bound reached without a range expression that can silently drop commits.

    `--topo-order` rather than date order: a rewrite must see a parent before the child naming
    it, and commit dates do not order a graph. `--parents` makes it one subprocess for the graph.
    """
    if not tips:
        return []
    out = stdout(repo, ["rev-list", "--reverse", "--topo-order", "--parents", *tips])
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


def rebuild_without_payload(repo: str | Path, graph: list[tuple[str, list[str]]],
                            replacements: dict[str, Replacement],
                            write_commit, still_carries=None) -> Rebuild:
    """Walk `order` parents-first, replacing each infected commit and carrying its correction
    into everything after it.

    `write_commit(commit, tree, new_parents) -> (sha, kind, refusal)` writes one commit; it is
    injected so this layer decides nothing about signing or identity.
    """
    mapping: dict[str, str] = {}
    corrections: dict[str, tuple[str, tuple[str, str] | None]] = {}
    replaced: list[str] = []
    carried: list[str] = []

    for sha, ps in graph:
        replacement = replacements.get(sha)
        if replacement is not None:
            if not replacement.ok:
                return _refused(replacement.kind or "replacement",
                                f"{sha[:12]}: {replacement.refusal}")
            for path, entry in replacement.plan:
                current = tree_entry(repo, sha, path)
                if current is None:
                    continue
                corrections[path] = (current[1], entry)

        tree, blocked = (carried_forward(repo, sha, corrections, still_carries)
                         if corrections else (None, ""))
        if blocked:
            return _refused("changed-downstream",
                            f"{sha[:12]} changed {blocked} and it still carries the payload — "
                            "that commit needs its own finding")
        if corrections and tree is None:
            return _refused("not-applied",
                            f"{sha[:12]}: the correction could not be carried into this commit")
        if tree is None:
            tree = stdout(repo, ["rev-parse", f"{sha}^{{tree}}"]).strip()
        if not tree:
            return _refused("write", f"{sha[:12]}: its tree could not be read")

        new_sha, kind, refusal = write_commit(sha, tree, [mapping.get(p, p) for p in ps])
        if not new_sha:
            return _refused(kind or "write", f"{sha[:12]}: {refusal}")
        mapping[sha] = new_sha
        (replaced if replacement is not None else carried).append(sha)

    return Rebuild(mapping=mapping, replaced=tuple(replaced), carried=tuple(carried))
