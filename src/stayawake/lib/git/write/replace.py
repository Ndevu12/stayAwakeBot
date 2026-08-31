#!/usr/bin/env python3
"""The tree a commit should have recorded: its own tree, corrected only where the payload is.

Rebuilding a commit from its parents destroys everything else it contributed — a conflict
resolution, a fixup made during the merge, a file it deleted — and the caller is then left
refusing rather than losing them. MEASURED: the two shapes that actually occur (a merge that
resolved a conflict AND smuggled the payload; a merge that made a legitimate edit AND smuggled
the payload) were both refused, and the first is the shape an attacker would choose.

The recorded tree is right about every path the finding did not name. Only the named ones are
wrong. Correcting those is the smaller change and the more accurate one.
"""
from __future__ import annotations

import os
import shutil
import tempfile
from dataclasses import dataclass
from pathlib import Path

from stayawake.lib.git.merge.tree import auto_merge
from stayawake.lib.git.query import file_at, parents, path_exists_at, tree_entry
from stayawake.lib.git.run import run, run_ok

_GITLINK = "160000"


@dataclass(frozen=True)
class Replacement:
    """A corrected tree, or the reason there is none.

    `kind` is what the caller maps to an operator-facing cause; `refusal` is the detail. Both are
    empty exactly when `tree` is set, so a caller that checks `ok` cannot act on a refusal.
    """

    tree: str = ""
    sha: str = ""
    """The replacement commit, once one has been written. `replacement_tree` leaves it empty."""
    reverted: tuple[str, ...] = ()
    removed: tuple[str, ...] = ()
    kind: str = ""
    refusal: str = ""

    @property
    def ok(self) -> bool:
        return bool(self.tree) and not self.kind


def _refused(kind: str, refusal: str) -> Replacement:
    return Replacement(kind=kind, refusal=refusal)


def _baseline(repo: str | Path, ps: list[str]) -> tuple[str | None, frozenset[str]]:
    """The tree this commit should have had, and the paths git could not decide on its own.

    Two parents: the clean 3-way auto-merge. One parent: that parent. Anything else — a root
    commit, an octopus merge — has no baseline git can produce, and None says so rather than
    nominating one parent as the truth.
    """
    if len(ps) == 2:
        merged = auto_merge(repo, ps[0], ps[1])
        return (merged.tree, merged.conflicted) if merged else (None, frozenset())
    if len(ps) == 1:
        return ps[0], frozenset()
    return None, frozenset()


def replacement_tree(repo: str | Path, commit: str, flagged_paths,
                     still_carries=None) -> Replacement:
    """`commit`'s recorded tree with each flagged path put back to what it should have been.

    A flagged path that exists in the baseline is reverted to it; one that does not was
    introduced by this commit and is removed. Refuses rather than guessing when git could not
    merge that path on its own, when the path is a submodule, or when the commit's shape offers
    no baseline and the path came from a parent.

    `still_carries(text) -> reason | None` is the caller's judge of whether restored content is
    actually clean — injected, so this layer never depends on the security domain. Without it the
    baseline is merely NOMINATED as clean: when the payload was already in a parent and this
    commit added more of it, reverting restores a version that still carries it.
    """
    flagged = sorted({p for p in flagged_paths if p})
    if not flagged:
        return _refused("unnamed", "no path was named to replace")

    ps = parents(repo, commit)
    baseline, conflicted = _baseline(repo, ps)
    plan: list[tuple[str, tuple[str, str] | None]] = []
    for path in flagged:
        if path in conflicted:
            return _refused("conflicted",
                            f"git could not merge {path} on its own, so there is no clean "
                            "version of it to restore")
        recorded = tree_entry(repo, commit, path)
        if recorded is not None and recorded[0] == _GITLINK:
            return _refused("submodule", f"{path} is a submodule")
        clean = tree_entry(repo, baseline, path) if baseline else None
        if clean is not None:
            if clean[0] == _GITLINK:
                return _refused("submodule", f"{path} is a submodule in the clean version")
            carried = still_carries(file_at(repo, baseline, path)) if still_carries else None
            if carried:
                return _refused("baseline-carries-payload",
                                f"the version of {path} this would restore still carries the "
                                f"payload ({carried}) — it was introduced earlier")
            plan.append((path, clean))
            continue
        if baseline is None and any(path_exists_at(repo, p, path) for p in ps):
            return _refused("shape",
                            f"{path} came from a parent and this commit's shape has no clean "
                            "version to restore")
        plan.append((path, None))

    tree = _write_corrected(repo, commit, plan)
    if tree is None:
        return _refused("write", "the corrected tree could not be written")
    untouched = _not_applied(repo, tree, plan)
    if untouched:
        return _refused("not-applied",
                        "the correction did not take effect at " + ", ".join(untouched))
    return Replacement(tree=tree,
                       reverted=tuple(p for p, entry in plan if entry is not None),
                       removed=tuple(p for p, entry in plan if entry is None))


def _not_applied(repo: str | Path, tree: str,
                 plan: list[tuple[str, tuple[str, str] | None]]) -> list[str]:
    """The planned paths the written tree does not actually reflect.

    A git command exiting 0 is not evidence that it changed anything: `update-index
    --force-remove` on a path that is not in the index exits 0 and removes nothing, so a path
    spelled in any way git does not match — a quoted name, a directory rather than a file —
    produced a tree identical to the recorded one and was reported as removed. The result is
    read back instead of the exit status being believed.
    """
    missed = []
    for path, entry in plan:
        written = tree_entry(repo, tree, path)
        if entry is None:
            if written is not None:
                missed.append(path)
        elif written != entry:
            missed.append(path)
    return missed


def _write_corrected(repo: str | Path, commit: str,
                     plan: list[tuple[str, tuple[str, str] | None]]) -> str | None:
    """Write the corrected tree through a throwaway index, so the repository's own index — and
    therefore anything uncommitted in a worktree — is never touched."""
    scratch = Path(tempfile.mkdtemp(prefix="saw-replace-"))
    env = dict(os.environ, GIT_INDEX_FILE=str(scratch / "index"))
    try:
        if not run_ok(repo, ["read-tree", commit], env=env):
            return None
        for path, entry in plan:
            if entry is None:
                ok = run_ok(repo, ["update-index", "--force-remove", "--", path], env=env)
            else:
                mode, oid = entry
                # The three-argument form: a path containing a comma breaks `<mode>,<oid>,<path>`.
                ok = run_ok(repo, ["update-index", "--add", "--cacheinfo", mode, oid, path],
                            env=env)
            if not ok:
                return None
        res = run(repo, ["write-tree"], env=env)
        if res is None or res.returncode != 0:
            return None
        oid = (res.stdout or "").strip()
        return oid or None
    finally:
        shutil.rmtree(scratch, ignore_errors=True)
