#!/usr/bin/env python3
"""Replace a named commit that still carries the payload, then replay the bounded suffix
on every branch that reached it. Capture the previous identifiers before any ref moves."""
from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path

from stayawake.lib.git.merge.tree import auto_merge
from stayawake.lib.git.query import parents, commit_meta, is_ancestor, branches_carrying
from stayawake.lib.git.run import run, run_ok, stdout
from stayawake.lib.git.write.commit import BOT_AUTHOR
from stayawake.lib.git.write.worktree import add_worktree, remove_worktree


_MSG = "security: remove payload that propagated into this commit\n"
_ZERO = "0" * 40


def branch_name(repo: str | Path) -> str | None:
    name = stdout(repo, ["symbolic-ref", "--short", "HEAD"]).strip()
    return name or None


def is_dirty(repo: str | Path) -> bool:
    return bool(stdout(repo, ["status", "--porcelain"]).strip())


def descendant_shas(repo: str | Path, merge: str, head: str = "HEAD") -> list[str]:
    """Commits after `merge` on the way to `head`, oldest first. Empty when `merge` is `head`."""
    out = stdout(repo, ["rev-list", "--reverse", "--ancestry-path", f"{merge}..{head}"])
    return [ln.strip() for ln in out.splitlines() if ln.strip()]


def reconstruct_merge(repo: str | Path, merge_sha: str) -> str | None:
    """A new merge commit whose tree is the clean 3-way merge of `merge_sha`'s parents.

    None when the merge is not two-parent, when there is no clean auto-merge, or when that
    auto-merge conflicted — those are not guessed at.
    """
    ps = parents(repo, merge_sha)
    if len(ps) != 2:
        return None
    merged = auto_merge(repo, ps[0], ps[1])
    if merged is None or merged.conflicted:
        return None
    res = run(repo, [*BOT_AUTHOR, "-c", "commit.gpgsign=false",
                     "commit-tree", merged.tree, "-p", ps[0], "-p", ps[1], "-m", _MSG])
    if res is None or res.returncode != 0:
        return None
    sha = (res.stdout or "").strip()
    return sha or None


def capture_bundle(repo: str | Path, merge_sha: str, related: tuple[str, ...],
                   branches: dict[str, str]) -> Path:
    """Write the identifiers that will stop being the tip, before any ref moves."""
    root = Path(repo) / ".git" / "saw-amend" / merge_sha[:12]
    root.mkdir(parents=True, exist_ok=True)
    blobs = {}
    for path in related:
        oid = stdout(repo, ["rev-parse", f"{merge_sha}:{path}"]).strip()
        if oid:
            blobs[path] = oid
    payload = {
        "commit": merge_sha,
        "branches": branches,
        "blobs": blobs,
        "meta": commit_meta(repo, merge_sha),
    }
    (root / "capture.json").write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    return root


def point_branch_at(repo: str | Path, branch: str, new: str, old: str) -> bool:
    """Compare-and-swap `refs/heads/branch` from `old` to `new`.

    The worktree is reset only when that branch is the one currently checked out.
    """
    if not run_ok(repo, ["update-ref", f"refs/heads/{branch}", new, old]):
        return False
    if branch_name(repo) == branch:
        return run_ok(repo, ["reset", "--hard", "--quiet", "HEAD"])
    return True


def replayed_head(repo: str | Path, old_merge: str, new_merge: str,
                  old_head: str) -> str | None:
    """The SHA after replaying `old_head`'s suffix onto `new_merge`. No ref is moved."""
    desc = descendant_shas(repo, old_merge, old_head)
    if not desc:
        return new_merge
    wt = Path(tempfile.mkdtemp(prefix="sab-amend-"))
    wt.rmdir()
    label = f"saw-amend/{os.urandom(4).hex()}"
    if not add_worktree(repo, wt, label, old_head):
        return None
    try:
        if not run_ok(wt, ["-c", "commit.gpgsign=false", "rebase", "--rebase-merges",
                           "--onto", new_merge, old_merge],
                      env=dict(os.environ, GIT_EDITOR="true", GIT_SEQUENCE_EDITOR="true",
                               GIT_TERMINAL_PROMPT="0")):
            run_ok(wt, ["rebase", "--abort"])
            return None
        new_head = stdout(wt, ["rev-parse", "HEAD"]).strip()
        return new_head or None
    finally:
        remove_worktree(repo, wt)
        run_ok(repo, ["branch", "-D", label])
        try:
            wt.rmdir()
        except OSError:
            pass


def apply_replacement(repo: str | Path, old_commit: str, new_commit: str,
                      heads: list[tuple[str, str, str]]) -> dict[str, str] | None:
    """Repoint every `(name, replay_tip, cas_old)` onto `new_commit`. None if any replay fails
    before refs move. A failed compare-and-swap stops the rest."""
    by_tip: dict[str, list[tuple[str, str]]] = {}
    for name, tip, cas_old in heads:
        by_tip.setdefault(tip, []).append((name, cas_old))
    planned: dict[str, tuple[str, str]] = {}
    for tip, named in by_tip.items():
        new_tip = replayed_head(repo, old_commit, new_commit, tip)
        if new_tip is None:
            return None
        for name, cas_old in named:
            planned[name] = (cas_old, new_tip)
    moved: dict[str, str] = {}
    for name, (cas_old, new_tip) in planned.items():
        if not point_branch_at(repo, name, new_tip, cas_old):
            return None
        moved[name] = new_tip
    return moved


def replay_suffix(repo: str | Path, branch: str, old_merge: str, new_merge: str,
                  old_head: str) -> str | None:
    """Replay commits after `old_merge` onto `new_merge` and move `branch`. Returns the new
    tip, or None on failure."""
    cas_old = stdout(repo, ["rev-parse", f"refs/heads/{branch}"]).strip() or _ZERO
    moved = apply_replacement(repo, old_merge, new_merge, [(branch, old_head, cas_old)])
    return moved.get(branch) if moved else None


def merge_is_on_head(repo: str | Path, merge_sha: str, head: str = "HEAD") -> bool:
    full = stdout(repo, ["rev-parse", merge_sha]).strip()
    tip = stdout(repo, ["rev-parse", head]).strip()
    if not full or not tip:
        return False
    return full == tip or is_ancestor(repo, full, tip)


def carrying_branches(repo: str | Path, sha: str) -> list[tuple[str, str, str]]:
    """Local and origin branches that still reach `sha`."""
    return branches_carrying(repo, sha)
