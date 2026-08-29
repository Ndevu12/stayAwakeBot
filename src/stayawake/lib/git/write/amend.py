#!/usr/bin/env python3
"""Replace a named merge commit with the clean 3-way merge of its parents, then replay
the bounded suffix. Capture the previous identifiers before any ref moves."""
from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path

from stayawake.lib.git.merge.tree import auto_merge
from stayawake.lib.git.query import parents, commit_meta, is_ancestor
from stayawake.lib.git.run import run, run_ok, stdout
from stayawake.lib.git.write.commit import BOT_AUTHOR
from stayawake.lib.git.write.worktree import add_worktree, remove_worktree


_MSG = "security: replace merge that introduced the payload\n"


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


def capture_bundle(repo: str | Path, merge_sha: str, head: str, related: tuple[str, ...]) -> Path:
    """Write the identifiers that will stop being the tip, before the ref moves."""
    root = Path(repo) / ".git" / "saw-amend" / merge_sha[:12]
    root.mkdir(parents=True, exist_ok=True)
    blobs = {}
    for path in related:
        oid = stdout(repo, ["rev-parse", f"{merge_sha}:{path}"]).strip()
        if oid:
            blobs[path] = oid
    payload = {
        "merge": merge_sha,
        "head": head,
        "blobs": blobs,
        "meta": commit_meta(repo, merge_sha),
    }
    (root / "capture.json").write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    return root


def point_branch_at(repo: str | Path, branch: str, new: str, old: str) -> bool:
    """Compare-and-swap `refs/heads/branch` from `old` to `new`, then make the worktree match."""
    if not run_ok(repo, ["update-ref", f"refs/heads/{branch}", new, old]):
        return False
    return run_ok(repo, ["reset", "--hard", "--quiet", "HEAD"])


def replay_suffix(repo: str | Path, branch: str, old_merge: str, new_merge: str,
                  old_head: str) -> str | None:
    """Replay commits after `old_merge` onto `new_merge`. Returns the new HEAD, or None on failure.

    The original ref is not moved until the replay finishes. A failed replay leaves the
    repository as it stood.
    """
    desc = descendant_shas(repo, old_merge, old_head)
    if not desc:
        return new_merge if point_branch_at(repo, branch, new_merge, old_head) else None
    wt = Path(tempfile.mkdtemp(prefix="sab-amend-"))
    wt.rmdir()
    label = f"saw-amend/{new_merge[:8]}"
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
        if not new_head:
            return None
        if not run_ok(repo, ["update-ref", f"refs/heads/{branch}", new_head, old_head]):
            return None
        if not run_ok(repo, ["reset", "--hard", "--quiet", "HEAD"]):
            return None
        return new_head
    finally:
        remove_worktree(repo, wt)
        run_ok(repo, ["branch", "-D", label])
        try:
            wt.rmdir()
        except OSError:
            pass


def merge_is_on_head(repo: str | Path, merge_sha: str, head: str = "HEAD") -> bool:
    full = stdout(repo, ["rev-parse", merge_sha]).strip()
    tip = stdout(repo, ["rev-parse", head]).strip()
    if not full or not tip:
        return False
    return full == tip or is_ancestor(repo, full, tip)
