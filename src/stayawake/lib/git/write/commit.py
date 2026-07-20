#!/usr/bin/env python3
"""Commit the remediation — as the security bot, and NEVER silently losing the fix when the
repo enforces signed commits but signing can't complete in a non-interactive subprocess."""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from stayawake.lib.git.run import run

# Author the fix as the bot (not the operator running `saw`) via `-c`, so the commit's identity
# is stable and doesn't depend on the ambient git config of whoever runs the sweep.
BOT_AUTHOR = ("-c", "user.name=StayAwakeBot Security",
              "-c", "user.email=security-bot@stayawake.local")


@dataclass(frozen=True)
class CommitResult:
    """Outcome of `commit_fix`. `committed` is the only truth about whether the branch actually
    advanced — the caller must never report a prepared fix when it is False. `signed` is False
    only when we had to force signing OFF to land the commit (so the caller can warn that a
    signed-commits ruleset may reject the push until the branch is re-signed)."""
    committed: bool
    signed: bool


def commit_fix(repo: str | Path, message: str) -> CommitResult:
    """Commit the staged fix as the security bot, returning what actually happened.

    The commit inherits the repo's config, including `commit.gpgsign=true`. In a throwaway
    worktree subprocess, SSH/GPG signing frequently CAN'T complete (no agent, no passphrase
    prompt, a key that isn't present) and `git commit` exits non-zero. The historical bug: the
    return code went unchecked, so the failure was swallowed and the caller reported a
    "prepared" fix on a branch that had **zero commits** — a phantom success.

    So: check the first (normally-signed) attempt; if it fails, retry ONCE with
    `-c commit.gpgsign=false` so a commit blocked *by signing* still lands, and report it
    unsigned. The retry disables ONLY signing — it does NOT add `--no-verify`, so a genuinely
    rejecting `pre-commit` hook (or an empty tree) fails both attempts and we return
    `committed=False`; the caller then reports an honest failure instead of an empty branch.
    We never silently bypass a repo's commit hooks.
    """
    res = run(repo, [*BOT_AUTHOR, "commit", "-m", message])
    if res is not None and res.returncode == 0:
        return CommitResult(committed=True, signed=True)
    # Retry with signing forced off — rescues the signing-failure case (an unavailable key in the
    # non-interactive worktree). A hook rejection / empty tree still fails here → honest failure.
    res = run(repo, [*BOT_AUTHOR, "-c", "commit.gpgsign=false", "commit", "-m", message])
    if res is not None and res.returncode == 0:
        return CommitResult(committed=True, signed=False)
    return CommitResult(committed=False, signed=False)
