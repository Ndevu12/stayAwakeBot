#!/usr/bin/env python3
"""Commit the remediation as the security bot, in the fix checkout saw made."""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from stayawake.lib.git.run import SAW_OWNED, run
from stayawake.lib.git.write.sign import fix_commit_signing
from stayawake.lib.git.write.worktree import held_checkout, land

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
    """Commit the staged fix in the fix checkout at `repo` as the security bot, then land it on the
    branch in the operator's repository. Signs when the operator's repository asks for
    signatures, with the signer the operator configured globally (`sign.fix_commit_signing`); a
    signed attempt that fails is retried once unsigned and reported unsigned. Returns what
    happened: `committed=False` when the commit fails or cannot be landed. No hook of the
    operator's repository runs."""
    checkout = held_checkout(repo)
    if checkout is None:
        return CommitResult(committed=False, signed=False)
    signing = fix_commit_signing(checkout.operator_repo)
    signed = True
    res = run(repo, [*BOT_AUTHOR, *signing, "commit", "-q", "-m", message], context=SAW_OWNED)
    if res is None or res.returncode != 0:
        signed = False
        res = run(repo, [*BOT_AUTHOR, *signing, "-c", "commit.gpgsign=false",
                         "commit", "-q", "-m", message], context=SAW_OWNED)
    if res is None or res.returncode != 0 or land(repo):
        return CommitResult(committed=False, signed=False)
    return CommitResult(committed=True, signed=signed)
