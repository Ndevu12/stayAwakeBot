#!/usr/bin/env python3
"""Give a signing git command its `-c` settings, its signing flag and its environment."""
from __future__ import annotations

import os
from collections.abc import Mapping
from pathlib import Path

from stayawake.lib.signing.commits.config import config_value, resolved_signing_config
from stayawake.lib.signing.commits.decision import SigningStatus
from stayawake.lib.signing.commits.probe import refuse_to_prompt


# MEASURED on git 2.39.2: `commit-tree` ignores `commit.gpgsign` entirely — a `-c` override alone
# leaves the replacement commit UNSIGNED. `rebase` honours the config, but the explicit flag is
# what makes the outcome independent of where the config was read from. Per command: (on, off).
_SIGN_FLAGS: dict[str, tuple[tuple[str, ...], tuple[str, ...]]] = {
    "commit-tree": (("-S",), ()),
    "commit": (("-S",), ("--no-gpg-sign",)),
    "rebase": (("--gpg-sign",), ("--no-gpg-sign",)),
    "cherry-pick": (("-S",), ("--no-gpg-sign",)),
}


_COMMITTER_VARS = ("GIT_COMMITTER_NAME", "GIT_COMMITTER_EMAIL", "GIT_COMMITTER_DATE")


def signing_env(repo: str | Path, base: Mapping[str, str] | None = None,
                committer: tuple[str, str] | None = None) -> dict:
    """The environment for the rewriting command: the committer is the OPERATOR.

    Taken from `committer` when given, else from the repository's own `user.name`/`user.email`,
    overriding whatever `GIT_COMMITTER_*` the ambient environment carries — a git hook and an
    in-progress rebase both export those, which would attribute the rewrite to the commit being
    replayed. `GIT_AUTHOR_*` is deliberately left untouched: preserving the original author is the
    caller's job.
    """
    env = dict(os.environ if base is None else base)
    for var in _COMMITTER_VARS:
        env.pop(var, None)
    if committer is not None:
        operator_name, operator_email = committer
    else:
        operator_name = config_value(repo, "user.name")
        operator_email = config_value(repo, "user.email")
    if operator_name:
        env["GIT_COMMITTER_NAME"] = operator_name
    if operator_email:
        env["GIT_COMMITTER_EMAIL"] = operator_email
    return refuse_to_prompt(env)


def signing_args(status: SigningStatus) -> tuple[str, ...]:
    """The `-c` overrides to place before the subcommand, pinning the decision AND the key so an
    ambient, included or per-worktree config cannot flip either. Not sufficient on its own — see
    `sign_flags`."""
    args = ["-c", f"commit.gpgsign={'true' if status.available else 'false'}"]
    if status.available:
        for key, value in status.config:
            if key not in ("commit.gpgsign", "user.name", "user.email"):
                args += ["-c", f"{key}={value}"]
    return tuple(args)


def sign_flags(status: SigningStatus, command: str) -> tuple[str, ...]:
    """The signing flag `command` itself needs, which is what actually decides the outcome for
    `commit-tree` (it reads no signing config at all). A command with no entry raises rather than
    returning nothing: defaulting to no flag is exactly the silent unsigned rewrite this module
    exists to prevent."""
    if command not in _SIGN_FLAGS:
        raise ValueError(f"no signing flag is known for `git {command}`; add it to _SIGN_FLAGS "
                         f"rather than letting the rewrite fall through to unsigned")
    signed, unsigned = _SIGN_FLAGS[command]
    return signed if status.available else unsigned


def fix_commit_signing(repo: str | Path) -> tuple[str, ...]:
    """The `-c` settings a commit saw makes on behalf of `repo` signs with: whether `repo` asks
    for a signature, and the signer the operator configured. Nothing is probed; the commit itself
    is the attempt."""
    config = resolved_signing_config(repo)
    args = ["-c", f"commit.gpgsign={config.get('commit.gpgsign') or 'false'}"]
    for key, value in sorted(config.items()):
        if key not in ("commit.gpgsign", "user.name", "user.email"):
            args += ["-c", f"{key}={value}"]
    return tuple(args)
