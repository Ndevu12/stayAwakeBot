#!/usr/bin/env python3
"""The one place a `git` subprocess is executed — env, a 60s timeout, and tolerant
decoding, defined exactly once. Read helpers (`query`, `merge`) and write helpers
(`write`) all build on this, so the subprocess contract and its robustness never drift."""
from __future__ import annotations

import subprocess
from pathlib import Path

# Local git ops (reads, commit, stage, worktree) touch only disk — 60s catches a hung git.
# Network ops (push, fetch, ls-remote) legitimately take longer on a slow link, so they pass
# the larger bound: generous enough not to abandon a real transfer, still finite so a dead
# connection can't hang the sweep forever (the old per-call subprocess had NO timeout at all).
LOCAL_TIMEOUT = 60
NETWORK_TIMEOUT = 180


def _argv(repo: str | Path | None, args: list[str]) -> list[str]:
    """Build the git argv. `repo=None` runs git with NO `-C` — for operations that act on an
    explicit remote URL (e.g. `ls-remote <url>` / `push <url> --delete`) and need no local
    working tree. Every other caller pins the command to a repo with `-C`."""
    return ["git", *args] if repo is None else ["git", "-C", str(repo), *args]


def run(repo: str | Path | None, args: list[str], *, env: dict | None = None,
        timeout: int = LOCAL_TIMEOUT) -> subprocess.CompletedProcess | None:
    """Run a git command in `repo`; return the CompletedProcess (None if git can't run at all).
    `repo=None` omits `-C` for URL-scoped remote commands that need no local repo. `timeout`
    defaults to the local bound; network helpers pass `NETWORK_TIMEOUT`.

    Exposes the return code and stdout even on non-zero exit — needed for `merge-tree`, which
    exits 1 (not 0) on a conflicting auto-merge yet still prints the resulting tree OID.
    `errors="replace"` decodes tolerantly (history can hold non-UTF-8 blobs; `cat-file -p`
    would otherwise raise UnicodeDecodeError mid-read and abort the caller — and the whole
    remediation sweep), and the timeout bounds a hung git.
    """
    try:
        return subprocess.run(
            _argv(repo, args),
            capture_output=True,
            text=True,
            errors="replace",
            timeout=timeout,
            check=False,
            env=env,
        )
    except (subprocess.SubprocessError, OSError):
        return None


def run_ok(repo: str | Path | None, args: list[str], *, env: dict | None = None,
           timeout: int = LOCAL_TIMEOUT) -> bool:
    """True iff the git command ran and exited 0 — the *checked* form. Write helpers use this
    so a failure can never be silently swallowed."""
    res = run(repo, args, env=env, timeout=timeout)
    return res is not None and res.returncode == 0


def stdout(repo: str | Path, args: list[str]) -> str:
    """Run a git command; return its stdout ('' on any failure) — for read helpers that
    deliberately degrade to empty rather than raise."""
    res = run(repo, args)
    return res.stdout if (res is not None and res.returncode == 0) else ""
