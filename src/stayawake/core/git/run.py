#!/usr/bin/env python3
"""The one place a `git` subprocess is executed — env, a 60s timeout, and tolerant
decoding, defined exactly once. Read helpers (`query`, `merge`) and write helpers
(`write`) all build on this, so the subprocess contract and its robustness never drift."""
from __future__ import annotations

import subprocess
from pathlib import Path


def run(repo: str | Path, args: list[str], *, env: dict | None = None
        ) -> subprocess.CompletedProcess | None:
    """Run a git command in `repo`; return the CompletedProcess (None if git can't run at all).

    Exposes the return code and stdout even on non-zero exit — needed for `merge-tree`, which
    exits 1 (not 0) on a conflicting auto-merge yet still prints the resulting tree OID.
    `errors="replace"` decodes tolerantly (history can hold non-UTF-8 blobs; `cat-file -p`
    would otherwise raise UnicodeDecodeError mid-read and abort the caller — and the whole
    remediation sweep), and `timeout=60` bounds a hung git.
    """
    try:
        return subprocess.run(
            ["git", "-C", str(repo), *args],
            capture_output=True,
            text=True,
            errors="replace",
            timeout=60,
            check=False,
            env=env,
        )
    except (subprocess.SubprocessError, OSError):
        return None


def run_ok(repo: str | Path, args: list[str], *, env: dict | None = None) -> bool:
    """True iff the git command ran and exited 0 — the *checked* form. Write helpers use this
    so a failure can never be silently swallowed."""
    res = run(repo, args, env=env)
    return res is not None and res.returncode == 0


def stdout(repo: str | Path, args: list[str]) -> str:
    """Run a git command; return its stdout ('' on any failure) — for read helpers that
    deliberately degrade to empty rather than raise."""
    res = run(repo, args)
    return res.stdout if (res is not None and res.returncode == 0) else ""
