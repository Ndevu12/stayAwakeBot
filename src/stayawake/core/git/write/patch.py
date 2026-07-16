#!/usr/bin/env python3
"""Capture the fix commit as a git-am-able patch — the no-write floor of the remediation
ladder, so a read-only run never loses the work when the branch can't be pushed."""
from __future__ import annotations

from pathlib import Path

from stayawake.core.git.run import run


def format_patch(repo: str | Path, ref: str = "HEAD") -> str | None:
    """The single commit `ref` as a `git am`-able patch (text), or None if there is no such
    commit / git failed / the patch is empty. Read-only itself, but part of the write ladder:
    its output is what the caller persists to disk when a push isn't possible."""
    res = run(repo, ["format-patch", "-1", ref, "--stdout"])
    if res is None or res.returncode != 0 or not res.stdout.strip():
        return None
    return res.stdout
