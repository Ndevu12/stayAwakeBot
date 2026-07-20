#!/usr/bin/env python3
"""Local branch mutations — deleting the auto-generated fix branch (`saw discard --branch`)."""
from __future__ import annotations

from pathlib import Path

from stayawake.lib.git.run import run_ok


def delete_branch(repo: str | Path, name: str) -> bool:
    """Force-delete local branch `name` (`git branch -D`). Only ever called on the
    auto-generated fix branch — never a real branch."""
    return run_ok(repo, ["branch", "-D", name])
