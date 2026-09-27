#!/usr/bin/env python3
"""Which of the operator's checkouts has a branch checked out, read from the files git keeps in the
repository."""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from stayawake.lib.git.run import UNTRUSTED, stdout


@dataclass(frozen=True)
class Checkout:
    """A working tree and the git directory holding its HEAD and index."""
    worktree: Path
    gitdir: Path


def _common_dir(repo: str | Path) -> Path | None:
    named = stdout(repo, ["rev-parse", "--git-common-dir"], context=UNTRUSTED).strip()
    if not named:
        return None
    path = Path(named)
    return (path if path.is_absolute() else Path(repo) / path).resolve()


def _read(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="replace").strip()
    except OSError:
        return ""


def _main_worktree(repo: str | Path, common: Path) -> Path | None:
    if stdout(repo, ["config", "--get", "--type=bool", "core.bare"],
              context=UNTRUSTED).strip() == "true":
        return None
    configured = stdout(repo, ["config", "--get", "core.worktree"], context=UNTRUSTED).strip()
    if configured:
        path = Path(configured)
        return (path if path.is_absolute() else common / path).resolve()
    return common.parent if common.name == ".git" else None


def checkouts(repo: str | Path) -> list[tuple[Checkout, str]]:
    """Every checkout of `repo` with what its HEAD file names (`ref: refs/heads/x` or an id).
    Raises OSError when `repo`'s git directory cannot be found."""
    common = _common_dir(repo)
    if common is None:
        raise OSError(f"{repo}: its git directory could not be found")
    found = []
    main = _main_worktree(repo, common)
    if main is not None:
        found.append((Checkout(main, common), _read(common / "HEAD")))
    linked = common / "worktrees"
    if linked.is_dir():
        for entry in sorted(linked.iterdir()):
            pointer = _read(entry / "gitdir")
            if not pointer:
                continue
            found.append((Checkout(Path(pointer).parent, entry), _read(entry / "HEAD")))
    return found


def checked_out_at(repo: str | Path, branch: str) -> Checkout | None:
    """The checkout that has `branch` checked out, or None when none does. Raises OSError when
    that cannot be established."""
    wanted = f"ref: refs/heads/{branch}"
    for checkout, head in checkouts(repo):
        if head == wanted:
            return checkout
    return None
