#!/usr/bin/env python3
"""Ask git which configuration files it reads for a repository, and which hooks directory that
configuration names. Read-only queries; saw's own command-line settings are told apart by scope."""
from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from stayawake.lib.git.run import stdout_bytes

REPOSITORY_SCOPES = (b"local", b"worktree")
_HOOKS_PATH = "core.hookspath"


@dataclass(frozen=True)
class RepositorySettings:
    """What git reports it reads for one repository view.

    `files` are the configuration files of the repository's own scopes, in the order git reads them;
    `hooks_paths` are the `core.hooksPath` values those scopes set, as git expands them, last one
    effective; `sets_hooks_path` is True when those scopes set one at all.
    """

    files: tuple[Path, ...]
    hooks_paths: tuple[str, ...]
    sets_hooks_path: bool


def repository_settings(where: Path) -> RepositorySettings | None:
    """Ask git what it reads for the repository view at `where`. Takes a working tree, or a git
    directory for a repository with none. Returns the answer, or None when git did not give one."""
    listed = stdout_bytes(where, ["config", "--list", "--show-origin", "--show-scope", "-z"])
    if listed is None:
        return None
    files: dict[Path, None] = {}
    sets_hooks_path = False
    fields = listed.split(b"\0")
    for scope, origin, entry in zip(fields[0::3], fields[1::3], fields[2::3]):
        if scope not in REPOSITORY_SCOPES or not origin.startswith(b"file:"):
            continue
        path = Path(os.fsdecode(origin[len(b"file:"):]))
        files[path if path.is_absolute() else Path(where) / path] = None
        sets_hooks_path = sets_hooks_path or entry.split(b"\n", 1)[0].lower() == _HOOKS_PATH.encode()
    hooks_paths: tuple[str, ...] = ()
    if sets_hooks_path:
        expanded = stdout_bytes(where, ["config", "--type=path", "--show-scope", "-z", "--get-all",
                                        _HOOKS_PATH])
        if expanded is None:
            return None
        parts = expanded.split(b"\0")
        hooks_paths = tuple(os.fsdecode(value) for scope, value in zip(parts[0::2], parts[1::2])
                            if scope in REPOSITORY_SCOPES)
    return RepositorySettings(tuple(files), hooks_paths, sets_hooks_path)
