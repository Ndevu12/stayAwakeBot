#!/usr/bin/env python3
"""Ask git which configuration files it reads for a repository, and which hooks directory that
configuration names. Read-only queries; saw's own command-line settings are told apart by scope."""
from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from stayawake.lib.git.run import run, stdout_bytes

REPOSITORY_SCOPES = (b"local", b"worktree")
_HOOKS_PATH = "core.hookspath"


@dataclass(frozen=True)
class RepositorySettings:
    """What git reports it reads for one repository view.

    `files` are the configuration files of the repository's own scopes, in the order git reads them;
    `hooks_paths` are the `core.hooksPath` values those scopes set, as git expands them, last one
    effective; `sets_hooks_path` is True when those scopes set one at all; `toplevel` is the working
    tree git runs hooks in, None for a repository without one; `git_runs_here` is False when git
    refuses the repository, so runs nothing in it.
    """

    files: tuple[Path, ...]
    hooks_paths: tuple[str, ...]
    sets_hooks_path: bool
    toplevel: Path | None = None
    git_runs_here: bool = True


GIT_REFUSES = RepositorySettings((), (), False, None, git_runs_here=False)


def repository_settings(where: Path) -> RepositorySettings | None:
    """Ask git what it reads for the repository view at `where`. Takes a working tree, or a git
    directory for a repository with none. Returns the answer, `GIT_REFUSES` when git will not run in
    the repository, or None when git did not give one."""
    state = stdout_bytes(where, ["rev-parse", "--is-bare-repository", "--show-toplevel"])
    if state is None:
        bare = run(where, ["rev-parse", "--is-bare-repository"])
        if bare is None:
            return None
        if bare.returncode != 0:
            return GIT_REFUSES
        top = None
    else:
        lines = state.split(b"\n")
        top = Path(os.fsdecode(lines[1])) if len(lines) > 1 and lines[1] else None
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
            unset = run(where, ["config", "--type=path", "--get-all", _HOOKS_PATH])
            if unset is None or unset.returncode != 1:
                return None
            expanded = b""
        parts = expanded.split(b"\0")
        hooks_paths = tuple(os.fsdecode(value) for scope, value in zip(parts[0::2], parts[1::2])
                            if scope in REPOSITORY_SCOPES)
    return RepositorySettings(tuple(files), hooks_paths, sets_hooks_path, top)


def gitlinks(where: Path) -> list[str] | None:
    """Ask git which paths its index records as submodules. Takes a working tree. Returns the paths,
    relative to it, or None when git did not answer."""
    listed = stdout_bytes(where, ["ls-files", "--stage", "-z"])
    if listed is None:
        return None
    found = []
    for record in listed.split(b"\0"):
        meta, tab, path = record.partition(b"\t")
        if tab and meta.startswith(b"160000 "):
            found.append(os.fsdecode(path))
    return found
