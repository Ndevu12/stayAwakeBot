#!/usr/bin/env python3
"""Where a package manager puts what it installs.

One answer to "what is an installed tree, and what is a package inside one", for every caller that
needs it. A reader that grades installed code and a remover that clears it must agree, or one of
them is looking somewhere the other is not.
"""
from __future__ import annotations

from pathlib import Path
from typing import Iterator

INSTALLED_DIR = "node_modules"
_NOT_WALKED = frozenset({".git", ".malware-quarantine", ".hg", ".svn"})
_MAX_DEPTH = 8


def _is_real_directory(path: Path) -> bool:
    """True when `path` is a directory and not a symlink."""
    try:
        return path.is_dir() and not path.is_symlink()
    except OSError:
        return False


def installed_trees(root: Path, unreadable: list[Path] | None = None) -> list[Path]:
    """Every installed tree under `root`.

    Takes the root to walk and, optionally, a list to record directories it could not read.
    Returns each tree deepest first, without descending into one already found and without
    following a link out of the walk.
    """
    found: list[Path] = []
    stack = [root]
    while stack:
        here = stack.pop()
        try:
            entries = list(here.iterdir())
        except OSError:
            if unreadable is not None:
                unreadable.append(here)
            continue
        for entry in entries:
            if entry.name == INSTALLED_DIR:
                found.append(entry)
            elif entry.name not in _NOT_WALKED and _is_real_directory(entry):
                stack.append(entry)
    return sorted(found, key=lambda p: len(p.parts), reverse=True)


def package_dirs(tree: Path, depth: int = 0) -> Iterator[Path]:
    """Every package directory inside one installed tree, whatever the layout.

    Takes the tree and how deep the walk already is. Yields the directory of each package: laid
    out flat, under a scope, nested inside another package, or held in a store the top level only
    links to.
    """
    if depth > _MAX_DEPTH:
        return
    try:
        entries = sorted(tree.iterdir(), key=lambda p: p.name)
    except OSError:
        return
    for entry in entries:
        if not _is_real_directory(entry):
            continue                                  # a link is the store's copy under another name
        if entry.name.startswith("."):
            for held in _children_of(entry):          # a store keyed by name@version
                yield from package_dirs(held / INSTALLED_DIR, depth + 1)
            continue
        if entry.name.startswith("@"):
            for scoped in _children_of(entry):
                if _is_real_directory(scoped):
                    yield scoped
                    yield from package_dirs(scoped / INSTALLED_DIR, depth + 1)
            continue
        yield entry
        yield from package_dirs(entry / INSTALLED_DIR, depth + 1)


def _children_of(path: Path) -> list[Path]:
    try:
        return sorted(path.iterdir(), key=lambda p: p.name)
    except OSError:
        return []
