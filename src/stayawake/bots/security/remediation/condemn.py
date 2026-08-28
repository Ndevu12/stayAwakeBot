#!/usr/bin/env python3
"""Removing an installed dependency tree that a lockfile can reconstruct.

A lockfile records what SHOULD be installed. It does not record what WAS — an install never
refreshed, a package added and never committed, a stale cache. So the tree is two things at once:
a part the lockfile proves derivable, and a part that exists only here and is the only record of
what actually ran. The second is evidence; it is preserved before anything is removed.

`saw` removes. It does not reinstall: an install re-runs the lifecycle scripts, which is the path
the payload arrived by."""
from __future__ import annotations

import json
import shutil
from dataclasses import dataclass, field
from pathlib import Path

INSTALLED_DIR = "node_modules"


@dataclass(frozen=True)
class InstalledPackage:
    """One package as it exists ON DISK, which is not necessarily what any file declares."""
    name: str
    version: str | None
    path: Path

    @property
    def identity(self) -> tuple[str, str | None]:
        return self.name, self.version


@dataclass
class CondemnPlan:
    """What may be removed, and what may not. `preserve` is read first and never deleted."""
    root: Path
    derivable: list[InstalledPackage] = field(default_factory=list)
    preserve: list[InstalledPackage] = field(default_factory=list)
    lockfiles: list[Path] = field(default_factory=list)
    reason: str | None = None

    @property
    def safe_to_remove(self) -> bool:
        """A tree is removable only when something proves it reconstructible. No lockfile, or a
        lockfile that declares nothing, means nothing was proven and nothing is removed."""
        return self.reason is None and bool(self.derivable)


def installed_packages(root: Path) -> list[InstalledPackage]:
    """Every package present in the installed tree, read from what each one says it is.

    Nested trees are walked too. A package the lockfile accounts for can contain one it does not,
    and removing the parent would take the child with it before anything had looked at it."""
    return _packages_under(root / INSTALLED_DIR)


def _packages_under(tree: Path) -> list[InstalledPackage]:
    found: list[InstalledPackage] = []
    try:
        entries = sorted(tree.iterdir())
    except OSError:
        return found
    for entry in entries:
        if entry.name.startswith("."):
            continue
        scoped = _scoped_children(entry) if entry.name.startswith("@") else [entry]
        for package in scoped:
            if not _is_real_directory(package):
                continue
            found.append(_read_package(package))
            found += _packages_under(package / INSTALLED_DIR)
    return found


def _scoped_children(scope: Path) -> list[Path]:
    try:
        return sorted(scope.iterdir())
    except OSError:
        return []


def _is_real_directory(path: Path) -> bool:
    """A link is not ours to remove — its target lives somewhere this tree does not own."""
    try:
        return path.is_dir() and not path.is_symlink()
    except OSError:
        return False


def _sits_where_its_name_says(package: InstalledPackage) -> bool:
    """Whether an install would put this package back at this path.

    A directory whose contents claim a different name is not reconstructible HERE — an install
    recreates the name's own location and leaves this one missing, so it is not derivable."""
    parts = package.name.split("/")
    location = package.path.parts[-len(parts):]
    return list(location) == parts


def _read_package(package: Path) -> InstalledPackage:
    try:
        data = json.loads((package / "package.json").read_text(encoding="utf-8", errors="replace"))
    except (OSError, ValueError):
        data = {}
    name = data.get("name") if isinstance(data, dict) else None
    version = data.get("version") if isinstance(data, dict) else None
    return InstalledPackage(name=name or package.name,
                            version=version if isinstance(version, str) else None,
                            path=package)


def plan_condemnation(root: Path, declared: set[tuple[str, str]], lockfiles: list[Path]) -> CondemnPlan:
    """Split the installed tree by what `declared` proves, without touching the filesystem.

    An installed package matches only on name AND version: a tree at a different version than the
    lockfile pins is drift, and drift is the case where the lockfile reads clean and the tree does
    not. A package with no readable version proves nothing about itself and is preserved."""
    plan = CondemnPlan(root=root, lockfiles=lockfiles)
    if not lockfiles:
        plan.reason = "no lockfile, so nothing proves what the tree should contain"
        return plan
    if not declared:
        plan.reason = "the lockfile declares nothing, so it cannot reconstruct the tree"
        return plan
    for package in installed_packages(root):
        if package.version and package.identity in declared and _sits_where_its_name_says(package):
            plan.derivable.append(package)
        else:
            plan.preserve.append(package)
    if not plan.derivable:
        plan.reason = "no installed package matches the lockfile, so none is proven derivable"
    return plan


def carry_out(plan: CondemnPlan, quarantine: Path) -> tuple[int, int]:
    """(preserved, removed). Preservation happens FIRST and completely: if any part of it fails,
    nothing is removed, because the copy being preserved is the only one that exists.

    Removal runs deepest-first. A package the lockfile accounts for can contain another, and
    removing the parent first takes the child with it — leaving the walk to delete a path that is
    already gone, mid-way through a destructive operation."""
    if not plan.safe_to_remove:
        return 0, 0
    preserved = 0
    for package in plan.preserve:
        destination = quarantine / package.path.relative_to(plan.root)
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copytree(package.path, destination, symlinks=True, dirs_exist_ok=True)
        preserved += 1
    removed = 0
    for package in sorted(plan.derivable, key=lambda p: len(p.path.parts), reverse=True):
        if not package.path.exists():
            continue                      # its parent went first; it went with it
        shutil.rmtree(package.path, ignore_errors=False)
        removed += 1
    return preserved, removed


def next_quarantine(root: Path, base: Path) -> Path:
    """A directory of its own for this run. Reusing one merges two incidents' evidence into a single
    tree, and lets a retry write over a copy that failed half way with no way to tell them apart."""
    for index in range(1, 1000):
        candidate = base / f"condemned-{index}"
        if not candidate.exists():
            return candidate
    raise OSError(f"cannot make a fresh quarantine under {base}")
