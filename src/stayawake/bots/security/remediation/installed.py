#!/usr/bin/env python3
"""Remove an installed dependency tree from a repository."""
from __future__ import annotations

import json
import shutil
from dataclasses import dataclass, field
from pathlib import Path

from stayawake.utils import env
from stayawake.utils.pathsafe import is_safe_write_target
from stayawake.bots.security.dependencies.resolvers.npm import NpmResolver
from stayawake.bots.security.models import QUARANTINE_DIR
from stayawake.bots.security.remediation.changes import quarantine_path
from stayawake.bots.security.targets import LocalRepoTarget, ScanOptions

INSTALLED_DIR = "node_modules"
_LOCKFILES = frozenset({"package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml"})
_BUILD_OUTPUTS = frozenset({"dist", "build", "out", ".next"})
_NOT_A_BUILD = frozenset({".git", INSTALLED_DIR, QUARANTINE_DIR, ".venv"})


@dataclass(frozen=True)
class InstalledPackage:
    """One package as it exists on disk."""
    name: str
    version: str | None
    path: Path

    @property
    def identity(self) -> tuple[str, str | None]:
        return self.name, self.version


@dataclass
class RemovalPlan:
    """What may be removed, and what is kept."""
    root: Path
    derivable: list[InstalledPackage] = field(default_factory=list)
    preserve: list[InstalledPackage] = field(default_factory=list)
    lockfiles: list[Path] = field(default_factory=list)
    reason: str | None = None

    @property
    def safe_to_remove(self) -> bool:
        return self.reason is None and bool(self.derivable)


def installed_packages(root: Path) -> list[InstalledPackage]:
    """Packages present under the installed tree."""
    tree = root / INSTALLED_DIR
    if not _is_real_directory(tree):
        return []
    return _packages_under(tree)


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
    """True when `path` is a directory and not a symlink."""
    try:
        return path.is_dir() and not path.is_symlink()
    except OSError:
        return False


def _sits_where_its_name_says(package: InstalledPackage) -> bool:
    """True when the package's path matches its name."""
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


def plan_removal(root: Path, declared: set[tuple[str, str]], lockfiles: list[Path]) -> RemovalPlan:
    """Split the installed tree by what `declared` proves. Does not write."""
    plan = RemovalPlan(root=root, lockfiles=lockfiles)
    if not lockfiles:
        plan.reason = "no lockfile, so nothing proves what the tree should contain"
        return plan
    if not declared:
        plan.reason = "the lockfile declares nothing, so it cannot reconstruct the tree"
        return plan
    for package in installed_packages(root):
        if not is_safe_write_target(package.path, root):
            continue
        if package.version and package.identity in declared and _sits_where_its_name_says(package):
            plan.derivable.append(package)
        else:
            plan.preserve.append(package)
    if not plan.derivable:
        plan.reason = "no installed package matches the lockfile, so none is proven derivable"
    return plan


def apply_removal(plan: RemovalPlan, quarantine: Path) -> tuple[int, int]:
    """Preserve first, then remove. Returns (preserved, removed)."""
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
            continue
        if not is_safe_write_target(package.path, plan.root):
            continue
        shutil.rmtree(package.path, ignore_errors=False)
        removed += 1
    return preserved, removed


def next_quarantine(root: Path, base: Path) -> Path:
    """A new subdirectory under `base` for this run."""
    for index in range(1, 1000):
        candidate = base / f"installed-{index}"
        if not candidate.exists():
            return candidate
    raise OSError(f"cannot make a fresh quarantine under {base}")


def declared_from_lockfiles(root: Path) -> tuple[set[tuple[str, str]], list[Path]]:
    """Declared (name, version) pairs and the lockfiles they came from."""
    target = LocalRepoTarget(root, str(root), ScanOptions())
    declared, lockfiles = set(), []
    for dependency in NpmResolver().resolve(target):
        path = root / dependency.source_path
        if path.name not in _LOCKFILES:
            continue
        if not is_safe_write_target(path, root):
            continue
        declared.add((dependency.purl.name, dependency.purl.version))
        if path not in lockfiles:
            lockfiles.append(path)
    return declared, lockfiles


def lockfile_stays() -> bool:
    """True when this process looks like CI."""
    return env.is_ci() or env.any_set(
        (env.GITHUB_ACTIONS, env.GITLAB_CI, env.CIRCLECI, env.BUILDKITE, env.RUNNER_OS))


@dataclass
class Report:
    """What this run did to one repository tree."""
    preserved_packages: int = 0
    removed_packages: int = 0
    removed_lockfiles: list[Path] = field(default_factory=list)
    removed_builds: list[str] = field(default_factory=list)

    def note(self) -> str:
        bits = []
        if self.removed_packages:
            bits.append(f"removed {self.removed_packages} installed package(s)")
        if self.preserved_packages:
            bits.append(f"kept {self.preserved_packages}")
        if self.removed_lockfiles:
            bits.append("removed the lockfile")
        if self.removed_builds:
            bits.append("removed " + ", ".join(self.removed_builds))
        return "; ".join(bits)


def build_output_dirs(root: Path, exclude_dirs) -> list[Path]:
    """Project-local generated trees under `root`."""
    names = set(_BUILD_OUTPUTS) | set(ScanOptions().exclude_dirs)
    if exclude_dirs:
        names |= set(exclude_dirs)
    names -= _NOT_A_BUILD
    found = []
    for name in sorted(names):
        path = root / name
        if _is_real_directory(path) and is_safe_write_target(path, root):
            found.append(path)
    return found


def _relative_to(path: Path, root: Path) -> Path | None:
    try:
        return path.resolve().relative_to(root.resolve())
    except (OSError, ValueError):
        return None


def remove_rebuildable(root: Path, *, exclude_dirs=None, remove_lockfiles: bool = True,
                       lockfile_root: Path | None = None) -> Report:
    """Remove this repository's installed tree, lockfile, and generated outputs. Bounded to `root`."""
    report = Report()
    try:
        if not root.is_dir():
            return report
    except OSError:
        return report

    proof = lockfile_root if lockfile_root is not None else root
    declared, lockfiles = declared_from_lockfiles(proof)
    plan = plan_removal(root, declared, lockfiles)
    quarantine: Path | None = None

    def _evidence() -> Path:
        nonlocal quarantine
        if quarantine is None:
            candidate = next_quarantine(root, quarantine_path(root))
            if not is_safe_write_target(candidate, root):
                raise OSError(f"quarantine is not inside {root}")
            candidate.mkdir(parents=True, exist_ok=True)
            if not is_safe_write_target(candidate, root):
                raise OSError(f"quarantine is not inside {root}")
            quarantine = candidate
        return quarantine

    copies: list[Path] = []
    if remove_lockfiles:
        for lockfile in lockfiles:
            if not lockfile.is_file() or lockfile.is_symlink():
                continue
            if not is_safe_write_target(lockfile, proof):
                continue
            rel = _relative_to(lockfile, proof)
            if rel is None:
                continue
            destination = _evidence() / rel
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(lockfile, destination)
            copies.append(lockfile)

    if plan.safe_to_remove:
        preserved, removed = apply_removal(plan, _evidence())
        report.preserved_packages = preserved
        report.removed_packages = removed
        leftover = root / INSTALLED_DIR
        if not plan.preserve and _is_real_directory(leftover) and is_safe_write_target(leftover, root):
            shutil.rmtree(leftover)

    seen: set[Path] = set()
    for lockfile in copies:
        lockfile.unlink()
        report.removed_lockfiles.append(lockfile)
        seen.add(lockfile.resolve())
        rel = _relative_to(lockfile, proof)
        if rel is None or proof == root:
            continue
        live = root / rel
        if live.resolve() in seen:
            continue
        if live.is_file() and not live.is_symlink() and is_safe_write_target(live, root):
            live.unlink()
            seen.add(live.resolve())

    for build in build_output_dirs(root, exclude_dirs):
        shutil.rmtree(build)
        report.removed_builds.append(build.name)
    return report
