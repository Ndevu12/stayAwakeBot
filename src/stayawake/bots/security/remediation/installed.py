#!/usr/bin/env python3
"""Remove an installed dependency tree from a repository."""
from __future__ import annotations

import json
import shutil
from dataclasses import dataclass, field
from pathlib import Path

from stayawake.utils import env
from stayawake.utils.pathsafe import is_safe_write_target
from stayawake.bots.security.dependencies import layout
from stayawake.bots.security.dependencies.resolvers.npm import NpmResolver
from stayawake.bots.security.models import QUARANTINE_DIR
from stayawake.bots.security.remediation.changes import quarantine_path
from stayawake.bots.security.targets import LocalRepoTarget, ScanOptions

INSTALLED_DIR = layout.INSTALLED_DIR
_LOCKFILES = frozenset({
    "package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml",
    "bun.lock", "bun.lockb", "deno.lock",
})
_DERIVED_FILES = frozenset({".pnp.cjs", ".pnp.loader.mjs", ".pnp.data.json"})
_ONLY_THESE_INSIDE = {".yarn": frozenset({"cache", "unplugged", "install-state.gz"})}
_BUILD_OUTPUTS = frozenset({"dist", "build", "out", ".next"})
_NOT_A_BUILD = frozenset({".git", INSTALLED_DIR, QUARANTINE_DIR, ".venv"})
_NOT_WALKED = frozenset({".git", QUARANTINE_DIR})


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

    @property
    def project_is_declared(self) -> bool:
        """Whether anything states what this project should contain.

        Weaker than `safe_to_remove` on purpose: a project with a lockfile and nothing installed
        still rebuilds its own `dist`.
        """
        return bool(self.lockfiles)


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
            if _is_real_directory(entry):
                for held in _scoped_children(entry):
                    found += _packages_under(held / INSTALLED_DIR)
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
        plan.reason = "no lockfile declares what the tree should contain"
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
    """Preserve first, then remove — including what the lockfile could not account for.

    An unaccounted package is the most suspicious thing in a confirmed-infected tree, and
    `npm install` does not prune extraneous packages, so leaving it in place carried it through the
    rebuild the operator is told to do. It is removed only after its copy is READ BACK: that copy is
    the only one there is, and the whole reason it is taken is that nobody can say what this is.
    """
    if not plan.safe_to_remove:
        return 0, 0
    preserved = 0
    copied: list[InstalledPackage] = []
    for package in plan.preserve:
        destination = quarantine / package.path.relative_to(plan.root)
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copytree(package.path, destination, symlinks=True, dirs_exist_ok=True)
        if not _every_file_arrived(package.path, destination):
            raise OSError(f"the copy of {package.path} is incomplete, so nothing was removed")
        copied.append(package)
        preserved += 1
    removed = 0
    for package in sorted(plan.derivable + copied, key=lambda p: len(p.path.parts), reverse=True):
        if not package.path.exists():
            continue
        if not is_safe_write_target(package.path, plan.root):
            continue
        shutil.rmtree(package.path, ignore_errors=False)
        removed += 1
    return preserved, removed


def _every_file_arrived(source: Path, destination: Path) -> bool:
    """Whether the copy holds every regular file the original does.

    `copytree` can copy part of a tree and report the failures at the end, so "it did not raise" is
    a weaker claim than the delete below needs. Symlinks are skipped: they are copied as links, and
    a dangling one would read as missing.
    """
    try:
        for path in source.rglob("*"):
            if path.is_symlink() or not path.is_file():
                continue
            if not (destination / path.relative_to(source)).exists():
                return False
    except OSError:
        return False
    return True


def _sweep_unaccounted(root: Path, quarantine: Path) -> int:
    """Copy out and remove whatever is still under the installed tree.

    Takes the repository root and this run's quarantine directory. Returns how many entries were
    removed. Nothing is deleted before its copy is read back.
    """
    tree = root / INSTALLED_DIR
    if not _is_real_directory(tree):
        return 0
    removed = 0
    try:
        entries = sorted(tree.iterdir())
    except OSError:
        return 0
    for entry in entries:
        destination = quarantine / entry.relative_to(root)
        destination.parent.mkdir(parents=True, exist_ok=True)
        if entry.is_symlink():
            if not destination.is_symlink() and not destination.exists():
                destination.symlink_to(entry.readlink())
            entry.unlink()
            removed += 1
            continue
        if entry.is_dir():
            shutil.copytree(entry, destination, symlinks=True, dirs_exist_ok=True)
            if not _every_file_arrived(entry, destination):
                raise OSError(f"the copy of {entry} is incomplete, so nothing was removed")
            if not is_safe_write_target(entry, root):
                continue
            shutil.rmtree(entry)
            removed += 1
            continue
        shutil.copy2(entry, destination)
        if not destination.is_file():
            raise OSError(f"the copy of {entry} is incomplete, so nothing was removed")
        if not is_safe_write_target(entry, root):
            continue
        entry.unlink()
        removed += 1
    return removed


def _installed_remnants(root: Path) -> tuple[int, bool]:
    """What is still under the installed tree, and whether it could be listed.

    Takes the repository root. Returns the number of entries still there and whether the tree could
    be read at all; an unreadable tree counts as holding something.
    """
    tree = root / INSTALLED_DIR
    try:
        if not tree.is_dir():
            return 0, True
        return sum(1 for _ in tree.iterdir()), True
    except OSError:
        return 1, False


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


def _named(names: list[str], most: int = 3) -> str:
    """A few names, and how many more there are.

    Takes the names and how many to show. Returns them joined, with a count when some are left out.
    """
    shown = ", ".join(names[:most])
    return shown if len(names) <= most else f"{shown} +{len(names) - most} more"


@dataclass
class Report:
    """What this run did to one repository tree."""
    preserved_packages: int = 0
    removed_packages: int = 0
    removed_lockfiles: list[Path] = field(default_factory=list)
    removed_builds: list[str] = field(default_factory=list)
    copies: Path | None = None
    removed_strays: int = 0
    removed_trees: int = 0
    not_removed: list[Path] = field(default_factory=list)
    unreadable: list[Path] = field(default_factory=list)
    installed_tree_kept: str | None = None
    installed_entries_kept: int = 0

    def note(self) -> str:
        """What this did to the live checkout, what it left alone, and where the copies went."""
        bits = []
        if self.removed_trees:
            bits.append(f"removed {self.removed_trees} installed tree(s)")
        if self.removed_packages:
            bits.append(f"removed {self.removed_packages} installed package(s)")
        if self.preserved_packages:
            bits.append(f"{self.preserved_packages} of them unaccounted for")
        if self.removed_strays:
            bits.append(f"removed {self.removed_strays} more entr(y/ies) nothing accounted for")
        if self.removed_lockfiles:
            bits.append("removed the lockfile")
        if self.removed_builds:
            bits.append("removed " + ", ".join(self.removed_builds))
        kept = "; ".join(n for n in (self.kept_note(), self.survived_note()) if n)
        if not bits:
            return kept
        done = "; ".join(bits) + " — from your working tree now, not only on the branch"
        done = f"{done}; copies in {self.copies}" if self.copies else done
        return f"{done}. {kept}" if kept else done

    def survived_note(self) -> str:
        """What a removal was asked to take and did not.

        Returns one line naming what is still there, or an empty string when everything the run
        reached was removed.
        """
        names = sorted({str(p.name) for p in self.not_removed + self.unreadable})
        return f"still there: {_named(names)}" if names else ""

    def kept_note(self) -> str:
        """What is still installed, and why it was left there.

        Returns the sentence naming the tree that was not removed, or an empty string when there
        was nothing to leave.
        """
        if self.installed_tree_kept is None:
            return ""
        what = (f"{self.installed_entries_kept} entr(y/ies) under {INSTALLED_DIR}"
                if self.installed_entries_kept else f"the {INSTALLED_DIR} directory")
        return (f"{what} left in place — {self.installed_tree_kept}. "
                f"Reinstalling does not clear it; remove it yourself before you rebuild")


def build_output_dirs(root: Path) -> list[Path]:
    """The NAMED generated trees under `root`, and nothing else.

    Never the caller's `exclude_dirs`: that setting says what is never TRAVERSED, and users put
    vendored code, fixtures and test corpora there.
    """
    found = []
    for name in sorted(_BUILD_OUTPUTS - _NOT_A_BUILD):
        path = root / name
        if _is_real_directory(path) and is_safe_write_target(path, root):
            found.append(path)
    return found


def _relative_to(path: Path, root: Path) -> Path | None:
    try:
        return path.resolve().relative_to(root.resolve())
    except (OSError, ValueError):
        return None


def derived_paths(root: Path, unreadable: list[Path]) -> list[Path]:
    """Everything under `root` that a package manager wrote rather than a person.

    Takes the repository root and a list to record directories it could not read. Returns each
    installed tree, dependency cache and resolver file, deepest first. Which directories are
    installed trees is `dependencies.layout`'s answer, so a removal clears what a scan reads.
    """
    trees = layout.installed_trees(root, unreadable)
    found: list[Path] = list(trees)
    for holder in {root, *(tree.parent for tree in trees)}:
        for name in sorted(_DERIVED_FILES):
            if (holder / name).exists():
                found.append(holder / name)
        for tool, held in _ONLY_THESE_INSIDE.items():
            for name in sorted(held):
                if (holder / tool / name).exists():
                    found.append(holder / tool / name)
    return sorted(set(found), key=lambda p: len(p.parts), reverse=True)


def remove_derived(path: Path, root: Path) -> bool:
    """Delete one piece of derived state.

    Takes the path and the repository root it must stay inside. Returns whether it was there and is
    now gone. A link loses the link, and a link inside a directory is removed as a link, so what
    either points at is left alone.
    """
    try:
        if path.is_symlink():
            path.unlink()
            return not path.is_symlink()
        if not path.exists():
            return False
    except OSError:
        return False
    if not is_safe_write_target(path, root):
        return False
    if path.is_dir():
        shutil.rmtree(path)
    else:
        path.unlink()
    return not path.exists()


def remove_installed(root: Path, *, confirmed: bool, remove_lockfiles: bool = True,
                     lockfile_root: Path | None = None) -> Report:
    """Remove what a finding of this confidence allows. Bounded to `root`.

    Takes the repository root, whether its infection is confirmed, whether the lockfile goes, and
    the tree the lockfiles are read from. Returns what was removed. A confirmed infection loses
    every reproducible directory whole; anything less keeps what no lockfile can account for.
    """
    if confirmed:
        return remove_confirmed(root, remove_lockfiles=remove_lockfiles,
                                lockfile_root=lockfile_root)
    return remove_rebuildable(root, remove_lockfiles=remove_lockfiles,
                              lockfile_root=lockfile_root)


def _still_there(path: Path) -> bool:
    """Whether `path` is on disk after a removal was attempted.

    Takes the path. Returns True when it is still there, and when that cannot be determined — an
    answer nobody can give is not an answer that it is gone.
    """
    try:
        return path.exists() or path.is_symlink()
    except OSError:
        return True


def remove_confirmed(root: Path, *, remove_lockfiles: bool = True,
                     lockfile_root: Path | None = None) -> Report:
    """Delete what a confirmed infection leaves behind. Bounded to `root`.

    Takes the repository root, whether the lockfile goes, and the tree the lockfiles are read from.
    Returns what was removed. Nothing here is copied first: an installed tree, a lockfile and a
    build output are all reproducible, and a copy of an infected one is the payload kept on disk.
    """
    report = Report()
    try:
        if not root.is_dir():
            return report
    except OSError:
        return report

    unreadable: list[Path] = []
    for path in derived_paths(root, unreadable):
        if remove_derived(path, root):
            report.removed_trees += 1
        elif _still_there(path):
            report.not_removed.append(path)
    report.unreadable.extend(unreadable)

    for build in build_output_dirs(root):
        if remove_derived(build, root):
            report.removed_builds.append(build.name)
        elif _still_there(build):
            report.not_removed.append(build)

    if remove_lockfiles:
        proof = lockfile_root if lockfile_root is not None else root
        for lockfile in lockfiles_under(proof):
            for live in {lockfile, root / (_relative_to(lockfile, proof) or lockfile.name)}:
                if not live.is_file() or live.is_symlink():
                    continue
                if not is_safe_write_target(live, root if live != lockfile else proof):
                    continue
                live.unlink()
                report.removed_lockfiles.append(live)
    return report


def lockfiles_under(root: Path) -> list[Path]:
    """The lockfiles this repository carries.

    Takes the repository root. Returns each lockfile a write may reach, without reading what any
    of them declares.
    """
    target = LocalRepoTarget(root, str(root), ScanOptions())
    found: list[Path] = []
    for name in target.iter_files():
        path = root / name
        if path.name not in _LOCKFILES or path.is_symlink() or not path.is_file():
            continue
        if not is_safe_write_target(path, root) or path in found:
            continue
        found.append(path)
    return found


def remove_rebuildable(root: Path, *, remove_lockfiles: bool = True,
                       lockfile_root: Path | None = None) -> Report:
    """Remove this repository's installed tree, lockfile, and generated outputs. Bounded to `root`.

    Kept for a repository that is not confirmed infected, where what the lockfile cannot account
    for is preserved rather than deleted. A confirmed infection goes through `remove_confirmed`.
    """
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
            report.copies = _relative_to(candidate, root) or candidate
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
        report.removed_strays = _sweep_unaccounted(root, _evidence())
        leftover = root / INSTALLED_DIR
        if _is_real_directory(leftover) and is_safe_write_target(leftover, root):
            shutil.rmtree(leftover)
    kept, readable = _installed_remnants(root)
    if kept:
        report.installed_entries_kept = kept
        report.installed_tree_kept = (
            "it could not be read" if not readable
            else plan.reason or "it is not this repository's to remove")

    if plan.project_is_declared:
        for build in build_output_dirs(root):
            shutil.copytree(build, _evidence() / build.name, symlinks=True, dirs_exist_ok=True)
            shutil.rmtree(build)
            report.removed_builds.append(build.name)

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

    return report
