#!/usr/bin/env python3
"""Remove an installed dependency tree from a repository."""
from __future__ import annotations

import shutil
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath

from stayawake.utils import env
from stayawake.utils.pathsafe import is_safe_write_target
from stayawake.bots.security.dependencies import layout
from stayawake.bots.security.models import ROLLBACK_DIR
from stayawake.bots.security.targets import LocalRepoTarget, ScanOptions

INSTALLED_DIR = layout.INSTALLED_DIR
_LOCKFILES = frozenset({
    "package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml",
    "bun.lock", "bun.lockb", "deno.lock",
})
_DERIVED_FILES = frozenset({".pnp.cjs", ".pnp.loader.mjs", ".pnp.data.json"})
_ONLY_THESE_INSIDE = {".yarn": frozenset({"cache", "unplugged", "install-state.gz"})}
_BUILD_OUTPUTS = frozenset({"dist", "build", "out", ".next"})
_NOT_A_BUILD = frozenset({".git", INSTALLED_DIR, ROLLBACK_DIR, ".venv"})


def kept_paths(root: Path, keep) -> list[Path]:
    """The directories the operator asked to keep, as paths under `root`.

    Takes the repository root and the entries to keep, each written relative to that root. Returns
    one path per entry that names a directory of this repository; an entry that reaches somewhere
    else, however it gets there, names nothing.
    """
    base = _resolved(root)
    if base is None:
        return []
    found = []
    for entry in keep or ():
        spelled = PurePosixPath(str(entry).strip().replace("\\", "/"))
        parts = [p for p in spelled.parts if p != "."]
        if not parts or spelled.is_absolute() or ".." in parts:
            continue
        candidate = root.joinpath(*parts)
        if _resolved(candidate) != base.joinpath(*parts):
            continue
        found.append(candidate)
    return found


def unmatched_keep(root: Path, keep) -> list[str]:
    """The keep entries that name nothing in this repository, or nothing on disk yet. Takes the
    root and the entries. Returns each entry as written."""
    named = {str(k) for k in kept_paths(root, keep)}
    out = []
    for entry in keep or ():
        spelled = PurePosixPath(str(entry).strip().replace("\\", "/"))
        parts = [p for p in spelled.parts if p != "."]
        candidate = root.joinpath(*parts) if parts else None
        if candidate is not None and (str(candidate) not in named
                                      or _identity(candidate) is None):
            out.append(str(entry))
    return out


def _identity(path: Path) -> tuple[int, int] | None:
    """The device and inode a path names, without following a link. Takes the path. Returns them,
    or None when it names nothing."""
    try:
        found = path.lstat()
    except OSError:
        return None
    return found.st_dev, found.st_ino


def _up_to(path: Path, root: Path) -> list[Path]:
    """A path and each of its parents down to the repository root. Takes the path and the root.
    Returns them, nearest first."""
    chain = [path]
    for parent in path.parents:
        chain.append(parent)
        if parent == root:
            break
    return chain


def kept_by_operator(path: Path, root: Path, keep) -> bool:
    """Whether the operator asked for this path to stay.

    Takes the path, the repository root it lies under and the directories to keep. Returns True
    when the path is one of them or sits inside one.
    """
    if not keep:
        return False
    kept = {i for k in kept_paths(root, keep) if (i := _identity(k)) is not None}
    return bool(kept) and any(_identity(p) in kept for p in _up_to(path, root))


def holds_a_kept_path(tree: Path, root: Path, keep) -> bool:
    """Whether anything the operator asked to keep lies inside `tree`.

    Takes the tree, the repository root and the directories to keep. Returns the answer.
    """
    target = _identity(tree)
    if target is None:
        return False
    return any(_identity(parent) == target
               for kept in kept_paths(root, keep) for parent in _up_to(kept, root)[1:])


def _resolved(path: Path) -> Path | None:
    """`path` with its links followed, or None when it cannot be read."""
    try:
        return path.resolve()
    except OSError:
        return None


def _is_real_directory(path: Path) -> bool:
    """True when `path` is a directory and not a symlink."""
    try:
        return path.is_dir() and not path.is_symlink()
    except OSError:
        return False


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
    unaccounted_packages: int = 0
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
    operator_kept: list[str] = field(default_factory=list)
    keep_unmatched: list[str] = field(default_factory=list)

    @property
    def acted(self) -> bool:
        """Whether this run took anything out of the tree."""
        return bool(self.removed_trees or self.removed_packages or self.removed_strays
                    or self.removed_lockfiles or self.removed_builds)

    def note(self) -> str:
        """What this did to the live checkout, what it left alone, and where the copies went."""
        bits = []
        if self.removed_trees:
            bits.append(f"removed {self.removed_trees} installed tree(s)")
        if self.removed_packages:
            bits.append(f"removed {self.removed_packages} installed package(s)")
        if self.unaccounted_packages:
            bits.append(f"{self.unaccounted_packages} of them unaccounted for")
        if self.removed_strays:
            bits.append(f"removed {self.removed_strays} more entr(y/ies) nothing accounted for")
        if self.removed_lockfiles:
            bits.append("removed the lockfile")
        if self.removed_builds:
            bits.append("removed " + ", ".join(self.removed_builds))
        kept = "; ".join(n for n in (self.kept_note(), self.asked_note(), self.builds_note(),
                                     self.survived_note()) if n)
        if not bits:
            return kept
        done = ("; ".join(bits) + " — from your working tree now, not only on the branch;"
                " reinstall and rebuild to regenerate them")
        done = f"{done}; copies in {self.copies}" if self.copies else done
        return f"{done}. {kept}" if kept else done

    def survived_note(self) -> str:
        """What a removal was asked to take and did not.

        Returns one line naming what is still there, or an empty string when everything the run
        reached was removed.
        """
        names = sorted({str(p.name) for p in self.not_removed + self.unreadable})
        return f"still there: {_named(names)}" if names else ""

    def builds_note(self) -> str:
        """The keep entries that named nothing here. Returns "" when every entry named something."""
        if not self.keep_unmatched:
            return ""
        return f"keep_dirs entries that name nothing here: {_named(sorted(self.keep_unmatched))}"

    def asked_note(self) -> str:
        """What the operator asked to keep and this run left. Returns "" when they asked for none."""
        if not self.operator_kept:
            return ""
        return f"left in place as you asked: {_named(sorted(self.operator_kept))}"

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


def build_output_dirs(root: Path, *, keep=()) -> list[Path]:
    """The generated trees under `root` a run clears.

    Takes the root and the directory names to keep. Returns the trees.
    """
    found = []
    for name in sorted(_BUILD_OUTPUTS - _NOT_A_BUILD):
        path = root / name
        if kept_by_operator(path, root, keep):
            continue
        if path.is_symlink() or (_is_real_directory(path) and is_safe_write_target(path, root)):
            found.append(path)
    return found


def remove_generated(tree: Path, root: Path, tracked=(), keep=(), confirms=None,
                     left: list[Path] | None = None) -> bool:
    """Remove what the repository does not track under `tree`, and what it tracks but carries.

    Takes the tree, the root it must stay inside, the tracked paths relative to that root, the
    directories to keep, `confirms(path) -> bool`, and a list to add each path to that could not be
    removed. Returns whether the tree itself is gone. A tracked path is left only when a reader is
    given and reads it clean, so a caller that gives none clears the tree whole.
    """
    kept = {root / t for t in tracked} if confirms is not None else set()
    if tree.is_symlink() or (not kept and not keep):
        return remove_derived(tree, root)
    for path in sorted(tree.rglob("*"), key=lambda p: len(p.parts), reverse=True):
        if kept_by_operator(path, root, keep) or holds_a_kept_path(path, root, keep):
            continue
        if path in kept or any(_inside(k, path) for k in kept):
            if not (path.is_file() and confirms(path)):
                continue
        if (not remove_derived(path, root) and left is not None and _still_there(path)
                and not any(_inside(named, path) for named in left)):
            left.append(path)
    if _is_empty(tree):
        remove_derived(tree, root)
    return not tree.exists()


def _is_empty(tree: Path) -> bool:
    """Whether nothing is left under `tree`. Takes the tree. Returns False when it cannot look."""
    try:
        return not any(tree.iterdir())
    except OSError:
        return False


def _inside(candidate: Path, parent: Path) -> bool:
    """Whether `candidate` lies under `parent`."""
    try:
        return candidate.is_relative_to(parent)
    except (OSError, ValueError):
        return False


def _relative_to(path: Path, root: Path) -> Path | None:
    try:
        return path.resolve().relative_to(root.resolve())
    except (OSError, ValueError):
        return None


def derived_paths(root: Path, unreadable: list[Path], keep=()) -> list[Path]:
    """Everything under `root` that a package manager wrote rather than a person.

    Takes the repository root, a list to record directories it could not read and the directory
    names to keep. Returns each installed tree, dependency cache and resolver file, deepest first.
    Which directories are installed trees is `dependencies.layout`'s answer.
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
    return sorted({p for p in found if not kept_by_operator(p, root, keep)},
                  key=lambda p: len(p.parts), reverse=True)


def remove_derived(path: Path, root: Path) -> bool:
    """Delete one piece of derived state.

    Takes the path and the repository root it must stay inside. Returns whether it was there and
    is now gone. A link loses the link; what it points at is left alone.
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


def remove_installed(root: Path, *, remove_lockfiles: bool = True,
                     lockfile_root: Path | None = None, keep=()) -> Report:
    """Remove the installed tree, the generated outputs and the lockfiles of a confirmed infection.
    Bounded to `root`. Takes the repository root, whether the lockfile goes, the tree the lockfiles
    are read from and the directories to keep. Returns what was removed."""
    return remove_confirmed(root, remove_lockfiles=remove_lockfiles,
                            lockfile_root=lockfile_root, keep=keep)


def _still_there(path: Path) -> bool:
    """Whether `path` is on disk after a removal was attempted.

    Takes the path. Returns True when it is still there, and when that cannot be read.
    """
    try:
        return path.exists() or path.is_symlink()
    except OSError:
        return True


def remove_confirmed(root: Path, *, keep=(), remove_lockfiles: bool = True,
                     lockfile_root: Path | None = None) -> Report:
    """Delete what a confirmed infection leaves behind. Bounded to `root`.

    Takes the repository root, the directories to keep, whether the lockfile goes and the tree the
    lockfiles are read from. Returns what was removed. A generated tree goes whole, and nothing is
    copied aside.
    """
    report = Report()
    try:
        if not root.is_dir():
            return report
    except OSError:
        return report

    report.operator_kept = [str(_relative_to(k, root) or k)
                            for k in kept_paths(root, keep) if k.is_dir()]
    report.keep_unmatched = unmatched_keep(root, keep)
    unreadable: list[Path] = []
    for path in derived_paths(root, unreadable, keep):
        if holds_a_kept_path(path, root, keep):
            left: list[Path] = []
            remove_generated(path, root, (), keep, left=left)
            report.not_removed.extend(left)
            report.removed_trees += not left
            continue
        if remove_derived(path, root):
            report.removed_trees += 1
        elif _still_there(path):
            report.not_removed.append(path)
    report.unreadable.extend(unreadable)


    for build in build_output_dirs(root, keep=keep):
        if remove_generated(build, root, (), keep):
            report.removed_builds.append(build.name)
        elif _still_there(build):
            report.not_removed.append(build)

    if remove_lockfiles:
        proof = lockfile_root if lockfile_root is not None else root
        report.removed_lockfiles += _remove_lockfiles(root, proof, keep)
    return report


def remove_lockfiles_of(tree: Path, *, keep=()) -> list[Path]:
    """Delete the lockfiles a tree carries. Takes the tree and the directories to keep. Returns
    the lockfiles removed."""
    return _remove_lockfiles(tree, tree, keep)


def _remove_lockfiles(root: Path, proof: Path, keep) -> list[Path]:
    """Delete each lockfile `proof` carries, there and at the same place under `root`. Takes the
    tree to clear, the tree the lockfiles are read from and the directories to keep. Returns the
    lockfiles removed."""
    removed: list[Path] = []
    for lockfile in lockfiles_under(proof):
        for live in {lockfile, root / (_relative_to(lockfile, proof) or lockfile.name)}:
            if not live.is_file() or live.is_symlink():
                continue
            if kept_by_operator(live, root, keep):
                continue
            if not is_safe_write_target(live, root if live != lockfile else proof):
                continue
            live.unlink()
            removed.append(live)
    return removed


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
