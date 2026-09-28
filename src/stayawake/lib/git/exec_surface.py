#!/usr/bin/env python3
"""List what git would execute for a repository: configured commands, hooks, and the includes
and attributes that decide which of them apply. Reads configuration as data and never runs it."""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

from stayawake.lib.git.exec_keys import HOOKS_DIRECTORY, ExecKey, rule_for, subsection
from stayawake.lib.git.run import LOCAL_TIMEOUT, run
from stayawake.utils import pathsafe, scratch

HOOK_NAMES = frozenset((
    "applypatch-msg pre-applypatch post-applypatch pre-commit pre-merge-commit prepare-commit-msg "
    "commit-msg post-commit pre-rebase post-checkout post-merge pre-push pre-receive update "
    "proc-receive post-receive post-update reference-transaction push-to-checkout pre-auto-gc "
    "post-rewrite sendemail-validate fsmonitor-watchman post-index-change p4-changelist "
    "p4-prepare-changelist p4-post-changelist p4-pre-submit").split())

MAX_INCLUDE_DEPTH = 10
MAX_GIT_DIRS = 256
MAX_CONFIG_BYTES = 4 << 20
_INCLUDE_NAMES = ("include.path",)
@dataclass(frozen=True)
class ConfigEntry:
    """One key set in a configuration file."""

    key: str
    value: str | None
    source: Path
    included_from: tuple[Path, ...] = ()


@dataclass(frozen=True)
class Include:
    """One file a configuration file pulls in."""

    source: Path
    target: Path
    conditional: bool


@dataclass(frozen=True)
class Command:
    """One configured value git executes, or which changes what it executes."""

    entry: ConfigEntry
    rule: ExecKey
    command: str | None
    git_dir: Path


@dataclass(frozen=True)
class Hook:
    """One file in a hooks directory under a hook's name."""

    name: str
    path: Path
    runs: bool
    git_dir: Path | None


@dataclass
class ExecSurface:
    """What git would execute for one working tree."""

    work_tree: Path
    git_dir: Path | None = None
    common_dir: Path | None = None
    git_dirs: list[Path] = field(default_factory=list)
    work_trees: dict[Path, Path] = field(default_factory=dict)
    hooks_dir: Path | None = None
    commands: list[Command] = field(default_factory=list)
    includes: list[Include] = field(default_factory=list)
    hooks: list[Hook] = field(default_factory=list)
    unexamined: list[str] = field(default_factory=list)




def list_config_file(path: Path) -> tuple[list[tuple[str, str | None]], str | None]:
    """Read one configuration file as data, without following its includes. Takes the file.
    Returns its `(key, value)` pairs in file order and None, or no pairs and why it was not read;
    an absent file reads as empty."""
    if not os.path.lexists(path):
        return [], None
    if not pathsafe.is_regular_file(path):
        return [], "not a regular file"
    try:
        if path.stat().st_size > MAX_CONFIG_BYTES:
            return [], "too large to read"
    except OSError as exc:
        return [], type(exc).__name__
    res = run(None, ["config", "--file", str(path), "--no-includes", "--list", "-z"],
              timeout=LOCAL_TIMEOUT)
    if res is None:
        return [], "git could not be run"
    if res.returncode != 0:
        return [], "git would not read it"
    pairs: list[tuple[str, str | None]] = []
    for chunk in res.stdout.split("\0"):
        if not chunk:
            continue
        key, newline, value = chunk.partition("\n")
        pairs.append((key, value if newline else None))
    return pairs, None


def _resolve(base: Path, value: str) -> Path:
    """Resolve a path git reads from configuration. Takes the directory it is relative to and the
    value. Returns the path, `~` expanded."""
    expanded = os.path.expanduser(value)
    return Path(os.path.normpath(expanded if os.path.isabs(expanded) else base / expanded))


def _is_include(key: str) -> bool:
    lowered = key.lower()
    return lowered in _INCLUDE_NAMES or (lowered.startswith("includeif.")
                                         and lowered.endswith(".path"))


def read_config(path: Path, surface: ExecSurface, _chain: tuple[Path, ...] = (),
                _seen: frozenset = frozenset()) -> list[ConfigEntry]:
    """Read a configuration file and every file it includes, treating each conditional include as
    taken. Takes the file and the surface that collects includes and what could not be read.
    Returns the entries in the order git applies them."""
    pairs, why = list_config_file(path)
    if why is not None:
        surface.unexamined.append(f"{path}: {why}")
        return []
    real = os.path.realpath(path)
    entries: list[ConfigEntry] = []
    for key, value in pairs:
        entries.append(ConfigEntry(key, value, path, _chain))
        if not _is_include(key) or not value:
            continue
        target = _resolve(path.parent, value)
        surface.includes.append(Include(path, target, key.lower() != "include.path"))
        if len(_chain) + 1 >= MAX_INCLUDE_DEPTH:
            surface.unexamined.append(f"{target}: includes nest deeper than {MAX_INCLUDE_DEPTH}")
            continue
        if os.path.realpath(target) in _seen | {real}:
            continue
        entries += read_config(target, surface, _chain + (path,), _seen | {real})
    return entries


def _pointer(dot_git: Path) -> Path | None:
    """Follow a `gitdir:` pointer file. Takes the file. Returns the directory it names, or None."""
    text = pathsafe.read_regular_text(dot_git)
    if not text or not text.startswith("gitdir:"):
        return None
    target = text[len("gitdir:"):].strip()
    return _resolve(dot_git.parent, target) if target else None


def _git_dir_of(work_tree: Path) -> Path | None:
    """Find the git directory of a working tree. Takes the tree. Returns it, or None."""
    dot_git = work_tree / ".git"
    try:
        if dot_git.is_dir():
            return dot_git
    except OSError:
        return None
    return _pointer(dot_git) if os.path.lexists(dot_git) else None


def _common_dir_of(git_dir: Path) -> Path:
    """Find where a git directory keeps what its worktrees share. Takes it. Returns that path."""
    text = pathsafe.read_regular_text(git_dir / "commondir")
    return _resolve(git_dir, text.strip()) if text and text.strip() else git_dir


def _module_git_dirs(common_dir: Path, surface: ExecSurface) -> list[Path]:
    """Walk the git directories of submodules stored under `modules/`. Takes the common directory
    and the surface. Returns them, shallowest first."""
    found: list[Path] = []
    pending = [common_dir / "modules"]
    while pending and len(found) < MAX_GIT_DIRS:
        here = pending.pop(0)
        try:
            if not here.is_dir():
                continue
            children = sorted(here.iterdir())
        except OSError as exc:
            surface.unexamined.append(f"{here}: {type(exc).__name__}")
            continue
        for child in children:
            try:
                if not child.is_dir() or child.is_symlink():
                    continue
                if (child / "HEAD").exists() and (child / "config").exists():
                    found.append(child)
                    pending.append(child / "modules")
                else:
                    pending.append(child)
            except OSError as exc:
                surface.unexamined.append(f"{child}: {type(exc).__name__}")
    if pending:
        surface.unexamined.append(f"{common_dir / 'modules'}: more than {MAX_GIT_DIRS} submodules")
    return found


def _submodule_pointers(work_tree: Path, surface: ExecSurface) -> list[tuple[Path, Path]]:
    """Find the git directory of each submodule `.gitmodules` places: the one its `.git` file
    names, or its own `.git` directory. Takes the working tree and the surface. Returns each git
    directory with the working tree it serves."""
    pairs, why = list_config_file(work_tree / ".gitmodules")
    if why is not None:
        surface.unexamined.append(f"{work_tree / '.gitmodules'}: {why}")
    found = []
    for key, value in pairs:
        if not (key.lower().startswith("submodule.") and key.lower().endswith(".path") and value):
            continue
        dot_git = _resolve(work_tree, value) / ".git"
        try:
            if dot_git.is_dir() and not dot_git.is_symlink():
                found.append((dot_git, dot_git.parent))
            elif os.path.lexists(dot_git):
                target = _pointer(dot_git)
                if target is not None:
                    found.append((target, dot_git.parent))
        except OSError as exc:
            surface.unexamined.append(f"{dot_git}: {type(exc).__name__}")
    return found


def _last(entries: list[ConfigEntry], key: str) -> ConfigEntry | None:
    return next((e for e in reversed(entries) if e.key.lower() == key and e.value), None)


def _hooks(hooks_dir: Path, runs: bool, git_dir: Path | None, surface: ExecSurface) -> list[Hook]:
    """List the files in a hooks directory under a hook's name. Takes the directory, whether git
    runs hooks from it, the git directory it serves and the surface. Returns them by name."""
    try:
        if not hooks_dir.is_dir():
            return []
        children = sorted(hooks_dir.iterdir())
    except OSError as exc:
        surface.unexamined.append(f"{hooks_dir}: {type(exc).__name__}")
        return []
    found = []
    for path in children:
        name = path.name
        base = name[:-len(".local")] if name.endswith(".local") else name
        if base not in HOOK_NAMES:
            continue
        executable = pathsafe.is_regular_file(path) and os.access(path, os.X_OK)
        found.append(Hook(name, path, runs and executable, git_dir))
    return found


def _repo_config(git_dir: Path, common_dir: Path, surface: ExecSurface) -> list[ConfigEntry]:
    """Read the configuration of one repository in the order git applies it. Takes its git
    directory, its common directory and the surface. Returns the entries."""
    entries = read_config(common_dir / "config", surface)
    for extra in dict.fromkeys([common_dir / "config.worktree", git_dir / "config.worktree"]):
        entries += read_config(extra, surface)
    return entries


def _commands(entries: list[ConfigEntry], git_dir: Path) -> list[Command]:
    found = []
    for entry in entries:
        rule = rule_for(entry.key)
        if rule is not None:
            found.append(Command(entry, rule, rule.command(entry.key, entry.value), git_dir))
    return found


def _hooks_dir(work_tree: Path, common_dir: Path, entries: list[ConfigEntry]) -> Path:
    configured = next((e for e in reversed(entries)
                       if rule_for(e.key) is not None and rule_for(e.key).runs == HOOKS_DIRECTORY
                       and e.value), None)
    return _resolve(work_tree, configured.value) if configured else common_dir / "hooks"


def read_exec_surface(work_tree: Path) -> ExecSurface | None:
    """Read what git would execute for a working tree. Takes the tree. Returns the surface, with
    everything that could not be read listed in `unexamined`, or None when it is not a git
    working tree."""
    work_tree = Path(work_tree)
    git_dir = _git_dir_of(work_tree)
    if git_dir is None:
        return None
    common_dir = _common_dir_of(git_dir)
    surface = ExecSurface(work_tree, git_dir, common_dir)
    try:
        if not git_dir.is_dir():
            surface.unexamined.append(f"{git_dir}: not a directory")
            return surface
    except OSError as exc:
        surface.unexamined.append(f"{git_dir}: {type(exc).__name__}")
        return surface
    entries = _repo_config(git_dir, common_dir, surface)
    surface.git_dirs = list(dict.fromkeys([git_dir, common_dir]))
    surface.commands = _commands(entries, common_dir)
    surface.hooks_dir = _hooks_dir(work_tree, common_dir, entries)
    surface.hooks = _hooks(surface.hooks_dir, True, common_dir, surface)
    default_hooks = common_dir / "hooks"
    if os.path.normpath(surface.hooks_dir) != os.path.normpath(default_hooks):
        surface.hooks += _hooks(default_hooks, False, common_dir, surface)
    others = list(common_dir.glob("worktrees/*/config.worktree"))
    for config in others:
        surface.commands += _commands(read_config(config, surface), common_dir)
    pointed = _submodule_pointers(work_tree, surface)
    for module, tree in pointed:
        surface.work_trees.setdefault(module, tree)
    module_dirs = _module_git_dirs(common_dir, surface) + [module for module, _ in pointed]
    for module in dict.fromkeys(module_dirs):
        if module in surface.git_dirs or len(surface.git_dirs) >= MAX_GIT_DIRS:
            continue
        surface.git_dirs.append(module)
        module_entries = read_config(module / "config", surface)
        configured = _last(module_entries, "core.worktree")
        if configured is not None and configured.value:
            surface.work_trees[module] = _resolve(module, configured.value)
        surface.commands += _commands(module_entries, module)
        surface.hooks += _hooks(module / "hooks", True, module, surface)
    return surface
