#!/usr/bin/env python3
"""List what git would execute for a repository: configured commands, hooks, and the includes
and attributes that decide which of them apply. Reads configuration as data and never runs it."""
from __future__ import annotations

import os
import stat
from dataclasses import dataclass, field
from pathlib import Path

from stayawake.lib.git.exec_keys import HOOKS_DIRECTORY, ExecKey, rule_for, subsection
from stayawake.lib.git.run import LOCAL_TIMEOUT, run
from stayawake.lib.git.what_git_reads import RepositorySettings, repository_settings
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
MAX_WAIT_FILES = 256
_INCLUDE_NAMES = ("include.path",)
_EXPANDED_BY_GIT = ("%(", ":(")
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


def _opened_instead(base: Path, value: str) -> Path | None:
    """Find the file the system opens for a path git reads from configuration, when it is not the one
    `_resolve` names. Takes the directory it is relative to and the value. Returns that file, or None
    when they are the same or the system opens nothing."""
    expanded = os.path.expanduser(value)
    joined = expanded if os.path.isabs(expanded) else os.path.join(base, expanded)
    try:
        opened = os.path.realpath(joined, strict=True)
    except (OSError, ValueError):
        return None
    return None if opened == os.path.realpath(os.path.normpath(joined)) else Path(opened)


def _is_include(key: str) -> bool:
    lowered = key.lower()
    return lowered in _INCLUDE_NAMES or (lowered.startswith("includeif.")
                                         and lowered.endswith(".path"))


def read_config(path: Path, surface: ExecSurface, _chain: tuple[Path, ...] = (),
                _seen: frozenset = frozenset(), *, unsure: list[str] | None = None,
                files_read: dict | None = None) -> list[ConfigEntry]:
    """Read a configuration file and every file it includes, treating each conditional include as
    taken. Takes the file, the surface that collects includes and what could not be read, `unsure`,
    which collects the includes only git can resolve, and `files_read`, the files already read in
    this pass. Returns the entries in the order git applies them."""
    if files_read is None:
        pairs, why = list_config_file(path)
    else:
        real_path = os.path.realpath(path)
        if real_path not in files_read:
            files_read[real_path] = list_config_file(path)
        pairs, why = files_read[real_path]
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
        if value.startswith(_EXPANDED_BY_GIT) and unsure is not None:
            unsure.append(f"{path}: {key} names a path only git can resolve")
        if len(_chain) + 1 >= MAX_INCLUDE_DEPTH:
            surface.unexamined.append(f"{target}: includes nest deeper than {MAX_INCLUDE_DEPTH}")
            continue
        for each in (target, _opened_instead(path.parent, value)):
            if each is None or os.path.realpath(each) in _seen | {real}:
                continue
            entries += read_config(each, surface, _chain + (path,), _seen | {real}, unsure=unsure,
                                   files_read=files_read)
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


def config_waits(start: str | Path) -> bool:
    """Whether every git command in a repository would wait on its configuration: the repository's
    configuration, or a file it includes unconditionally, is a pipe git would open and wait on.

    Takes the repository's top directory. Returns True only when that is certain; False when the
    repository is not a plain one at `start` owned by this user, or when an include cannot be
    followed exactly as git follows it, or when more than `MAX_WAIT_FILES` files would be read.
    """
    git_dir = _plain_git_dir(Path(start))
    if git_dir is None:
        return False
    common = (_followed(git_dir / "commondir", "") if os.path.lexists(git_dir / "commondir")
              else git_dir)
    if common is None:
        return False
    return _waits_on(common / "config", set(), [MAX_WAIT_FILES], 0) is True


def _plain_git_dir(start: Path) -> Path | None:
    """The git directory git itself would use at `start`, when that needs no search: a `.git`
    directory or `gitdir:` file at `start`, or `start` itself when it is a bare repository. Takes
    the directory. Returns the git directory when it is complete and owned by this user, else
    None."""
    try:
        top = Path(os.path.realpath(start))
        dot_git = top / ".git"
        if dot_git.is_dir() and not dot_git.is_symlink():
            git_dir = dot_git
        elif os.path.lexists(dot_git):
            git_dir = _followed(dot_git, "gitdir:")
        else:
            git_dir = top
        if git_dir is None or not _is_git_dir(git_dir):
            return None
        return git_dir if os.stat(git_dir).st_uid == os.getuid() else None
    except (OSError, ValueError):
        return None


def _followed(pointer: Path, prefix: str) -> Path | None:
    """The directory a pointer file names, resolved by the file system as git resolves it. Takes
    the file and the prefix its text starts with ("" for none). Returns the directory, or None."""
    text = pathsafe.read_regular_text(pointer)
    if not text or not text.startswith(prefix):
        return None
    value = text[len(prefix):].strip()
    return Path(os.path.realpath(os.path.join(str(pointer.parent), value))) if value else None


def _is_git_dir(path: Path) -> bool:
    """Whether `path` holds what git requires of a git directory, HEAD included. Takes the path.
    Returns it."""
    common = (_followed(path / "commondir", "") if os.path.lexists(path / "commondir")
              else path)
    return (common is not None and _valid_head(path / "HEAD") and (common / "objects").is_dir()
            and (common / "refs").is_dir())


def _valid_head(head: Path) -> bool:
    """Whether a HEAD is one git accepts: a link into `refs/`, a `ref: refs/...` file, or a file
    that starts with a full object id. Takes the path. Returns the answer."""
    try:
        if head.is_symlink():
            return os.readlink(head).startswith("refs/")
    except OSError:
        return False
    text = pathsafe.read_regular_text(head)
    if text is None:
        return False
    if text.startswith("ref:"):
        return text[4:].lstrip().startswith("refs/")
    word = text.strip().split()[0] if text.strip() else ""
    return len(word) in (40, 64) and all(c in "0123456789abcdef" for c in word)


def _is_pipe(path: str | Path) -> bool:
    """Whether opening `path` to read would wait for a writer. Takes the path. Returns the answer."""
    try:
        return stat.S_ISFIFO(os.stat(path).st_mode)
    except (OSError, ValueError):
        return False


def _waits_on(path: Path, examined: set[str], budget: list[int], depth: int) -> bool | None:
    """Whether git reading the configuration file `path` would wait on a pipe, there or in a file it
    includes unconditionally. Takes the file as git names it, the files already examined in this
    check, the number of files still allowed and how deep in includes it is. Returns True, False,
    or None when it cannot be said exactly."""
    if depth > MAX_INCLUDE_DEPTH:
        return None
    if _is_pipe(path):
        return True
    key = os.path.realpath(path)
    if key in examined:
        return False
    if budget[0] <= 0:
        return None
    budget[0] -= 1
    examined.add(key)
    pairs, why = list_config_file(path)
    if why is not None:
        return False
    unsure = False
    for name, value in pairs:
        if name.lower() not in _INCLUDE_NAMES or not value:
            continue
        target = _include_target(path, value)
        if target is None:
            unsure = True
            continue
        found = _waits_on(target, examined, budget, depth + 1)
        if found is True:
            return True
        unsure = unsure or found is None
    return None if unsure else False


def _include_target(including: Path, value: str) -> Path | None:
    """The file an `include.path` names, joined the way git joins it and left for the file system
    to resolve. Takes the including file and the value. Returns the path, or None when it cannot
    be given exactly."""
    if value.startswith("%("):
        return None
    if value.startswith("~"):
        expanded = os.path.expanduser(value)
        return None if expanded.startswith("~") else Path(expanded)
    if os.path.isabs(value):
        return Path(value)
    return Path(os.path.join(os.path.dirname(str(including)), value))


def _module_git_dirs(git_dir: Path, surface: ExecSurface) -> list[Path]:
    """Walk the git directories of submodules stored under a git directory's `modules/`. Takes the
    git directory and the surface. Returns them, shallowest first."""
    found: list[Path] = []
    pending = [git_dir / "modules"]
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
        surface.unexamined.append(f"{git_dir / 'modules'}: more than {MAX_GIT_DIRS} submodules")
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


def _repo_config(git_dir: Path, common_dir: Path, surface: ExecSurface,
                 unsure: list[str] | None = None, files_read: dict | None = None) -> list[ConfigEntry]:
    """Read the configuration of one repository in the order git applies it. Takes its git
    directory, its common directory, the surface, where to collect the includes only git can
    resolve, and the files already read in this pass. Returns the entries."""
    entries = read_config(common_dir / "config", surface, unsure=unsure, files_read=files_read)
    for extra in dict.fromkeys([common_dir / "config.worktree", git_dir / "config.worktree"]):
        entries += read_config(extra, surface, unsure=unsure, files_read=files_read)
    return entries


def _commands(entries: list[ConfigEntry], git_dir: Path) -> list[Command]:
    found = []
    for entry in entries:
        rule = rule_for(entry.key)
        if rule is not None:
            found.append(Command(entry, rule, rule.command(entry.key, entry.value), git_dir))
    return found


def _hooks_dir(work_tree: Path, common_dir: Path, entries: list[ConfigEntry],
               unsure: list[str]) -> Path:
    """Find the hooks directory a repository's parsed settings name. Takes its working tree, its
    common directory, its entries and where to note a value only git can resolve. Returns it."""
    configured = next((e for e in reversed(entries)
                       if rule_for(e.key) is not None and rule_for(e.key).runs == HOOKS_DIRECTORY
                       and e.value), None)
    if configured is None:
        return common_dir / "hooks"
    if configured.value.startswith(_EXPANDED_BY_GIT):
        unsure.append(f"{configured.source}: {configured.key} names a path only git can resolve")
    return _resolve(work_tree, configured.value)


def _read_view(surface: ExecSurface, tree: Path, common_dir: Path, entries: list[ConfigEntry],
               unsure: list[str], ask, collected: set[str], default_hooks_run: bool = False) -> Path:
    """Collect what git runs for one view of a repository: the commands its settings name and the
    hooks it runs, from saw's reading joined with every file git reports it reads. Takes the surface,
    the view's working tree (its git directory when it has none), its common directory, the entries
    saw read for it and what only git can resolve in them, the function that asks git, the realpaths
    of the files and hooks directories of this repository already collected, and whether the default
    hooks directory is graded as running when the settings name another. Returns the hooks directory
    git runs hooks from."""
    entries = list(entries)
    real_path_of = {source: os.path.realpath(source)
                    for source in dict.fromkeys(e.source for e in entries)}
    git_can_run_here = os.path.isdir(tree)
    answer: RepositorySettings | None = ask(tree) if git_can_run_here else None
    if answer is None and git_can_run_here:
        surface.unexamined += unsure
        surface.unexamined.append(f"{tree}: git did not report which settings it reads")
    elif answer is not None:
        known = set(real_path_of.values())
        for path in answer.files:
            if os.path.realpath(path) not in known:
                added = read_config(path, surface, _seen=frozenset(known))
                entries += added
                real_path_of.update({e.source: os.path.realpath(e.source) for e in added})
                known.add(os.path.realpath(path))
    fresh = [e for e in entries if real_path_of[e.source] not in collected]
    collected.update(real_path_of.values())
    surface.commands += _commands(fresh, common_dir)
    named_by_settings = _hooks_dir(tree, common_dir, entries, unsure if answer is None else [])
    effective = named_by_settings
    if answer is not None:
        effective = (_resolve(tree, answer.hooks_paths[-1]) if answer.hooks_paths
                     else common_dir / "hooks")
    for directory, runs in ((effective, True), (named_by_settings, True),
                            (common_dir / "hooks", default_hooks_run)):
        real_directory = os.path.realpath(directory)
        if real_directory not in collected:
            collected.add(real_directory)
            surface.hooks += _hooks(directory, runs, common_dir, surface)
    return effective


def _linked_worktrees(common_dir: Path, surface: ExecSurface) -> list[tuple[Path, Path]]:
    """Find every linked worktree of a repository. Takes its common directory and the surface.
    Returns each worktree's git directory with its working tree, or with the git directory itself
    when the working tree is gone."""
    found = []
    try:
        listed = sorted(p for p in (common_dir / "worktrees").iterdir() if p.is_dir())
    except FileNotFoundError:
        return found
    except OSError as exc:
        surface.unexamined.append(f"{common_dir / 'worktrees'}: {type(exc).__name__}")
        return found
    for git_dir in listed:
        pointer = pathsafe.read_regular_text(git_dir / "gitdir")
        tree = _resolve(git_dir, pointer.strip()).parent if pointer and pointer.strip() else None
        found.append((git_dir, tree if tree is not None and tree.is_dir() else git_dir))
    return found


def _main_worktree(common_dir: Path, entries: list[ConfigEntry]) -> Path | None:
    """Find a repository's main working tree. Takes its common directory and its settings. Returns
    the tree, the common directory itself for a bare repository, or None when the repository does not
    record where the tree is."""
    if common_dir.name == ".git":
        return common_dir.parent
    configured = _last(entries, "core.worktree")
    if configured is not None:
        return _resolve(common_dir, configured.value)
    bare = _last(entries, "core.bare")
    if bare is not None and bare.value.lower() in ("true", "yes", "on", "1"):
        return common_dir
    return None


def read_exec_surface(work_tree: Path, ask=repository_settings) -> ExecSurface | None:
    """Read what git would execute for a working tree: for the repository, every linked worktree
    of it, and every submodule at any depth. Takes the tree, and the function that asks git which
    settings it reads. Returns the surface, with everything that could not be read listed in
    `unexamined`, or None when it is not a git working tree."""
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
    surface.git_dirs = list(dict.fromkeys([git_dir, common_dir]))
    collected: set[str] = set()
    files_read: dict = {}
    unsure: list[str] = []
    entries = _repo_config(git_dir, common_dir, surface, unsure, files_read)
    scanned_view_answer = ask(work_tree)

    def as_the_scanned_view(_where: Path):
        return scanned_view_answer
    surface.hooks_dir = _read_view(surface, work_tree, common_dir, entries, unsure,
                                   as_the_scanned_view, collected)
    main_worktree = _main_worktree(common_dir, entries)
    scanned_is_main = os.path.realpath(git_dir) == os.path.realpath(common_dir)
    if main_worktree is None and not scanned_is_main:
        surface.unexamined.append(f"{common_dir}: the repository does not record where its main "
                                  "working tree is, so what git runs there was not read")
    every_other_worktree = [(common_dir, main_worktree or common_dir),
                            *_linked_worktrees(common_dir, surface)]
    pending: list[Path] = []
    for other, tree in [(git_dir, work_tree), *every_other_worktree]:
        if other != git_dir and os.path.realpath(other) == os.path.realpath(git_dir):
            continue
        if other != git_dir:
            unsure = []
            entries = _repo_config(other, common_dir, surface, unsure, files_read)
            can_differ = (os.path.lexists(other / "config.worktree")
                          or any(e.key.lower().startswith("includeif.") for e in entries))
            _read_view(surface, tree, common_dir, entries, unsure,
                       ask if can_differ else as_the_scanned_view, collected)
        pending += _module_git_dirs(other, surface)
        if tree != other:
            for module, module_tree in _submodule_pointers(tree, surface):
                surface.work_trees.setdefault(module, module_tree)
                pending.append(module)
    while pending:
        module = pending.pop(0)
        if module in surface.git_dirs:
            continue
        if len(surface.git_dirs) >= MAX_GIT_DIRS:
            surface.unexamined.append(f"{module}: more than {MAX_GIT_DIRS} repositories")
            break
        surface.git_dirs.append(module)
        unsure = []
        entries = _repo_config(module, module, surface, unsure, files_read)
        configured = _last(entries, "core.worktree")
        if configured is not None and configured.value:
            surface.work_trees[module] = _resolve(module, configured.value)
        tree = surface.work_trees.get(module, module)
        _read_view(surface, tree, module, entries, unsure, ask, set(), default_hooks_run=True)
        if tree != module:
            for nested, nested_tree in _submodule_pointers(tree, surface):
                surface.work_trees.setdefault(nested, nested_tree)
                pending.append(nested)
    return surface
