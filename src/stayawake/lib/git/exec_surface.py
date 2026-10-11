#!/usr/bin/env python3
"""List what git would execute for a repository: configured commands, hooks, and the includes
and attributes that decide which of them apply. Reads configuration as data and never runs it."""
from __future__ import annotations

import dataclasses
import os
import stat
from dataclasses import dataclass, field
from pathlib import Path

from stayawake.lib.git.exec_keys import HOOKS_DIRECTORY, ExecKey, rule_for, subsection
from stayawake.lib.git.run import LOCAL_TIMEOUT, run
from stayawake.lib.git.what_git_reads import RepositorySettings, gitlinks, repository_settings
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
                files_read: dict | None = None,
                opened: list[ConfigEntry] | None = None) -> list[ConfigEntry]:
    """Read a configuration file and every file it includes, treating each conditional include as
    taken. Takes the file, the surface that collects includes and what could not be read, `unsure`,
    which collects the includes only git can resolve, `files_read`, the files already read in this
    pass, and `opened`, which collects what is read where the system opens an include rather than as
    it is written (None to read each include only as it is written). Returns the entries in the
    order git applies them, with those `opened` collects left out."""
    if files_read is None:
        pairs, why = list_config_file(path)
    else:
        written = os.path.abspath(path)
        if written not in files_read:
            files_read[written] = list_config_file(path)
        pairs, why = files_read[written]
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
        for each, as_opened in ((target, False), (_opened_instead(path.parent, value), True)):
            if each is None or (as_opened and opened is None) or os.path.realpath(each) in _seen | {real}:
                continue
            read = read_config(each, surface, _chain + (path,), _seen | {real}, unsure=unsure,
                               files_read=files_read, opened=opened)
            if as_opened:
                opened += read
            else:
                entries += read
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
                 unsure: list[str] | None = None, files_read: dict | None = None,
                 opened: list[ConfigEntry] | None = None) -> list[ConfigEntry]:
    """Read the configuration of one repository in the order git applies it. Takes its git
    directory, its common directory, the surface, where to collect the includes only git can
    resolve, the files already read in this pass, and where to collect what is read where the system
    opens an include. Returns the entries."""
    entries = read_config(common_dir / "config", surface, unsure=unsure, files_read=files_read,
                          opened=opened)
    for extra in dict.fromkeys([common_dir / "config.worktree", git_dir / "config.worktree"]):
        entries += read_config(extra, surface, unsure=unsure, files_read=files_read, opened=opened)
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
               unsure: list[str], ask, collected: set[str]) -> Path | None:
    """Collect what git runs for one view of a repository: the commands its settings name and the
    hooks it runs, from saw's reading joined with every file git reports it reads. Takes the surface,
    the view's working tree (its git directory when it has none), its common directory, the entries
    saw read for it, what only git can resolve in them, the function that asks git (None when git
    cannot run in the view), and the real paths of the files and hooks directories of this
    repository already collected. Returns the hooks directory git runs hooks from, None when it runs
    none."""
    entries = list(entries)
    identity_of = {source: file_identity(source) for source in dict.fromkeys(e.source for e in entries)}
    answer: RepositorySettings | None = ask(tree) if ask is not None else None
    refused = answer is not None and not answer.git_runs_here
    git_can_run_here = ask is not None and not refused
    if refused:
        answer = None
    if answer is not None:
        known = set(identity_of.values())
        for path in answer.files:
            if file_identity(path) not in known:
                added = read_config(path, surface, _seen=frozenset(os.path.realpath(p) for p in
                                                                   dict.fromkeys(e.source for e in entries)))
                entries += added
                identity_of.update({e.source: file_identity(e.source) for e in added})
                known.add(file_identity(path))
    fresh = [e for e in entries if identity_of[e.source] not in collected]
    collected.update(identity_of.values())
    surface.commands += _commands(fresh, common_dir)
    if refused:
        effective: Path | None = None
    elif answer is None:
        effective = _hooks_dir(tree, common_dir, entries, unsure)
        if git_can_run_here:
            surface.unexamined += unsure
            surface.unexamined.append(f"{tree}: git did not report which settings it reads")
    elif not answer.hooks_paths:
        effective = common_dir / "hooks"
    else:
        effective = (_resolve(answer.toplevel or tree, answer.hooks_paths[-1])
                     if answer.hooks_paths[-1] else None)
    for directory, runs in ((effective, True), (common_dir / "hooks", False)):
        if directory is None:
            continue
        same_directory = file_identity(directory)
        if (same_directory, True) not in collected and (same_directory, runs) not in collected:
            collected.add((same_directory, runs))
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


def file_identity(path: Path) -> tuple | str:
    """Name the file or directory a path reaches, the same for every spelling of it. Takes the path.
    Returns its device and inode, or its real path when it does not exist."""
    try:
        found = os.stat(path)
        return found.st_dev, found.st_ino
    except (OSError, ValueError):
        return os.path.realpath(path)


def _belongs(tree: Path, git_dir: Path) -> bool:
    """Tell whether a working tree is a view of a git directory: its `.git` leads back to it. Takes
    the tree and the git directory. Returns the answer."""
    try:
        found = _git_dir_of(tree)
        return found is not None and file_identity(found) == file_identity(git_dir)
    except (OSError, ValueError):
        return False


def repository_views(work_tree: Path) -> list[Path]:
    """List where git runs for every view of the repository at a working tree: the tree itself, the
    main working tree and every linked worktree, each as its working tree or, without one, its git
    directory. Takes the tree. Returns the places, the given tree first; empty when it is not a git
    working tree or bare repository."""
    work_tree = Path(work_tree)
    git_dir = _git_dir_of(work_tree) or (work_tree if _is_git_dir(work_tree) else None)
    if git_dir is None:
        return []
    common_dir = _common_dir_of(git_dir)
    scratch_surface = ExecSurface(work_tree)
    main = _main_worktree(common_dir, _repo_config(git_dir, common_dir, scratch_surface))
    places: dict = {}
    for view_git_dir, tree in [(git_dir, work_tree), (common_dir, main or common_dir),
                               *_linked_worktrees(common_dir, scratch_surface)]:
        place = tree if tree == view_git_dir or _belongs(tree, view_git_dir) else view_git_dir
        places.setdefault(file_identity(view_git_dir), place)
    return list(places.values())


def _read_repository(surface: ExecSurface, tree: Path | None, git_dir: Path, ask, files_read: dict,
                     as_a_submodule: bool) -> tuple[Path | None, list[tuple[Path, Path | None]]]:
    """Collect what git runs for one repository in every view of it: the view at `git_dir`, its main
    working tree and every linked worktree. Takes the surface, the view's working tree (None for a
    submodule whose tree its settings or `.gitmodules` name), its git directory, the function that
    asks git, the settings files already read in this pass, and whether it is a submodule. Returns the
    hooks directory of the view at `git_dir`, and the git directory of every submodule its views
    hold, each with its working tree when one is known."""
    common_dir = _common_dir_of(git_dir)
    collected: set[str] = set()
    unsure: list[str] = []
    opened: list[ConfigEntry] = []
    entries = _repo_config(git_dir, common_dir, surface, unsure, files_read, opened)
    configured = _last(entries, "core.worktree") if as_a_submodule else None
    if configured is not None:
        surface.work_trees[git_dir] = _resolve(git_dir, configured.value)
    recorded = surface.work_trees.get(git_dir, tree) if as_a_submodule else tree
    tree = recorded if recorded is not None else git_dir
    git_can_run = (tree == git_dir or _belongs(tree, git_dir)) and os.path.isdir(tree)
    answer = ask(tree) if git_can_run else None

    def as_this_view(_where: Path):
        return answer
    hooks_dir = _read_view(surface, tree, common_dir, [*entries, *opened], unsure,
                           as_this_view if git_can_run else None, collected)
    main_worktree = _main_worktree(common_dir, entries)
    if main_worktree is None and os.path.realpath(git_dir) != os.path.realpath(common_dir):
        surface.unexamined.append(f"{common_dir}: the repository does not record where its main "
                                  "working tree is, so what git runs there was not read")
    views = [(view_git_dir, view_tree if _belongs(view_tree, view_git_dir) else view_git_dir)
             for view_git_dir, view_tree in [(git_dir, tree), (common_dir, main_worktree or common_dir),
                                             *_linked_worktrees(common_dir, surface)]]
    submodules: list[tuple[Path, Path | None]] = _submodules_of(surface, common_dir, tree)
    read_views: set[str] = set()
    for position, (view_git_dir, view_tree) in enumerate(views):
        if file_identity(view_git_dir) in read_views:
            continue
        read_views.add(file_identity(view_git_dir))
        if position:
            unsure, opened = [], []
            entries = _repo_config(view_git_dir, common_dir, surface, unsure, files_read, opened)
            _read_view(surface, view_tree, common_dir, [*entries, *opened], unsure, ask, collected)
        holds_its_own_modules = os.path.realpath(view_git_dir) != os.path.realpath(common_dir)
        if position:
            submodules += _submodules_of(surface, view_git_dir if holds_its_own_modules else None,
                                         view_tree)
    return hooks_dir, submodules


def _submodules_of(surface: ExecSurface, git_dir: Path | None,
                   tree: Path) -> list[tuple[Path, Path | None]]:
    """Find the submodules one view of a repository holds: the git directories under its `modules/`
    and those its tree's `.gitmodules` places, recording each tree found. Takes the surface, the
    view's git directory (None to leave its `modules/` to another view) and its working tree. Returns
    each git directory with its tree when known."""
    found: list[tuple[Path, Path | None]] = (
        [(module, None) for module in _module_git_dirs(git_dir, surface)] if git_dir is not None else [])
    if tree != git_dir and os.path.isdir(tree):
        for module, module_tree in _submodule_pointers(tree, surface):
            surface.work_trees.setdefault(module, module_tree)
            found.append((module, module_tree))
        for path in gitlinks(tree) or ():
            module_tree = tree / path
            module = _git_dir_of(module_tree) if module_tree.is_dir() else None
            if module is not None:
                surface.work_trees.setdefault(module, module_tree)
                found.append((module, module_tree))
    return found


def read_exec_surface(work_tree: Path, ask=repository_settings) -> ExecSurface | None:
    """Read what git would execute for a working tree: by parsing the repository's settings, and then
    with git for the repository and every submodule at any depth, each in every view of it. Takes the
    tree, and the function that asks git which settings it reads. Returns the surface, with everything
    that could not be read listed in `unexamined`, or None when it is not a git working tree."""
    root = Path(work_tree)
    files_read: dict = {}
    surface = _read_by_parsing(root, files_read)
    if surface is None and not _is_git_dir(root):
        return None
    if surface is not None and not surface.git_dirs:
        return surface
    try:
        with_git = _read_with_git(root, ask, files_read)
    except Exception as exc:  # the reading with git only adds; its failure must not lose the first
        surface = surface or ExecSurface(root, root, root)
        surface.unexamined.append(f"{work_tree}: reading the settings with git stopped "
                                  f"({type(exc).__name__}), so what it adds was not read")
        return surface
    if surface is None:
        return with_git
    if with_git is not None:
        _join(surface, with_git)
    return surface


def _read_by_parsing(work_tree: Path, files_read: dict) -> ExecSurface | None:
    """Read what git would execute for a working tree by parsing the repository's settings files, its
    other worktrees' settings and its submodules' settings. Takes the tree and the settings files
    already read in this pass. Returns the surface, or None when it is not a git working tree."""
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
    entries = _repo_config(git_dir, common_dir, surface, files_read=files_read)
    surface.git_dirs = list(dict.fromkeys([git_dir, common_dir]))
    surface.commands = _commands(entries, common_dir)
    surface.hooks_dir = _hooks_dir(work_tree, common_dir, entries, [])
    surface.hooks = _hooks(surface.hooks_dir, True, common_dir, surface)
    default_hooks = common_dir / "hooks"
    if os.path.normpath(surface.hooks_dir) != os.path.normpath(default_hooks):
        surface.hooks += _hooks(default_hooks, False, common_dir, surface)
    others = list(common_dir.glob("worktrees/*/config.worktree"))
    for config in others:
        surface.commands += _commands(read_config(config, surface, files_read=files_read), common_dir)
    pointed = _submodule_pointers(work_tree, surface)
    for module, tree in pointed:
        surface.work_trees.setdefault(module, tree)
    module_dirs = _module_git_dirs(common_dir, surface) + [module for module, _ in pointed]
    for module in dict.fromkeys(module_dirs):
        if module in surface.git_dirs or len(surface.git_dirs) >= MAX_GIT_DIRS:
            continue
        surface.git_dirs.append(module)
        module_entries = read_config(module / "config", surface, files_read=files_read)
        configured = _last(module_entries, "core.worktree")
        if configured is not None and configured.value:
            surface.work_trees[module] = _resolve(module, configured.value)
        surface.commands += _commands(module_entries, module)
        surface.hooks += _hooks(module / "hooks", True, module, surface)
    return surface


def _join(surface: ExecSurface, with_git: ExecSurface) -> None:
    """Add to a reading what a reading with git found that it lacks: commands from a setting not yet
    read, hooks not yet listed or now found to run, includes, a working tree for a git directory none
    of its commands are graded against, and what could not be read. Takes the reading and the reading
    with git."""
    graded_against = {c.git_dir for c in surface.commands}
    read = {(file_identity(c.entry.source), c.entry.key, c.entry.value) for c in surface.commands}
    for command in with_git.commands:
        key = (file_identity(command.entry.source), command.entry.key, command.entry.value)
        if key not in read:
            read.add(key)
            surface.commands.append(command)
    listed = {file_identity(h.path): at for at, h in enumerate(surface.hooks)}
    for hook in with_git.hooks:
        at = listed.get(file_identity(hook.path))
        if at is None:
            listed[file_identity(hook.path)] = len(surface.hooks)
            surface.hooks.append(hook)
        elif hook.runs and not surface.hooks[at].runs:
            surface.hooks[at] = dataclasses.replace(surface.hooks[at], runs=True)
    included = {(file_identity(i.source), file_identity(i.target), i.conditional) for i in surface.includes}
    for include in with_git.includes:
        key = (file_identity(include.source), file_identity(include.target), include.conditional)
        if key not in included:
            included.add(key)
            surface.includes.append(include)
    for git_dir, tree in with_git.work_trees.items():
        if git_dir not in surface.work_trees and git_dir not in graded_against:
            surface.work_trees[git_dir] = tree
    surface.unexamined = list(dict.fromkeys([*surface.unexamined, *with_git.unexamined]))


def _read_with_git(work_tree: Path, ask, files_read: dict) -> ExecSurface | None:
    """Read what git would execute for a working tree with git's own answer: for the repository and
    every submodule at any depth, each in every view of it. Takes the tree, the function that asks git
    which settings it reads, and the settings files already read in this pass. Returns the surface,
    or None when it is neither a git working tree nor a bare repository."""
    git_dir = _git_dir_of(work_tree) or (work_tree if _is_git_dir(work_tree) else None)
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
    surface.hooks_dir, pending = _read_repository(surface, work_tree, git_dir, ask, files_read, False)
    while pending:
        module, module_tree = pending.pop(0)
        if module in surface.git_dirs:
            continue
        if module_tree is not None:
            surface.work_trees.setdefault(module, module_tree)
        if len(surface.git_dirs) >= MAX_GIT_DIRS:
            surface.unexamined.append(f"{module}: more than {MAX_GIT_DIRS} repositories")
            break
        surface.git_dirs.append(module)
        _, nested = _read_repository(surface, module_tree, module, ask, files_read, True)
        pending += nested
    return surface
