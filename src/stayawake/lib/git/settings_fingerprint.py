#!/usr/bin/env python3
"""The fingerprint of the programs a repository's own git settings start: every setting in its own
configuration that `lib/data/git_exec_keys.json` lists as running a program, every file under the
hooks folder git runs hooks from when that folder is the repository's own, except a hook whose bytes
match the one saw installs, every file under the working tree's top folder that holds that hooks
folder, and the hook managers' own files (`lib/data/git_hook_managers.json`). The git stand-in reads
the same fingerprint. Nothing in the folder is run."""
from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass
from pathlib import Path

from stayawake.lib.git.exec_keys import ABSOLUTE_PATH, ENABLES_TRANSPORT, HOOKS_DIRECTORY, ExecKey, rule_for
from stayawake.lib.git import runs_directly, runs_from_the_folder
from stayawake.lib.git.run import run
from stayawake.utils import env

OWN_SCOPES = ("local", "worktree")
HOOKS_KEY = "core.hookspath"
NEVER_RUN_SUFFIX = ".sample"
SETTING = "setting"
HOOKS_FOLDER = "hooks"
HOOK = "hook"
HOOK_LINK = "hook-link"
TREE = "tree"
TREE_LINK = "tree-link"
MANAGER = "manager"
MANAGER_LINK = "manager-link"
ABSENT = "absent"
PACKAGE = "package.json"
MOST_FILES = 2000
_RUN = frozenset({SETTING, HOOK, HOOK_LINK})
_LOCATE = ["rev-parse", "--path-format=absolute", "--absolute-git-dir", "--git-common-dir",
           "--is-inside-work-tree"]


@dataclass(frozen=True)
class Fingerprint:
    """The programs one repository's own settings start, as sorted entries: `("setting", scope,
    key, value)`, `("hooks", folder)` and `("hook", name, sha256)`. `repository` is its common git
    directory with every link resolved, the key it is kept under; `folder` names it: the top of its
    working tree, or its git directory without one."""

    repository: str
    folder: str
    entries: tuple[tuple[str, ...], ...]

    @property
    def empty(self) -> bool:
        """Whether the repository's own settings start no program at all: no setting and no hook."""
        return not any(entry[0] in _RUN for entry in self.entries)

    def digest(self) -> str:
        """Return the sha256 of the entries written as compact JSON, in hex."""
        written = json.dumps([list(entry) for entry in self.entries], ensure_ascii=False, separators=(",", ":"))
        return hashlib.sha256(written.encode("utf-8")).hexdigest()

    def named(self) -> list[str]:
        """Name what the settings start, the way a person reads them: each setting's key and each
        hook by name. Returns the names in order."""
        names: list[str] = []
        for entry in self.entries:
            name = (entry[2] if entry[0] == SETTING else f"the {entry[1]} hook" if entry[0] == HOOK else None)
            if name is not None and name not in names:
                names.append(name)
        return names

    def hooks_folder(self) -> str | None:
        """Return the hooks folder whose files are in the fingerprint, or None."""
        return next((entry[1] for entry in self.entries if entry[0] == HOOKS_FOLDER), None)


def fingerprint(folder: str | Path) -> Fingerprint | str | None:
    """Read the fingerprint of the repository a folder is in. Takes the folder. Returns it, None when
    the folder is in no repository, or why it cannot be read."""
    located = run(folder, _LOCATE)
    lines = (located.stdout or "").splitlines() if located is not None and located.returncode == 0 else []
    if len(lines) != 3:
        return None
    git_dir, common_dir, inside = lines
    top = None
    if inside == "true":
        shown = run(folder, ["rev-parse", "--show-toplevel"])
        top = (shown.stdout or "").splitlines()[0] if shown is not None and shown.returncode == 0 and shown.stdout else ""
        if not top:
            return f"the working tree of {folder} could not be found"
    listed = run(folder, ["config", "--list", "--show-scope", "-z"])
    if listed is None or listed.returncode != 0:
        return f"the git settings of {folder} did not load"
    return from_listing(listed.stdout or "", git_dir, common_dir, top)


def from_listing(listing: str, git_dir: str, common_dir: str, top: str | None) -> Fingerprint | str:
    """Read the fingerprint from git's listing of every setting with its scope (`git config --list
    --show-scope -z`). Takes the listing, the git directory, the common directory and the top of the
    working tree (None without one). Returns the fingerprint, or why a hook file could not be read."""
    fields = listing.split("\0")
    entries: list[tuple[str, ...]] = []
    hooks_setting: tuple[str, str] | None = None
    for scope, entry in zip(fields[0::2], fields[1::2]):
        key, newline, value = entry.partition("\n")
        if not newline:
            continue
        if key.lower() == HOOKS_KEY and value:
            hooks_setting = (scope, value)
        rule = rule_for(key)
        if scope in OWN_SCOPES and rule is not None and runs_a_program(rule, key, value):
            entries.append((SETTING, scope, key, value))
    folder = _own_hooks_folder(hooks_setting, git_dir, common_dir, top)
    read = _Budget()
    try:
        if folder is not None:
            hooks = _hook_files(folder, read)
            if hooks:
                entries.append((HOOKS_FOLDER, os.path.realpath(folder)))
                entries += hooks
        if top is not None:
            named = folder if hooks_setting is not None else None
            entries += _tree_holding_the_hooks(named, top, common_dir, read) + _manager_files(top, read)
    except _Unreadable as why:
        return str(why)
    folder_named = top if top is not None else git_dir
    return Fingerprint(os.path.realpath(common_dir), folder_named, tuple(sorted(set(entries))))


def runs_a_program(rule: ExecKey, key: str, value: str) -> bool:
    """Say whether a setting's value starts a program. Takes its rule, its listed key and its
    value."""
    text = value.strip()
    if rule.runs == HOOKS_DIRECTORY:
        return bool(text)
    if rule.runs == ENABLES_TRANSPORT:
        return bool(text) and text.lower() != "never"
    if rule.runs == ABSOLUTE_PATH:
        return bool(text) and os.path.isabs(expand_home(text))
    return rule.command(key, value) is not None


def expand_home(value: str) -> str:
    """Expand a leading `~` or `~/` to the home folder. Takes the text. Returns the expanded
    text."""
    home = os.environ.get("HOME")
    if home is None:
        return value
    if value == "~":
        return home
    return home.rstrip("/") + value[1:] if value.startswith("~/") else value


def _own_hooks_folder(setting: tuple[str, str] | None, git_dir: str, common_dir: str,
                      top: str | None) -> str | None:
    """Find the hooks folder git runs hooks from when it is the repository's own: the folder its own
    settings name, a relative folder the operator's settings name, or the default under the common
    directory. Takes the last `core.hooksPath` with its scope, the git directory, the common
    directory and the top of the working tree. Returns it, or None when the operator's own folder is
    in force."""
    if setting is None:
        return os.path.join(common_dir, "hooks")
    scope, value = setting
    expanded = expand_home(value)
    if os.path.isabs(expanded):
        return expanded if scope in OWN_SCOPES else None
    return os.path.normpath(os.path.join(top if top is not None else git_dir, expanded))


class _Unreadable(Exception):
    """A file the fingerprint covers could not be read, or there were too many."""


class _Budget:
    """Counts the files read, up to `MOST_FILES`."""

    def __init__(self) -> None:
        self.read = 0

    def one_more(self, where: str) -> None:
        """Count one file. Takes where it lies. Raises `_Unreadable` past the limit."""
        self.read += 1
        if self.read > MOST_FILES:
            raise _Unreadable(f"more than {MOST_FILES} files lie under {where}")


def _walk(folder: bytes, budget: _Budget) -> list[tuple[str, bool, str]]:
    """List every file under a folder, links under it recorded as links and never followed. Takes
    the folder and the count of files read. Returns each path relative to it with `/` between its
    parts, whether it is a link, and the sha256 of a file or the target of a link."""
    try:
        names = sorted(os.listdir(folder))
    except (FileNotFoundError, NotADirectoryError):
        return []
    except OSError as error:
        raise _Unreadable(f"{os.fsdecode(folder)} could not be read: {error.strerror or error}") from error
    found: list[tuple[str, bool, str]] = []
    for raw in names:
        found += _read(os.path.join(folder, raw), raw.decode("utf-8", "replace"), budget)
    return found


def _read(path: bytes, rel: str, budget: _Budget) -> list[tuple[str, bool, str]]:
    """Read one path: a link by its target, a folder by every file under it, a file by its sha256.
    Takes the path, its name relative to where the reading started and the count of files read.
    Returns the entries, none for anything else."""
    try:
        if os.path.islink(path):
            budget.one_more(os.fsdecode(path))
            return [(rel, True, os.fsencode(os.readlink(path)).decode("utf-8", "replace"))]
        if os.path.isdir(path):
            return [(f"{rel}/{inner}", link, value) for inner, link, value in _walk(path, budget)]
        if not os.path.isfile(path):
            return []
        budget.one_more(os.fsdecode(path))
        with open(path, "rb") as file:
            return [(rel, False, hashlib.sha256(file.read()).hexdigest())]
    except FileNotFoundError:
        return []
    except OSError as error:
        raise _Unreadable(f"{os.fsdecode(path)} could not be read: {error.strerror or error}") from error


def _hook_files(folder: str, budget: _Budget) -> list[tuple[str, ...]]:
    """List every file under a hooks folder: each path with the sha256 of its contents or a link's
    target, the example files git writes and the hooks saw installs left out. Takes the folder and
    the count of files read. Returns the entries."""
    found: list[tuple[str, ...]] = []
    for rel, link, value in _walk(os.fsencode(folder), budget):
        if "/" not in rel and rel.endswith(NEVER_RUN_SUFFIX):
            continue
        if not link and value == _saws_own_hook(os.fsencode(rel)):
            continue
        found.append((HOOK_LINK if link else HOOK, rel, value))
    return found


def _tree_holding_the_hooks(folder: str | None, top: str, common_dir: str, budget: _Budget) -> list[tuple[str, ...]]:
    """List every file under the working tree's top folder that holds the hooks folder `core.hooksPath`
    names, when it lies inside the working tree and outside the git directory. Takes that hooks
    folder (None when no setting names one), the top of the working tree, the common directory and
    the count of files read. Returns the entries."""
    if folder is None or _lies_in(folder, common_dir):
        return []
    inside = os.path.relpath(os.path.realpath(folder), os.path.realpath(top)).replace(os.sep, "/")
    if inside == ".":
        raise _Unreadable(f"the hooks folder is the whole working tree of {top}")
    if inside == ".." or inside.startswith("../"):
        return []
    first = inside.split("/")[0]
    return [(TREE_LINK if link else TREE, f"{first}/{rel}", value)
            for rel, link, value in _walk(os.fsencode(os.path.join(top, first)), budget)]


def _lies_in(path: str, folder: str) -> bool:
    """Say whether a path is a folder or lies inside it, every link resolved. Takes both."""
    inside = os.path.relpath(os.path.realpath(path), os.path.realpath(folder)).replace(os.sep, "/")
    return inside == "." or not (inside == ".." or inside.startswith("../"))


def _manager_files(top: str, budget: _Budget) -> list[tuple[str, ...]]:
    """List the hook managers' own files in a working tree, each pattern no file matches recorded as
    absent, and package.json when it holds a key a hook manager reads. Takes the top of the working
    tree and the count of files read. Returns the entries."""
    managers = runs_from_the_folder.hook_managers()
    found: list[tuple[str, ...]] = []
    for pattern in managers.files:
        matched = _matching(top, pattern, budget)
        found += [(MANAGER_LINK if link else MANAGER, rel, value) for rel, link, value in matched]
        if not matched:
            found.append((ABSENT, pattern))
    package = os.path.join(top, PACKAGE)
    try:
        with open(package, "rb") as file:
            contents = file.read()
    except FileNotFoundError:
        return found + [(ABSENT, PACKAGE)]
    except OSError as error:
        raise _Unreadable(f"{package} could not be read: {error.strerror or error}") from error
    try:
        keys = json.loads(contents)
    except ValueError:
        keys = None
    if isinstance(keys, dict) and not any(key in keys for key in managers.package_keys):
        return found + [(ABSENT, PACKAGE)]
    return found + [(MANAGER, PACKAGE, hashlib.sha256(contents).hexdigest())]


def _matching(top: str, pattern: str, budget: _Budget) -> list[tuple[str, bool, str]]:
    """List the files a hook manager pattern matches in a working tree, a matched folder by every
    file under it. Takes the top of the working tree, the pattern and the count of files read.
    Returns each path relative to the top, whether it is a link, and its sha256 or target."""
    star = pattern.find("*")
    named_up_to = pattern if star < 0 else pattern[:star]
    base = named_up_to[:named_up_to.rfind("/")] if "/" in named_up_to else ""
    wanted = pattern[len(base) + 1:] if base else pattern
    folder = os.fsencode(os.path.join(top, base) if base else top)
    try:
        names = sorted(os.listdir(folder))
    except (FileNotFoundError, NotADirectoryError):
        return []
    except OSError as error:
        raise _Unreadable(f"{os.fsdecode(folder)} could not be read: {error.strerror or error}") from error
    found: list[tuple[str, bool, str]] = []
    for raw in names:
        name = raw.decode("utf-8", "replace")
        if _glob_matches(wanted, name):
            found += _read(os.path.join(folder, raw), f"{base}/{name}" if base else name, budget)
    return found


def _glob_matches(pattern: str, name: str) -> bool:
    """Say whether a name matches a pattern whose only wildcard is `*`, letters compared without
    regard to ASCII case. Takes the pattern and the name."""
    pattern, name = _ascii_lower(pattern), _ascii_lower(name)
    parts = pattern.split("*")
    if len(parts) == 1:
        return pattern == name
    if not name.startswith(parts[0]) or not name.endswith(parts[-1]) or len(name) < len(parts[0]) + len(parts[-1]):
        return False
    at = len(parts[0])
    for middle in parts[1:-1]:
        found = name.find(middle, at, len(name) - len(parts[-1]))
        if found < 0:
            return False
        at = found + len(middle)
    return True


def _ascii_lower(text: str) -> str:
    return "".join(char.lower() if char.isascii() else char for char in text)


def _saws_own_hook(rel: bytes) -> str | None:
    """Read the hook saw installs at a path in its own template. Takes the path relative to the
    hooks folder. Returns the sha256 of its bytes, or None."""
    folder = os.path.join(env.xdg_config_home(), *runs_directly.tables()["saws_own_hooks_folder"])
    path = os.path.join(os.fsencode(folder), rel)
    try:
        if os.path.islink(path) or not os.path.isfile(path):
            return None
        with open(path, "rb") as hook:
            return hashlib.sha256(hook.read()).hexdigest()
    except OSError:
        return None
