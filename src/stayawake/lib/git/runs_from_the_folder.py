#!/usr/bin/env python3
"""Find what makes git run files from a working tree on its own: the folder git runs hooks from,
the files a hook manager runs or reads (`lib/data/git_hook_managers.yml`), and settings whose value
names a file or folder in the working tree."""
from __future__ import annotations

import functools
import itertools
import json
import os
import shlex
from dataclasses import dataclass
from fnmatch import fnmatchcase
from pathlib import Path
from typing import Callable

import yaml

from stayawake.lib.git import exec_keys, query
from stayawake.lib.git.run import UNTRUSTED, stdout, stdout_bytes
from stayawake.utils import pathsafe

MANAGERS_FILE = Path(__file__).resolve().parent.parent / "data" / "git_hook_managers.yml"
_LARGEST_CONFIG = 1 << 20
_MOST_FOLLOWED = 500
_FOLLOW_DEPTH = 4
_SEPARATORS = str.maketrans({char: " " for char in "\"'`,;:=()[]{}|&<>\t\r\n"})
_INCLUDES = ("include.path",)
_CONFIG_OPTIONS_WITH_A_VALUE = frozenset({"-f", "--file", "--blob", "--type", "--default", "--comment",
                                          "--value", "--url"})
_CONFIG_FLAGS = frozenset({"--add", "--replace-all", "--unset", "--unset-all", "--remove-section", "--local",
                           "--global", "--system", "--worktree", "--bool", "--int", "--bool-or-int", "--path",
                           "--expiry-date", "--null", "-z", "--show-origin", "--show-scope", "--name-only",
                           "--includes", "--no-includes", "--fixed-value", "--all", "--regexp", "--get",
                           "--get-all", "--get-regexp", "--get-urlmatch", "--get-color", "--get-colorbool",
                           "--list", "-l", "--no-type", "--no-value"})
_CONFIG_EDITS_BY_HAND = frozenset({"-e", "--edit", "--rename-section"})
_CONFIG_WORDS = frozenset({"set", "unset", "get", "list", "edit", "rename-section", "remove-section"})
_TEMPLATE_OPTION = "--template"
EDITS_BY_HAND = "the command edits git's configuration in a way that cannot be checked first"


@dataclass(frozen=True)
class HookManagers:
    """What hook managers run or read: file patterns, and the package.json keys they read."""

    files: tuple[str, ...]
    package_keys: tuple[str, ...]


@functools.lru_cache(maxsize=None)
def hook_managers(path: Path = MANAGERS_FILE) -> HookManagers:
    """Load what hook managers run or read. Takes the file (default: the shipped list). Returns it;
    raises ValueError on a malformed file."""
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    files = tuple(str(item) for item in data.get("files") or ())
    keys = tuple(str(key) for key in data.get("package_keys") or ())
    if not files or not keys:
        raise ValueError(f"{path}: hook manager files and package keys must both be listed")
    return HookManagers(files, keys)


def run_on_arrival(repo: Path, changed: tuple[str, ...], before: Callable[[str], "bytes | None"],
                   after: Callable[[str], "bytes | None"]) -> "tuple[str, ...] | None":
    """Pick the changed paths that git or a hook manager runs, or reads to decide what runs, on its
    own: files in the folder git runs hooks from, hook manager files, files any of those name and
    the files they name in turn, package.json's hook manager keys, and files or folders the folder's
    configuration has git run or include. Takes the repository, the changed paths relative to its
    top, and readers of a path's bytes before and after the change, None for no file. Returns the
    paths picked, or None when git could not say where the folder's hooks run from or what it
    tracks."""
    folder, top = query.hooks_folder(repo), _top(repo)
    picked = query.hook_files(repo, changed)
    tracked = _tracked(repo)
    configured = configured_paths(repo)
    if folder is None or top is None or picked is None or tracked is None or configured is None:
        return None
    managers = hook_managers()
    moved = set(changed)
    known = tracked | moved

    def current(rel: str) -> "bytes | None":
        return after(rel) if rel in moved else before(rel)

    manager_files = {rel for rel in known if any(fnmatchcase(rel.casefold(), pattern.casefold())
                                                 for pattern in managers.files)}
    named = _named_by_hooks(top, folder, manager_files, known, current, managers)
    found = list(picked)
    found += [rel for rel in changed if rel in manager_files or rel in named or _under(rel, configured)]
    if "package.json" in moved and _package_keys_differ(before("package.json"), after("package.json"),
                                                        managers.package_keys):
        found.append("package.json")
    return tuple(dict.fromkeys(found))


def _named_by_hooks(top: Path, folder: Path, manager_files: set[str], known: set[str],
                    current: Callable[[str], "bytes | None"], managers: HookManagers) -> set[str]:
    """Follow the files a hook or a hook manager file names, and the files those name, within a
    bound. Takes the top of the working tree, the hooks folder, the hook manager files, every
    tracked or changed path, a reader of a path's bytes as they will be, and the hook managers.
    Returns the paths reached."""
    waiting: list[tuple[str, str, int]] = []
    for hook in _hooks_in(folder):
        rel = _relative(top, hook)
        data = current(rel) if rel not in (None, ".") else pathsafe.read_regular_no_follow(hook, _LARGEST_CONFIG)
        if data:
            waiting.append((_text(data), os.path.dirname(rel) if rel else "", 0))
    for rel in manager_files:
        data = current(rel)
        if data:
            waiting.append((_text(data), os.path.dirname(rel), 0))
    package = current("package.json")
    if package:
        waiting.append((_package_hook_commands(package, managers.package_keys), "", 0))
    reached: set[str] = set()
    while waiting and len(reached) < _MOST_FOLLOWED:
        text, beside, depth = waiting.pop()
        for rel in _paths_in(text, beside) & known:
            if rel in reached:
                continue
            reached.add(rel)
            data = current(rel) if depth < _FOLLOW_DEPTH else None
            if data and len(data) <= _LARGEST_CONFIG:
                waiting.append((_text(data), os.path.dirname(rel), depth + 1))
    return reached


def _hooks_in(folder: Path) -> list[Path]:
    """List the hook files in the folder git runs hooks from, leaving out samples. Takes the
    folder. Returns them."""
    try:
        found = (entry for entry in folder.rglob("*") if entry.is_file() and not entry.name.endswith(".sample"))
        return list(itertools.islice(found, _MOST_FOLLOWED))
    except OSError:
        return []


def _package_hook_commands(data: bytes, keys: tuple[str, ...]) -> str:
    """Read the commands package.json's hook manager keys give, with each npm script they name.
    Takes package.json's bytes and the keys. Returns the commands as one text."""
    try:
        loaded = json.loads(data[:_LARGEST_CONFIG].decode("utf-8-sig"))
    except (ValueError, UnicodeDecodeError):
        return ""
    if not isinstance(loaded, dict):
        return ""
    text = " ".join(json.dumps(loaded[key]) for key in keys if key in loaded)
    scripts = loaded.get("scripts") if isinstance(loaded.get("scripts"), dict) else {}
    named = [scripts[word] for word in text.translate(_SEPARATORS).split()
             if isinstance(scripts.get(word), str)]
    return " ".join([text, *named])


def _package_keys_differ(before: "bytes | None", after: "bytes | None", keys: tuple[str, ...]) -> bool:
    """Tell whether package.json's hook manager keys differ between two versions. Takes both
    versions, None for no file, and the keys. Returns the answer, True for a version that cannot be
    read."""
    def read(data: "bytes | None") -> "dict | None":
        if data is None:
            return {}
        try:
            loaded = json.loads(data[:_LARGEST_CONFIG].decode("utf-8-sig"))
        except (ValueError, UnicodeDecodeError):
            return None
        return loaded if isinstance(loaded, dict) else {}
    old, new = read(before), read(after)
    if old is None or new is None:
        return True
    return any(old.get(key) != new.get(key) for key in keys)


def _paths_in(text: str, beside: str) -> set[str]:
    """Read the words of a text that may name files. Takes the text and the folder of the file it
    came from. Returns each word twice: a path from the top, and one from that folder."""
    paths: set[str] = set()
    for word in text.translate(_SEPARATORS).split():
        if not word or word.startswith(("-", "$", "/", "~")):
            continue
        paths.add(os.path.normpath(word))
        paths.add(os.path.normpath(os.path.join(beside, word)))
    return paths


def configured_paths(repo: Path) -> "set[str] | None":
    """List the files and folders in the working tree that the folder's own configuration, local,
    global or included, has git run or include. Takes the repository. Returns them relative to the
    top, or None when git could not list its configuration."""
    top = _top(repo)
    listed = stdout_bytes(repo, ["config", "--list", "--show-origin", "-z"], context=UNTRUSTED)
    if top is None or listed is None:
        return None
    fields = listed.split(b"\0")
    settings = []
    for origin, entry in zip(fields[0::2], fields[1::2]):
        key, _, value = os.fsdecode(entry).partition("\n")
        place = os.fsdecode(origin).removeprefix("file:")
        beside = (Path(repo) / place).parent if place and not place.startswith(("command line:", "blob:")) else top
        settings.append((key, value, beside))
    return {rel for _text, rel in _named_paths(top, settings)}


def _under(rel: str, folders: set[str]) -> bool:
    """Tell whether a path is one of `folders` or inside one. Takes the path and the folders."""
    return any(folder == "." or rel == folder or rel.startswith(folder.rstrip("/") + "/") for folder in folders)


def _tracked(repo: Path) -> "set[str] | None":
    """List the paths the folder tracks. Takes the repository. Returns them, or None."""
    listed = stdout_bytes(repo, ["ls-files", "-z"], context=UNTRUSTED)
    return None if listed is None else {os.fsdecode(path) for path in listed.split(b"\0") if path}


def _top(repo: Path) -> "Path | None":
    """Find the top of a repository's working tree. Takes the repository. Returns it, or None."""
    top = stdout(repo, ["rev-parse", "--show-toplevel"], context=UNTRUSTED).strip()
    return Path(top) if top else None


def _relative(top: Path, path: Path) -> "str | None":
    """Name a path from the top of the working tree. Takes the top and the path. Returns the name,
    or None for a path outside it."""
    resolved, root = os.path.realpath(path), os.path.realpath(top)
    inside = resolved == root or resolved.startswith(root.rstrip(os.sep) + os.sep)
    return os.path.relpath(resolved, root) if inside else None


def _text(data: bytes) -> str:
    """Decode a file's bytes for reading its words. Takes the bytes. Returns the text."""
    return data[:_LARGEST_CONFIG].decode("utf-8", errors="replace")


def settings_running_folder_files(top: "Path | None", settings) -> tuple[str, ...]:
    """Pick the settings that make git run a file or folder in a working tree: a hooks folder, a
    command whose program is a file there, or an included configuration file there. Takes the top
    of the working tree, None when there is none, and the (key, value) settings. Returns each
    picked one as `key=value`."""
    if top is None:
        return ()
    return tuple(text for text, _rel in _named_paths(top, [(key, value, top) for key, value in settings]))


def _named_paths(top: Path, settings) -> list[tuple[str, str]]:
    """Find the settings that name a file or folder in a working tree for git to run or include.
    Takes the top and the (key, value, folder a relative include starts from) settings. Returns
    each as (`key=value`, the path from the top)."""
    named = []
    for key, value, beside in settings:
        if value is None:
            continue
        lowered = key.lower()
        if lowered in _INCLUDES or (lowered.startswith("includeif.") and lowered.endswith(".path")):
            candidate, start = value, beside
        else:
            rule = exec_keys.rule_for(key)
            if rule is None:
                continue
            if rule.runs == exec_keys.HOOKS_DIRECTORY:
                candidate, start = value, top
            else:
                command = rule.command(key, value)
                try:
                    words = shlex.split(command) if command else []
                except ValueError:
                    words = command.split() if command else []
                if not words or "/" not in words[0]:
                    continue
                candidate, start = words[0], top
        path = Path(os.path.expanduser(candidate))
        rel = _relative(top, path if path.is_absolute() else Path(start) / path)
        if rel is not None and not (rel == ".git" or rel.startswith(".git" + os.sep)):
            named.append((f"{key}={value}", rel))
    return named


def config_settings(rest: tuple[str, ...]) -> "tuple[tuple[str, str | None], ...] | str":
    """Read the setting a `git config` command writes. Takes its arguments. Returns the (key, value)
    it sets, none for one that only reads or removes, or a sentence when it changes configuration in
    a way saw cannot read."""
    words: list[str] = []
    index = 0
    while index < len(rest):
        arg = rest[index]
        index += 1
        if arg == "--":
            words += list(rest[index:])
            break
        if not arg.startswith("-") or arg == "-":
            words.append(arg)
            continue
        name = arg.partition("=")[0]
        if name in _CONFIG_EDITS_BY_HAND:
            return EDITS_BY_HAND
        if name in _CONFIG_OPTIONS_WITH_A_VALUE:
            index += 0 if "=" in arg else 1
            continue
        if name not in _CONFIG_FLAGS:
            return EDITS_BY_HAND
    if words and words[0] in _CONFIG_WORDS:
        if words[0] in ("edit", "rename-section"):
            return EDITS_BY_HAND
        words = words[1:]
    if len(words) >= 2:
        return ((words[0], words[1]),)
    return ()


def template_named(rest: tuple[str, ...], template_variable: str, settings) -> str:
    """Find the template folder a `git init` copies from, when the command names one. Takes its
    arguments, the template variable's value and the settings. Returns the folder, or "" when none
    is named."""
    named = template_variable
    for key, value in settings:
        if key.lower() == "init.templatedir" and value:
            named = value
    index = 0
    while index < len(rest):
        arg = rest[index]
        index += 1
        name, joined, value = arg.partition("=")
        if len(name) > 3 and _TEMPLATE_OPTION.startswith(name):
            named = value if joined else (rest[index] if index < len(rest) else "")
            index += 0 if joined else 1
    return named


def lies_in_a_working_tree(folder: str, where: Path) -> bool:
    """Tell whether a folder is inside some git working tree. Takes the folder, as named, and where
    the command runs. Returns the answer."""
    path = Path(os.path.expanduser(folder))
    path = path if path.is_absolute() else where / path
    probe = path if path.is_dir() else path.parent
    while not probe.is_dir() and probe != probe.parent:
        probe = probe.parent
    return bool(stdout(probe, ["rev-parse", "--show-toplevel"], context=UNTRUSTED).strip())


