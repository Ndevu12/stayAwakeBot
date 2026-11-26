#!/usr/bin/env python3
"""Find what makes git run files from a working tree on its own: the folder git runs hooks from,
the files a hook manager runs or reads (`lib/data/git_hook_managers.yml`), and settings whose value
names a file or folder in the working tree."""
from __future__ import annotations

import functools
import json
import os
import shlex
from dataclasses import dataclass
from fnmatch import fnmatchcase
from pathlib import Path
from typing import Callable

import yaml

from stayawake.lib.git import exec_keys, query
from stayawake.lib.git.run import UNTRUSTED, stdout

MANAGERS_FILE = Path(__file__).resolve().parent.parent / "data" / "git_hook_managers.yml"
_LARGEST_CONFIG = 1 << 20
_MOST_NODES = 20000
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
    """What hook managers run or read: file patterns, files naming scripts under some keys, and the
    package.json keys they read."""

    files: tuple[str, ...]
    names_scripts: tuple[tuple[str, tuple[str, ...]], ...]
    package_keys: tuple[str, ...]


@functools.lru_cache(maxsize=None)
def hook_managers(path: Path = MANAGERS_FILE) -> HookManagers:
    """Load what hook managers run or read. Takes the file (default: the shipped list). Returns it;
    raises ValueError on a malformed file."""
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    files = tuple(str(item) for item in data.get("files") or ())
    named = tuple((str(item["file"]), tuple(str(key) for key in item["keys"]))
                  for item in data.get("names_scripts") or ())
    keys = tuple(str(key) for key in data.get("package_keys") or ())
    if not files or not all(named_file in files for named_file, _keys in named):
        raise ValueError(f"{path}: every file that names scripts must also be listed")
    return HookManagers(files, named, keys)


def run_on_arrival(repo: Path, changed: tuple[str, ...], before: Callable[[str], "bytes | None"],
                   after: Callable[[str], "bytes | None"]) -> "tuple[str, ...] | None":
    """Pick the changed paths that git, or a hook manager, runs or reads when git runs one of the
    folder's hooks. Takes the repository, the changed paths relative to its top, and readers of a
    path's bytes before and after the change, None for no file. Returns the paths picked, or None
    when git could not say where the folder's hooks run from."""
    picked = query.hook_files(repo, changed)
    if picked is None:
        return None
    managers = hook_managers()
    found = list(picked)
    found += [rel for rel in changed if any(fnmatchcase(rel.casefold(), pattern.casefold())
                                            for pattern in managers.files)]
    if "package.json" in changed and _package_keys_differ(before("package.json"), after("package.json"),
                                                          managers.package_keys):
        found.append("package.json")
    named = _named_scripts(managers, set(changed), before, after)
    found += [rel for rel in changed if os.path.normpath(rel) in named]
    return tuple(dict.fromkeys(found))


def _package_keys_differ(before: "bytes | None", after: "bytes | None", keys: tuple[str, ...]) -> bool:
    """Tell whether package.json's hook manager keys differ between two versions. Takes both
    versions, None for no file, and the keys. Returns the answer, True for a version that cannot be read."""
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


def _named_scripts(managers: HookManagers, changed: set[str], before: Callable[[str], "bytes | None"],
                   after: Callable[[str], "bytes | None"]) -> set[str]:
    """Collect the paths hook manager files name as scripts they run. Takes the hook managers, the
    changed paths and readers of a path's bytes before and after. Returns the paths, normalised."""
    named: set[str] = set()
    for config, keys in managers.names_scripts:
        data = after(config) if config in changed else before(config)
        if not data or len(data) > _LARGEST_CONFIG:
            continue
        try:
            loaded = yaml.safe_load(data)
        except yaml.YAMLError:
            continue
        for command in _values_under(loaded, frozenset(keys)):
            named.update(_paths_in(command, os.path.dirname(config)))
    return named


def _values_under(loaded, keys: frozenset[str]) -> list[str]:
    """Collect every string value under one of `keys`, at any depth. Takes the loaded document and
    the keys. Returns the values, stopping after a bounded number of nodes."""
    values: list[str] = []
    waiting = [loaded]
    seen = 0
    while waiting and seen < _MOST_NODES:
        node = waiting.pop()
        seen += 1
        if isinstance(node, dict):
            for key, value in node.items():
                if key in keys and isinstance(value, str):
                    values.append(value)
                else:
                    waiting.append(value)
        elif isinstance(node, list):
            waiting.extend(node)
    return values


def _paths_in(command: str, beside: str) -> set[str]:
    """Read the words of a command line that name files. Takes the command and the folder of the
    file it came from. Returns each word twice: a path from the top, and the word itself."""
    try:
        words = shlex.split(command, comments=True)
    except ValueError:
        words = command.split()
    paths: set[str] = set()
    for word in words:
        word = word.strip("'\"")
        if not word or word.startswith("-") or word.startswith("/"):
            continue
        paths.add(os.path.normpath(word))
        paths.add(os.path.normpath(os.path.join(beside, word)))
    return paths


def settings_running_folder_files(top: "Path | None", settings) -> tuple[str, ...]:
    """Pick the settings that make git run a file or folder in a working tree: a hooks folder, a
    command whose program is a file there, or an included configuration file there. Takes the top
    of the working tree, None when there is none, and the (key, value) settings. Returns each
    picked one as `key=value`."""
    if top is None:
        return ()
    picked = []
    for key, value in settings:
        if value is None:
            continue
        lowered = key.lower()
        if lowered in _INCLUDES or (lowered.startswith("includeif.") and lowered.endswith(".path")):
            candidate, runs_a_program = value, False
        else:
            rule = exec_keys.rule_for(key)
            if rule is None:
                continue
            if rule.runs == exec_keys.HOOKS_DIRECTORY:
                candidate, runs_a_program = value, False
            else:
                command = rule.command(key, value)
                words = shlex.split(command) if command else []
                if not words:
                    continue
                candidate, runs_a_program = words[0], True
        if runs_a_program and "/" not in candidate:
            continue
        if _inside(top, candidate):
            picked.append(f"{key}={value}")
    return tuple(picked)


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


def _inside(top: Path, named: str) -> bool:
    """Tell whether a path, relative ones taken from the top, lies in the working tree and outside
    its git directory. Takes the top and the path. Returns the answer."""
    path = Path(os.path.expanduser(named))
    path = path if path.is_absolute() else top / path
    resolved = os.path.realpath(path)
    root = os.path.realpath(top)
    inside = resolved == root or resolved.startswith(root.rstrip(os.sep) + os.sep)
    in_git = resolved.startswith(os.path.join(root, ".git") + os.sep) or resolved == os.path.join(root, ".git")
    return inside and not in_git
