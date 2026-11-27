#!/usr/bin/env python3
"""Find what makes git run files from a working tree on its own: the folder git runs hooks from,
the files a hook manager runs or reads (`lib/data/git_hook_managers.json`), and settings whose value
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

from stayawake.lib.git import exec_keys, query
from stayawake.lib.git.run import UNTRUSTED, stdout, stdout_bytes
from stayawake.utils import pathsafe

MANAGERS_FILE = Path(__file__).resolve().parent.parent / "data" / "git_hook_managers.json"
_LARGEST_CONFIG = 1 << 20
_MOST_FOLLOWED = 500
_SEPARATORS = str.maketrans({char: " " for char in "\"'`,;:=()[]{}|&<>\t\r\n"})
_TOP_SPELLINGS = ("$(git rev-parse --show-toplevel)", "`git rev-parse --show-toplevel`", "${PWD}", "$PWD", "$(pwd)",
                  "`pwd`")
_GIT_DIR_SPELLINGS = ("$(git rev-parse --absolute-git-dir)", "$(git rev-parse --git-dir)", "`git rev-parse --git-dir`",
                      "${GIT_DIR}", "$GIT_DIR")
_OWN_FOLDER_SPELLINGS = ('$(dirname -- "$0")', '$(dirname "$0")', "$(dirname -- $0)", "$(dirname $0)",
                         '`dirname "$0"`', "`dirname $0`")
_HOME_SPELLINGS = ("${HOME}", "$HOME")
_NPM_SCRIPT_COMMANDS = frozenset({"test", "t", "start", "stop", "restart"})
_RUNNERS = frozenset({"npm", "yarn", "pnpm", "bun"})
_RUN_WORDS = frozenset({"run", "run-script", "rum", "urn"})
_SCRIPT_LISTS = frozenset({"pre-commit", "precommit"})
_MAKEFILE_NAMES = ("Makefile", "makefile", "GNUmakefile")
_FOLDER_KEYS = frozenset({"init.templatedir"})
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
    data = json.loads(path.read_text(encoding="utf-8")) or {}
    files = tuple(str(item) for item in data.get("files") or ())
    keys = tuple(str(key) for key in data.get("package_keys") or ())
    if not files or not keys:
        raise ValueError(f"{path}: hook manager files and package keys must both be listed")
    return HookManagers(files, keys)


def run_on_arrival(repo: Path, changed: tuple[str, ...], before: Callable[[str], "bytes | None"],
                   after: Callable[[str], "bytes | None"]) -> "tuple[str, ...] | None":
    """Pick the changed paths that git or a hook manager runs, or reads to decide what runs, on its
    own: files in the folder git runs hooks from, hook manager files, the files those name, the
    package.json script entries they run and the files those entries name, a Makefile they run,
    package.json's hook manager keys, and the files or folders the folder's configuration has git
    run or include. Takes the repository, the changed paths relative to its top, and readers of a
    path's bytes before and after the change, None for no file. Returns the paths picked, or None
    when git could not say where the folder's hooks run from or what it tracks."""
    folder, top, git_dir = query.hooks_folder(repo), _top(repo), _git_dir(repo)
    picked = query.hook_files(repo, changed)
    tracked = _tracked(repo)
    configured = configured_paths(repo)
    if None in (folder, top, git_dir, picked, tracked, configured):
        return None
    managers = hook_managers()
    moved = set(changed)
    known = tracked | moved

    def current(rel: str) -> "bytes | None":
        return after(rel) if rel in moved else before(rel)

    manager_files = {rel for rel in known if any(fnmatchcase(rel.casefold(), pattern.casefold())
                                                 for pattern in managers.files)}
    named, scripts = _named_by_hooks(top, git_dir, folder, manager_files, known, current, managers)
    found = list(picked)
    found += [rel for rel in changed if rel in manager_files or rel in named or _under(rel, configured)]
    if "package.json" in moved and (_package_keys_differ(before("package.json"), after("package.json"),
                                                         managers.package_keys)
                                    or _scripts_differ(before("package.json"), after("package.json"), scripts)):
        found.append("package.json")
    return tuple(dict.fromkeys(found))


def _named_by_hooks(top: Path, git_dir: Path, folder: Path, manager_files: set[str], known: set[str],
                    current: Callable[[str], "bytes | None"], managers: HookManagers) -> tuple[set[str], set[str]]:
    """Collect what the hooks and hook manager files run directly: the files they name, a Makefile
    they run, the package.json scripts they run and the files those scripts name. Takes the top of
    the working tree, the git directory, the hooks folder, the hook manager files, every tracked or
    changed path, a reader of a path's bytes as they will be, and the hook managers. Returns the
    files, and the names of the scripts."""
    texts: list[tuple[str, Path]] = []
    for hook in _hooks_in(folder):
        rel = _relative(top, hook)
        data = current(rel) if rel not in (None, ".") else pathsafe.read_regular_no_follow(hook, _LARGEST_CONFIG)
        if data:
            texts.append((_text(data), hook.parent))
    for rel in manager_files:
        data = current(rel)
        if data:
            texts.append((_text(data), (top / rel).parent))
    package = _package(current("package.json"))
    scripts: set[str] = set()
    for key in managers.package_keys:
        value = package.get(key)
        if key in _SCRIPT_LISTS and isinstance(value, (list, str)):
            scripts.update(name.strip() for name in (value if isinstance(value, list) else value.split(","))
                           if isinstance(name, str) and name.strip())
        elif value is not None:
            texts.append((json.dumps(value), top))
    named: set[str] = set()
    for text, beside in texts:
        words = _words(text, Places(top, git_dir, beside))
        named |= _resolved(words, Places(top, git_dir, beside)) & known
        named |= _makefiles(words, top) & known
        scripts |= _scripts_run(words)
    entries = package.get("scripts") if isinstance(package.get("scripts"), dict) else {}
    for name in scripts:
        if isinstance(entries.get(name), str):
            named |= _resolved(_words(entries[name], Places(top, git_dir, top)), Places(top, git_dir, top)) & known
    return named, scripts


@dataclass(frozen=True)
class Places:
    """Where the paths a text names resolve from: the top of the working tree, the git directory and
    the folder of the file the text came from."""

    top: Path
    git_dir: Path
    beside: Path


def _words(text: str, places: Places) -> list[str]:
    """Split a command or file text into words, with the spellings of the working tree's top, the
    git directory, the file's own folder and the home folder written out. Takes the text and the
    places. Returns the words."""
    for spellings, place in ((_TOP_SPELLINGS, places.top), (_GIT_DIR_SPELLINGS, places.git_dir),
                             (_OWN_FOLDER_SPELLINGS, places.beside), (_HOME_SPELLINGS, Path.home())):
        for spelling in spellings:
            text = text.replace(spelling, str(place))
    return text.translate(_SEPARATORS).split()


def _resolved(words: list[str], places: Places) -> set[str]:
    """Name each path the words may point to inside the working tree, from the top and from the
    file's own folder. Takes the words and the places. Returns the paths from the top, leaving out
    the git directory."""
    found: set[str] = set()
    for candidate in _candidates(words, places):
        rel = _in_the_tree(places.top, candidate)
        if rel is not None:
            found.add(rel)
    return found


def _candidates(words: list[str], places: Places) -> set[Path]:
    """Name each path the words may point to, from the top and from the file's own folder. Takes
    the words and the places. Returns the paths."""
    found: set[Path] = set()
    for word in words:
        if word.startswith("-") or "$" in word:
            continue
        path = Path(os.path.expanduser(word))
        found.update((path,) if path.is_absolute() else (places.beside / path, places.top / path))
    return found


def _in_the_tree(top: Path, path: Path) -> "str | None":
    """Name a path from the top of a working tree when it lies there, outside the git directory.
    Takes the top and the path. Returns the name, or None."""
    rel = _relative(top, path)
    return None if rel in (None, ".") or rel == ".git" or rel.startswith(".git" + os.sep) else rel


def _scripts_run(words: list[str]) -> set[str]:
    """Find the package.json scripts a command runs through npm, yarn, pnpm or bun. Takes its words.
    Returns the script names."""
    found: set[str] = set()
    for index, word in enumerate(words):
        following = words[index + 1:index + 3]
        if not following:
            continue
        if word == "npm" and following[0] in _NPM_SCRIPT_COMMANDS:
            found.add("test" if following[0] == "t" else following[0])
        elif word in _RUNNERS and following[0] in _RUN_WORDS and len(following) > 1:
            found.add(following[1])
        elif word in ("yarn", "pnpm") and not following[0].startswith("-") and following[0] not in _RUN_WORDS:
            found.add(following[0])
    return found


def _makefiles(words: list[str], top: Path) -> set[str]:
    """Name the Makefile a command's `make` reads. Takes its words and the top of the working
    tree. Returns the possible names from the top, empty for a command that runs no make."""
    found: set[str] = set()
    for index, word in enumerate(words):
        if word not in ("make", "gmake"):
            continue
        folder = "."
        following = words[index + 1:index + 3]
        if following[:1] in (["-C"], ["--directory"]) and len(following) > 1:
            folder = following[1]
        found |= {os.path.normpath(os.path.join(folder, name)) for name in _MAKEFILE_NAMES}
    return found


def _scripts_differ(before: "bytes | None", after: "bytes | None", scripts: set[str]) -> bool:
    """Tell whether any of the named package.json scripts differs between two versions. Takes both
    versions and the script names. Returns the answer."""
    def entries(data: "bytes | None") -> dict:
        found = _package(data).get("scripts")
        return found if isinstance(found, dict) else {}
    old, new = entries(before), entries(after)
    return any(old.get(name) != new.get(name) for name in scripts)


def _package(data: "bytes | None") -> dict:
    """Read package.json. Takes its bytes, None for no file. Returns its object, empty when it
    cannot be read."""
    if not data:
        return {}
    try:
        loaded = json.loads(data[:_LARGEST_CONFIG].decode("utf-8-sig"))
    except (ValueError, UnicodeDecodeError):
        return {}
    return loaded if isinstance(loaded, dict) else {}


def _hooks_in(folder: Path) -> list[Path]:
    """List the hook files in the folder git runs hooks from, leaving out samples. Takes the
    folder. Returns them."""
    try:
        found = (entry for entry in folder.rglob("*") if entry.is_file() and not entry.name.endswith(".sample"))
        return list(itertools.islice(found, _MOST_FOLLOWED))
    except OSError:
        return []


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
    git_dir = _git_dir(repo) or top / ".git"
    named = (_in_the_tree(top, path) for _text, path, _named_program in _named_paths(top, git_dir, settings))
    return {rel for rel in named if rel is not None}


def _under(rel: str, folders: set[str]) -> bool:
    """Tell whether a path is one of `folders` or inside one. Takes the path and the folders."""
    return any(folder == "." or rel == folder or rel.startswith(folder.rstrip("/") + "/") for folder in folders)


def _tracked(repo: Path) -> "set[str] | None":
    """List the paths the folder tracks. Takes the repository. Returns them, or None."""
    listed = stdout_bytes(repo, ["ls-files", "-z"], context=UNTRUSTED)
    return None if listed is None else {os.fsdecode(path) for path in listed.split(b"\0") if path}


def lies_in(top: Path, path: Path) -> bool:
    """Tell whether a path lies in a working tree, outside its git directory. Takes the top and the
    path. Returns the answer."""
    return _in_the_tree(top, path) is not None


def lies_in_any_working_tree(path: Path, top: "Path | None", where: Path) -> bool:
    """Tell whether a path lies in the command's own working tree or in any other, outside its git
    directory. Takes the path, the top of the command's working tree, None when it has none, and
    where the command runs. Returns the answer."""
    return (top is not None and lies_in(top, path)) or lies_in_a_working_tree(str(path), where)


def _git_dir(repo: Path) -> "Path | None":
    """Find a repository's git directory. Takes the repository. Returns it, or None."""
    found = stdout(repo, ["rev-parse", "--path-format=absolute", "--absolute-git-dir"], context=UNTRUSTED).strip()
    return Path(found) if found else None


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


def settings_running_working_tree_files(where: Path, top: "Path | None", settings,
                                        beside: "Path | None" = None) -> tuple[str, ...]:
    """Pick the settings that make git run a file or folder in a working tree, the command's own or
    any other: a hooks folder or template, a command naming a file there in any of its words, or an
    included configuration file there. Takes where the command runs, the top of its working tree,
    None when it has none, the (key, value) settings and the folder their relative paths start
    from, the top or else where the command runs when not given. Returns each picked one as
    `key=value`."""
    base = top or where
    git_dir = _git_dir(base) or base / ".git"
    named = _named_paths(base, git_dir, [(key, value, beside or base) for key, value in settings])
    return tuple(dict.fromkeys(text for text, path, named_program in named
                               if (named_program or os.path.lexists(path))
                               and lies_in_any_working_tree(path, top, where)))


def _named_paths(top: Path, git_dir: Path, settings) -> list[tuple[str, Path, bool]]:
    """Find the settings that name a file or folder for git to run, copy hooks from or include.
    Takes the top, the git directory and the (key, value, folder a relative path starts from)
    settings. Returns each as (`key=value`, the path, whether the path is the setting's own program
    or folder, False for a word handed to it)."""
    named = []
    for key, value, beside in settings:
        if value is None:
            continue
        lowered = key.lower()
        places = Places(top, git_dir, Path(beside))
        if lowered in _INCLUDES or (lowered.startswith("includeif.") and lowered.endswith(".path")):
            paths = [(path, True) for path in _candidates(_words(value, places), places)]
        elif lowered in _FOLDER_KEYS:
            paths = [(path, True) for path in _candidates(_words(value, places), Places(top, git_dir, top))]
        else:
            rule = exec_keys.rule_for(key)
            if rule is None:
                continue
            if rule.runs == exec_keys.HOOKS_DIRECTORY:
                paths = [(path, True) for path in _candidates(_words(value, places), Places(top, git_dir, top))]
            else:
                command = rule.command(key, value)
                words = _words(command, Places(top, git_dir, top)) if command else []
                program = [words[0]] if words and "/" in words[0] else []
                paths = [(path, True) for path in _candidates(program, Places(top, git_dir, top))]
                paths += [(path, False) for path in _candidates(words[1:], Places(top, git_dir, top))]
        named += [(f"{key}={value}", path, named_program) for path, named_program in paths]
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
    """Tell whether a folder is inside some git working tree, also through a repository with no
    working tree that lies among its files. Takes the folder, as named, and where the command runs.
    Returns the answer."""
    path = Path(os.path.expanduser(folder))
    path = path if path.is_absolute() else where / path
    probe = path if path.is_dir() else path.parent
    while not probe.is_dir() and probe != probe.parent:
        probe = probe.parent
    probe = Path(os.path.realpath(probe))
    while True:
        if stdout(probe, ["rev-parse", "--show-toplevel"], context=UNTRUSTED).strip():
            return True
        found = stdout(probe, ["rev-parse", "--path-format=absolute", "--absolute-git-dir"], context=UNTRUSTED).strip()
        above = Path(os.path.realpath(found)).parent if found else None
        if above is None or Path(found).name == ".git" or above not in probe.parents:
            return False
        probe = above


