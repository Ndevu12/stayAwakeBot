#!/usr/bin/env python3
"""A git command the way the operator typed it: git's own options, the settings its command line and
environment give, the variables that name its repository, and the subcommand with its arguments."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping, MutableMapping

from stayawake.lib.git import subcommand_options

LOCATION_VARIABLES = ("GIT_DIR", "GIT_WORK_TREE", "GIT_INDEX_FILE", "GIT_OBJECT_DIRECTORY",
                      "GIT_ALTERNATE_OBJECT_DIRECTORIES", "GIT_COMMON_DIR", "GIT_NAMESPACE",
                      "GIT_CEILING_DIRECTORIES", "GIT_DISCOVERY_ACROSS_FILESYSTEM")
_SETTINGS_VARIABLES = ("GIT_CONFIG_PARAMETERS", "GIT_CONFIG_COUNT")
_NUMBERED_SETTINGS = ("GIT_CONFIG_KEY_", "GIT_CONFIG_VALUE_")
TEMPLATE_VARIABLE = "GIT_TEMPLATE_DIR"
_OPTIONS_NAMING_THE_REPOSITORY = ("--git-dir", "--work-tree")
_OPTIONS_WITH_A_VALUE = ("-C", "-c", "--git-dir", "--work-tree", "--namespace", "--config-env",
                         "--super-prefix", "--attr-source", "--shallow-file", "--exec-path")
_KEPT_FLAGS = frozenset({"--no-replace-objects", "--no-lazy-fetch", "--no-optional-locks", "--no-advice",
                         "--literal-pathspecs", "--no-literal-pathspecs", "--glob-pathspecs",
                         "--noglob-pathspecs", "--icase-pathspecs"})
_DROPPED_FLAGS = frozenset({"-p", "--paginate", "-P", "--no-pager"})
_PRINTS_AND_STOPS = frozenset({"-h", "--help", "-v", "--version", "--exec-path", "--html-path",
                               "--man-path", "--info-path"})
NOT_READ = "how git would run this command cannot be checked"


@dataclass(frozen=True)
class TypedCommand:
    """A git command read through git's own options. `sub` and `rest` are the subcommand and its
    arguments. `git_dir` and `work_tree` are what `--git-dir` and `--work-tree` name, unchanged, and
    `bare` says `--bare` was given. `flags` are git's own options a replay keeps. `settings` are the
    (key, value) pairs the environment and `-c` give, in the order git reads them, a value of None
    standing for a key given without `=`. `locations` are the variables that name the repository,
    and `template` the folder `GIT_TEMPLATE_DIR` names."""

    sub: str
    rest: tuple[str, ...]
    git_dir: str = ""
    work_tree: str = ""
    namespace: str = ""
    bare: bool = False
    flags: tuple[str, ...] = ()
    settings: tuple[tuple[str, "str | None"], ...] = ()
    locations: tuple[tuple[str, str], ...] = ()
    template: str = ""

    @property
    def names_its_repository(self) -> bool:
        """Tell whether the command names its repository, index or objects itself."""
        named = {name for name, _value in self.locations} - {"GIT_NAMESPACE", "GIT_CEILING_DIRECTORIES",
                                                               "GIT_DISCOVERY_ACROSS_FILESYSTEM"}
        return bool(self.git_dir or self.work_tree or self.bare or named)

    def location_options(self) -> list[str]:
        """List the options that name the command's repository, in git's own spelling."""
        options = [f"--git-dir={self.git_dir}"] if self.git_dir else []
        options += [f"--work-tree={self.work_tree}"] if self.work_tree else []
        return options + (["--bare"] if self.bare else [])


def take_environment(environ: MutableMapping[str, str]) -> dict[str, str]:
    """Move the variables that name a command's repository, give it settings or name its template
    out of an environment. Takes the environment, usually this process's own. Returns them."""
    taken = {}
    for name in list(environ):
        if (name in LOCATION_VARIABLES or name in _SETTINGS_VARIABLES or name == TEMPLATE_VARIABLE
                or name.startswith(_NUMBERED_SETTINGS)):
            taken[name] = environ.pop(name)
    return taken


def read(args: list[str], environment: "Mapping[str, str] | None" = None) -> "TypedCommand | str":
    """Read a git command line through git's own options and its environment. Takes the arguments
    without the program name and the command's environment. Returns the command, or a sentence when
    git would not reach a subcommand saw can read, or its settings cannot be read."""
    environment = dict(environment or {})
    settings = _environment_settings(environment)
    if settings is None:
        return NOT_READ
    git_dir = work_tree = namespace = ""
    bare = False
    flags: list[str] = []
    index = 0
    while index < len(args):
        arg = args[index]
        if not arg.startswith("-"):
            locations = tuple((name, environment[name]) for name in LOCATION_VARIABLES if environment.get(name))
            namespace = namespace or environment.get("GIT_NAMESPACE", "")
            return TypedCommand(arg, tuple(args[index + 1:]), git_dir, work_tree, namespace, bare, tuple(flags),
                                tuple(settings), locations, environment.get(TEMPLATE_VARIABLE, ""))
        name, joined, value = arg.partition("=")
        if arg in _PRINTS_AND_STOPS or name in ("--super-prefix", "--attr-source", "--shallow-file",
                                                "--config-env", "--exec-path", "--list-cmds"):
            return NOT_READ
        if arg in _KEPT_FLAGS:
            flags.append(arg)
            index += 1
            continue
        if arg in _DROPPED_FLAGS:
            index += 1
            continue
        if arg == "--bare":
            bare = True
            index += 1
            continue
        if name not in _OPTIONS_WITH_A_VALUE:
            return NOT_READ
        if not joined:
            if index + 1 >= len(args) or name not in ("-C", "-c", "--git-dir", "--work-tree", "--namespace"):
                return NOT_READ
            value = args[index + 1]
            index += 2
        else:
            index += 1
        if name == "-C":
            continue
        if name == "-c":
            key, has_value, setting = value.partition("=")
            if not key:
                return NOT_READ
            settings.append((key, setting if has_value else None))
        elif name == "--git-dir":
            git_dir = value
        elif name == "--work-tree":
            work_tree = value
        elif name == "--namespace":
            namespace = value
    return NOT_READ


def _environment_settings(environment: dict[str, str]) -> "list[tuple[str, str | None]] | None":
    """Read the settings a command's environment gives git. Takes the environment. Returns them in
    the order git reads them, or None when one cannot be read."""
    settings: list[tuple[str, str | None]] = []
    parameters = environment.get("GIT_CONFIG_PARAMETERS")
    if parameters:
        read_parameters = _quoted_settings(parameters)
        if read_parameters is None:
            return None
        settings += read_parameters
    count = environment.get("GIT_CONFIG_COUNT")
    if count:
        if not count.isdigit():
            return None
        for number in range(int(count)):
            key = environment.get(f"GIT_CONFIG_KEY_{number}")
            value = environment.get(f"GIT_CONFIG_VALUE_{number}")
            if not key or value is None:
                return None
            settings.append((key, value))
    return settings


def _quoted_settings(text: str) -> "list[tuple[str, str | None]] | None":
    """Read `GIT_CONFIG_PARAMETERS`: quoted `'key'='value'` or `'key=value'` items. Takes its value.
    Returns the settings, or None for a value git did not write."""
    settings: list[tuple[str, str | None]] = []
    index = 0
    while index < len(text):
        if text[index] == " ":
            index += 1
            continue
        first, index = _quoted(text, index)
        if first is None:
            return None
        if text.startswith("=", index):
            second, index = _quoted(text, index + 1)
            if second is None:
                return None
            settings.append((first, second))
        else:
            key, has_value, value = first.partition("=")
            settings.append((key, value if has_value else None))
    return settings


def _quoted(text: str, index: int) -> "tuple[str | None, int]":
    """Read one word quoted the way git quotes it, from `index`. Takes the text and where the word
    starts. Returns the word and where it ends, or None for a word quoted another way."""
    parts: list[str] = []
    while index < len(text) and text[index] == "'":
        end = text.find("'", index + 1)
        if end < 0:
            return None, index
        parts.append(text[index + 1:end])
        index = end + 1
        if text.startswith(("\\'", "\\!"), index):
            parts.append(text[index + 1])
            index += 2
            continue
        return "".join(parts), index
    return None, index


def folder_it_creates(command: TypedCommand) -> "str | None":
    """Find the folder a clone or a `worktree add` creates, named the way git names it. Takes the
    command. Returns the folder relative to where git runs, or None for a command that creates none,
    or whose folder cannot be told."""
    rest = list(command.rest)
    if command.sub == "worktree" and rest[:1] == ["add"]:
        words = subcommand_options.read("worktree add", rest[1:]).words
        return words[0] if words else None
    if command.sub != "clone":
        return None
    reading = subcommand_options.read("clone", rest)
    words = list(reading.words) + list(reading.paths)
    if len(words) >= 2:
        return words[1]
    if not words:
        return None
    name = words[0].rstrip("/")
    name = name[:-len("/.git")] if name.endswith("/.git") else name
    name = name.replace(":", "/").rsplit("/", 1)[-1]
    for suffix in (".git", ".bundle"):
        name = name[:-len(suffix)] if name.endswith(suffix) else name
    bare = reading.last("--bare", "--no-bare", "--mirror", "--no-mirror") in ("--bare", "--mirror")
    return (name + ".git" if bare else name) or None
