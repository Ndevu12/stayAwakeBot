#!/usr/bin/env python3
"""Reads a git or gh command line and says what it does to a folder."""
from __future__ import annotations

import shlex
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from stayawake.lib.git import runs_directly, subcommand_options
from stayawake.lib.git.run import UNTRUSTED, stdout

GIT_AS_COMMANDS = {"--help": "help", "-h": "help", "--version": "version", "-v": "version"}
_MOST_ALIASES = 16

AliasReader = Callable[[Path, str], "str | None"]


@dataclass(frozen=True)
class Reading:
    """How a command line reads: the subcommand after aliases, its arguments and the folder it acts
    on, or why it could not be read."""

    readable: bool
    subcommand: str | None = None
    rest: tuple[str, ...] = ()
    folder: Path | None = None
    reason: str = ""


def _unreadable(reason: str) -> Reading:
    return Reading(False, reason=reason)


def configured_alias(folder: Path, name: str) -> str | None:
    """Return what an alias stands for in a folder's git configuration, or none. Takes the folder and
    the alias."""
    found = stdout(folder, ["config", "--get", f"alias.{name}"], context=UNTRUSTED).rstrip("\n")
    return found or None


def read(tool: str, args: list[str], folder: Path, alias_of: AliasReader = configured_alias) -> Reading:
    """Read a command line. Takes `git` or `gh`, the arguments without the program name, the folder
    it runs in and the reader of the folder's aliases. Returns the reading."""
    if tool == "gh":
        return _read_gh(list(args), Path(folder))
    if tool != "git":
        return _unreadable(f"{tool} is neither git nor gh")
    return _read_git(list(args), Path(folder), alias_of)


def _read_gh(args: list[str], folder: Path) -> Reading:
    repository_options = runs_directly.tables()["gh_repository_options"]
    words: list[str] = []
    index = 0
    while index < len(args) and len(words) < 2:
        arg = args[index]
        if arg in repository_options:
            index += 2
            continue
        if arg != "--" and not arg.startswith("-"):
            words.append(arg)
        index += 1
    return Reading(True, words[0] if words else None, tuple(args[1:]), folder)


def _alias_set_inline(pair: str) -> tuple[str, str] | None:
    key, _, value = pair.partition("=")
    section, _, name = key.partition(".")
    return (name.lower(), value) if section.lower() == "alias" and name else None


def _git_own_subcommands() -> frozenset[str]:
    """Return the git subcommands listed in saw's tables."""
    return frozenset(runs_directly.tables()["subcommands_that_bring_no_files"]) | frozenset(subcommand_options.LISTED)


def _read_git(args: list[str], folder: Path, alias_of: AliasReader) -> Reading:
    known = runs_directly.tables()
    inline: dict[str, str] = {}
    index = 0
    while index < len(args):
        arg = args[index]
        if not arg.startswith("-"):
            break
        if arg in GIT_AS_COMMANDS:
            return Reading(True, GIT_AS_COMMANDS[arg], tuple(args[index + 1:]), folder)
        if arg in known["global_queries"] or arg.startswith("--list-cmds="):
            return Reading(True, None, (), folder)
        if arg in known["global_flags"] or arg.startswith(known["global_options_with_a_joined_value"]):
            index += 1
            continue
        if arg not in known["global_options_with_a_value"]:
            return _unreadable(f"saw checks a command line with the option {arg} first")
        if index + 1 >= len(args):
            return _unreadable(f"{arg} is missing its value")
        value = args[index + 1]
        if arg == "-C" and value:
            folder = folder / value
        if arg == "-c" and value.partition("=")[0].lower().startswith("include"):
            return _unreadable(f"{arg} {value.partition('=')[0]} changes which commands are aliases")
        if arg == "-c" and _alias_set_inline(value):
            name, expansion = _alias_set_inline(value)
            inline[name] = expansion
        index += 2
    if index >= len(args):
        return Reading(True, None, (), folder)
    sub, rest = args[index], args[index + 1:]
    seen: set[str] = set()
    own = _git_own_subcommands()
    while sub not in own:
        expansion = inline.get(sub.lower()) if sub.lower() in inline else alias_of(folder, sub)
        if expansion is None:
            break
        if expansion.startswith("!"):
            return _unreadable(f"the alias {sub} runs a shell command")
        if sub in seen or len(seen) >= _MOST_ALIASES:
            return _unreadable(f"the alias {sub} expands into itself")
        seen.add(sub)
        try:
            words = shlex.split(expansion)
        except ValueError:
            return _unreadable(f"the alias {sub} could not be read")
        if not words or words[0].startswith("-"):
            return _unreadable(f"the alias {sub} could not be read")
        sub, rest = words[0], words[1:] + rest
    return Reading(True, sub, tuple(rest), folder)
