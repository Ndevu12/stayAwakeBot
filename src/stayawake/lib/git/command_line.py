#!/usr/bin/env python3
"""Reads a git or gh command line and says what it does to a folder."""
from __future__ import annotations

import shlex
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from stayawake.lib.git import subcommand_options
from stayawake.lib.git.run import UNTRUSTED, stdout

GIT_FLAGS = frozenset({
    "-p", "--paginate", "-P", "--no-pager", "--no-replace-objects", "--no-lazy-fetch", "--bare",
    "--literal-pathspecs", "--no-literal-pathspecs", "--glob-pathspecs", "--noglob-pathspecs",
    "--icase-pathspecs", "--no-optional-locks", "--no-advice",
})
GIT_VALUED = frozenset({"-C", "-c", "--git-dir", "--work-tree", "--namespace", "--config-env",
                        "--shallow-file", "--attr-source"})
GIT_VALUED_JOINED = ("--git-dir=", "--work-tree=", "--namespace=", "--config-env=", "--attr-source=",
                     "--exec-path=")
GIT_QUERIES = frozenset({"--exec-path", "--html-path", "--man-path", "--info-path"})
GIT_AS_COMMANDS = {"--help": "help", "-h": "help", "--version": "version", "-v": "version"}
BRINGING = frozenset({"pull", "merge", "rebase", "fetch", "checkout", "switch", "submodule"})
GH_INBOUND = frozenset({("pr", "checkout"), ("repo", "sync"), ("release", "download"), ("run", "download")})
GH_VALUED = frozenset({"-R", "--repo"})
_MOST_ALIASES = 16

AliasReader = Callable[[Path, str], "str | None"]


@dataclass(frozen=True)
class Reading:
    """What a command line does to a folder."""

    readable: bool
    subcommand: str | None = None
    rest: tuple[str, ...] = ()
    folder: Path | None = None
    kind: str | None = None
    reason: str = ""

    @property
    def brings_files(self) -> bool:
        """Tell whether the command brings files into the folder."""
        return self.kind is not None


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
    words: list[str] = []
    index = 0
    while index < len(args) and len(words) < 2:
        arg = args[index]
        if arg in GH_VALUED:
            index += 2
            continue
        if arg != "--" and not arg.startswith("-"):
            words.append(arg)
        index += 1
    kind = "gh" if tuple(words) in GH_INBOUND else None
    return Reading(True, words[0] if words else None, tuple(args[1:]), folder, kind)


def _alias_set_inline(pair: str) -> tuple[str, str] | None:
    key, _, value = pair.partition("=")
    section, _, name = key.partition(".")
    return (name.lower(), value) if section.lower() == "alias" and name else None


def _sets_aliases_elsewhere(option: str, value: str) -> bool:
    key = value.partition("=")[0].lower()
    return key.startswith("include") or (option == "--config-env" and key.startswith("alias."))


def _read_git(args: list[str], folder: Path, alias_of: AliasReader) -> Reading:
    names_repository = False
    inline: dict[str, str] = {}
    index = 0
    while index < len(args):
        arg = args[index]
        if not arg.startswith("-"):
            break
        if arg in GIT_AS_COMMANDS:
            return Reading(True, GIT_AS_COMMANDS[arg], tuple(args[index + 1:]), folder)
        if arg in GIT_QUERIES or arg.startswith("--list-cmds="):
            return Reading(True, None, (), folder)
        if arg in GIT_FLAGS:
            index += 1
            continue
        if arg in GIT_VALUED:
            if index + 1 >= len(args):
                return _unreadable(f"{arg} is missing its value")
            value = args[index + 1]
            if arg == "-C" and value:
                folder = folder / value
            if arg in ("-c", "--config-env") and _sets_aliases_elsewhere(arg, value):
                return _unreadable(f"{arg} {value.partition('=')[0]} changes which commands are aliases")
            if arg == "-c" and _alias_set_inline(value):
                name, expansion = _alias_set_inline(value)
                inline[name] = expansion
            names_repository = names_repository or arg in ("--git-dir", "--work-tree")
            index += 2
            continue
        if arg.startswith("--config-env=") and _sets_aliases_elsewhere("--config-env", arg.partition("=")[2]):
            return _unreadable("--config-env changes which commands are aliases")
        if arg.startswith(GIT_VALUED_JOINED):
            names_repository = names_repository or arg.startswith(("--git-dir=", "--work-tree="))
            index += 1
            continue
        return _unreadable(f"git does not know the option {arg}")
    if index >= len(args):
        return Reading(True, None, (), folder)
    sub, rest = args[index], args[index + 1:]
    seen: set[str] = set()
    while sub not in BRINGING:
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
    kind = git_kind(sub, rest)
    if kind is not None and names_repository:
        return _unreadable("the command names its own repository")
    return Reading(True, sub, tuple(rest), folder, kind)


def git_kind(sub: str, rest: list[str]) -> str | None:
    """Return the kind of files-bringing command a git subcommand is, or none. Takes the subcommand
    and its arguments, read with git's options for that subcommand."""
    if {"--abort", "--quit", "--dry-run"} & set(subcommand_options.read(sub, list(rest)).names()):
        return None
    if sub in {"pull", "merge", "rebase", "fetch"}:
        return sub
    if sub == "submodule" and positionals(sub, rest)[:1] == ["update"]:
        return sub
    if sub == "checkout" and checkout_brings(rest):
        return sub
    if sub == "switch" and switch_brings(rest):
        return sub
    return None


def positionals(sub: str, args: list[str]) -> list[str]:
    """Return a subcommand's words before `--`, read with git's options for it. Takes the
    subcommand and its arguments."""
    return list(subcommand_options.read(sub, list(args)).words)


def checkout_brings(args: list[str]) -> bool:
    """Tell whether a checkout moves the folder to another commit. Takes its arguments."""
    if "--orphan" in subcommand_options.read("checkout", list(args)).names():
        return False
    return len(positionals("checkout", args)) > 0


def switch_brings(args: list[str]) -> bool:
    """Tell whether a switch moves the folder to another commit. Takes its arguments."""
    if "--orphan" in subcommand_options.read("switch", list(args)).names():
        return False
    return len(positionals("switch", args)) > 0
