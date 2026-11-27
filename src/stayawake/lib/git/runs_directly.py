#!/usr/bin/env python3
"""Decide, as saw's git stand-in decides, whether a git or gh command runs as typed or goes to saw
first. The tables are read from `lib/data/git_runs_directly.json`, which is built into the stand-in."""
from __future__ import annotations

import functools
import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Mapping

from stayawake.lib.git import subcommand_options
from stayawake.lib.git.run import UNTRUSTED, run

TABLES_FILE = Path(__file__).resolve().parent.parent / "data" / "git_runs_directly.json"
RUNS_AS_TYPED = "runs-as-typed"
CHECKED = "checked"
CHECKED_FOR_WHAT_IT_NAMES = "checked-for-what-it-names"
RUNS_A_PROGRAM = "runs-a-program"
WRITES_A_FILE = "writes-a-file"
FETCHES = "fetches"
NOT_READ = "gives-an-option-git-does-not-take"
_PUSH_REWRITES = r"^url\..*\.pushinsteadof$"


@functools.lru_cache(maxsize=1)
def tables() -> dict[str, tuple[str, ...]]:
    """Return the stand-in's tables by name."""
    return {name: tuple(words) for name, words in json.loads(TABLES_FILE.read_text(encoding="utf-8")).items()}


@dataclass
class _Line:
    """A git command line read through git's global options."""

    subcommand: int | None = None
    folders: list[str] = field(default_factory=list)
    read: bool = True
    settings: list[str] = field(default_factory=list)
    names_a_work_tree: bool = False


def decide(tool: str, args: list[str], folder: Path, environ: Mapping[str, str] | None = None) -> str:
    """Decide what the stand-in does with a command. Takes `git` or `gh`, the arguments without the
    program name, the folder it runs in and its environment, this process's when None. Returns
    RUNS_AS_TYPED, CHECKED or CHECKED_FOR_WHAT_IT_NAMES."""
    environ = os.environ if environ is None else environ
    if tool == "gh":
        return CHECKED if gh_brings_files(list(args)) else RUNS_AS_TYPED
    if tool != "git":
        return RUNS_AS_TYPED
    return _git_decision(list(args), Path(folder), environ)


def _git_decision(args: list[str], folder: Path, environ: Mapping[str, str]) -> str:
    line = _read_line(args)
    if not line.read:
        return CHECKED
    if line.subcommand is None:
        return RUNS_AS_TYPED
    sub = args[line.subcommand]
    if (sub not in tables()["subcommands_that_bring_no_files"] or line.names_a_work_tree
            or "GIT_WORK_TREE" in environ):
        return CHECKED
    target = folder
    for path in line.folders:
        if path:
            target = target / path
    if _names_what_saw_checks(sub, args[line.subcommand + 1:], line.settings, folder, target, environ):
        return CHECKED_FOR_WHAT_IT_NAMES
    return RUNS_AS_TYPED


def _read_line(args: list[str]) -> _Line:
    """Read git's global options up to the subcommand. Takes the arguments. Returns the reading,
    which stops at the first option the stand-in cannot read."""
    known = tables()
    line = _Line()
    index = 0
    while index < len(args):
        arg = args[index]
        if not arg.startswith("-"):
            line.subcommand = index
            return line
        if arg in known["global_queries"] or arg.startswith("--list-cmds="):
            return line
        if arg == "--work-tree" or arg.startswith("--work-tree="):
            line.names_a_work_tree = True
        if arg in known["global_flags"] or arg.startswith(known["global_options_with_a_joined_value"]):
            index += 1
            continue
        if arg not in known["global_options_with_a_value"] or index + 1 >= len(args):
            line.read = False
            return line
        value = args[index + 1]
        if arg == "-c" and _names_commands(value):
            line.read = False
            return line
        if arg == "-C":
            line.folders.append(value)
        if arg == "-c":
            line.settings.append(value.split("=")[0])
        index += 2
    return line


def _names_commands(setting: str) -> bool:
    """Tell whether a `-c <name>=<value>` sets a key in a section that changes which commands git
    runs. Takes the setting."""
    section = setting.replace("=", ".").split(".")[0].lower()
    return section in tables()["sections_that_name_commands"]


def _names_what_saw_checks(sub: str, rest: list[str], settings: list[str], here: Path, target: Path,
                           environ: Mapping[str, str]) -> bool:
    """Tell whether a command that brings no files names a setting that may run something, an output
    file, a program, an option git does not take, a hooks template, a configuration change or a
    fetch. Takes the subcommand, its arguments, the settings the line gives, the folder it runs in,
    the folder it acts on and the environment."""
    known = tables()

    def runs_something(key: str) -> bool:
        key = key.lower()
        return not (key in known["settings_that_run_nothing"]
                    or key.split(".")[0] in known["sections_that_run_nothing"])
    if any(runs_something(key) for key in settings) or any(name in environ for name in known["settings_variables"]):
        return True
    every = list(rest)
    options = rest[:rest.index("--")] if "--" in rest else list(rest)
    words = [arg for arg in options if not arg.startswith("-")]
    if named_anywhere(sub, every) is not None:
        return True
    if sub in ("init", "maintenance"):
        return True
    resolved = subcommand_options.resolve(sub, every)
    if sub in ("push", "ls-remote"):
        return resolved is None or _reaches_this_machine(sub, resolved, here, target)
    if sub == "config":
        return not _config_only_reads(every, words)
    if sub == "remote":
        return resolved is None or resolved.words[:1] == ("update",)
    return False


def named_by_its_options(sub: str, args: list[str]) -> str | None:
    """Name what a subcommand's options, read the way git reads them up to `--`, have git do that
    saw checks: run a program one names, write a file one names, fetch, or none git takes. A value in
    the next word that may itself name such an option counts as one. Takes the subcommand and its
    arguments. Returns RUNS_A_PROGRAM, WRITES_A_FILE, FETCHES, NOT_READ, also for a subcommand off the
    direct-run list,
    or None for a subcommand read by its own rule and for options that name neither."""
    if sub in tables()["subcommands_read_by_their_own_rule"]:
        return None
    if sub not in tables()["subcommands_that_bring_no_files"]:
        return NOT_READ
    checked = subcommand_options.options_saw_checks(sub)
    resolved = subcommand_options.resolve(sub, args)
    if resolved is None:
        written = args[:args.index("--")] if "--" in args else args
        return _first_named(written, checked) or NOT_READ
    for option in resolved.options:
        named = _first_named([option.value] if option.value_is_the_next_word and option.value else [], checked)
        for kind, names in zip(_KINDS, checked):
            if option.name in names:
                return kind
        if named:
            return named
    return None


def named_anywhere(sub: str, args: list[str]) -> str | None:
    """Name what a subcommand's arguments may have git do that saw checks: any argument, a value,
    `--` and the words after it included, that is or begins an option that runs a program, writes a
    file or fetches, then what its options name read the way git reads them. Takes the subcommand
    and its arguments. Returns RUNS_A_PROGRAM, WRITES_A_FILE, FETCHES, NOT_READ or None."""
    return _first_named(args, subcommand_options.options_saw_checks(sub)) or named_by_its_options(sub, args)


_KINDS = (RUNS_A_PROGRAM, WRITES_A_FILE, FETCHES)


def _first_named(args: list[str], checked: tuple[frozenset[str], ...]) -> str | None:
    """Name the first argument that may name an option that runs a program, writes a file or
    fetches. Takes the arguments and those three sets of options. Returns RUNS_A_PROGRAM,
    WRITES_A_FILE, FETCHES or None."""
    for arg in args:
        for kind, names in zip(_KINDS, checked):
            if _may_name(arg, names):
                return kind
    return None


def _may_name(arg: str, names: frozenset[str]) -> bool:
    """Tell whether an argument may name one of the options: a long option that is, or is the
    leading part of, one, or a bundle of short options holding one. Takes the argument and the
    options."""
    if arg.startswith("--"):
        written = arg.partition("=")[0]
        return len(written) > 2 and any(name.startswith(written) for name in names if name.startswith("--"))
    return arg.startswith("-") and any(name[1] in arg[1:] for name in names if not name.startswith("--"))


def _reaches_this_machine(sub: str, resolved: subcommand_options.Resolved, here: Path, target: Path) -> bool:
    """Tell whether a push or ls-remote may reach a repository on this machine or a program: a word
    that is a folder here, or any address git names for it that is not a network address. Takes the
    subcommand, its reading, the folder it runs in and the folder it acts on."""
    if any((here / word).is_dir() for word in resolved.words[:1]):
        return True
    addresses = destinations(sub, resolved, target)
    return addresses is None or not all(is_network_address(address) for address in addresses)


def destinations(sub: str, resolved: subcommand_options.Resolved, folder: Path) -> "list[str] | None":
    """List the addresses a push or ls-remote reaches, asked of git: each repository the reading
    names, or with none the remote git would use, through that remote's addresses. Takes the
    subcommand, its reading and the folder it acts on. Returns the addresses, or None when git
    names none or cannot answer."""
    pushes = sub == "push"
    named = [*resolved.values("--repo"), *resolved.words[:1]] if pushes else list(resolved.words[:1])
    if not named:
        branch = _git_lines(folder, ["symbolic-ref", "--short", "-q", "HEAD"])
        asked = "--format=%(push:remotename)" if pushes else "--format=%(upstream:remotename)"
        named = _git_lines(folder, ["for-each-ref", asked, f"refs/heads/{branch[0]}"]) if branch else None
        if not named:
            return None
    addresses: list[str] = []
    for repository in named:
        if pushes:
            configured = _git_lines(folder, ["remote", "get-url", "--push", "--all", repository])
            if configured:
                addresses += configured
                continue
            if _git_lines(folder, ["config", "--get-regexp", _PUSH_REWRITES]):
                return None
        given = _git_lines(folder, ["ls-remote", "--get-url", repository])
        if not given:
            return None
        addresses += [*given, *([repository] if pushes else [])]
    return addresses


def _git_lines(folder: Path, args: list[str]) -> "list[str] | None":
    """Ask git a question in the folder and read its answer. Takes the folder and git's arguments.
    Returns the answer's lines, None for no answer."""
    done = run(folder, args, context=UNTRUSTED)
    if done is None or done.returncode != 0:
        return None
    return [line for line in (done.stdout or "").splitlines() if line.strip()] or None


def is_network_address(address: str) -> bool:
    """Tell whether git reaches an address over the network: an `http://`, `https://`, `ssh://` or
    `git://` address, or `[user@]host:path` with no `::` or `://`, no `/` or `\\` before the first
    `:` and no drive letter. Every other address, a remote helper's `<transport>::` form and `file://` among
    them, is not. Takes the address."""
    if address.startswith(("http://", "https://", "ssh://", "git://")):
        return "::" not in address
    host, colon, _path = address.partition(":")
    drive = len(host) == 1 and host.isascii() and host.isalpha()
    return (bool(colon) and "::" not in address and "://" not in address and bool(host) and not drive
            and not host.startswith("-") and "/" not in host and "\\" not in host)


def _config_only_reads(options: list[str], words: list[str]) -> bool:
    """Tell whether a `git config` command only reads. Takes its options and words."""
    known = tables()
    named = [_config_option(arg) for arg in options if arg.startswith("--")]
    if any(option is None or option in known["config_writes"] for option in named) or "-e" in options:
        return False
    return (any(option in known["config_reads"] for option in named) or "-l" in options
            or words[:1] in (["get"], ["list"])
            or (len(words) == 1 and words[0] not in ("set", "unset", "edit", "rename-section", "remove-section")))


def _config_option(arg: str) -> str | None:
    """Name the `git config` long option an argument names, in full: itself, the option its `--no-`
    form turns off, or the one option it abbreviates. Takes the argument. Returns none for an
    argument naming no listed option, or several."""
    known = tables()
    written = arg.split("=")[0]
    name = written[len("--no-"):] if written.startswith("--no-") else written[2:]
    listed = (*known["config_reads"], *known["config_writes"], *known["config_other_options"])
    for option in listed:
        if option[2:] == name:
            return option
    abbreviated = [option for option in listed if name and option[2:].startswith(name)]
    return abbreviated[0] if len(abbreviated) == 1 else None


def gh_brings_files(args: list[str]) -> bool:
    """Tell whether a gh command brings files into the folder it runs in. Takes its arguments."""
    known = tables()
    given = args[:args.index("--")] if "--" in args else list(args)
    words: list[str] = []
    index = 0
    while index < len(given):
        arg = given[index]
        index += 1
        if arg in known["gh_repository_options"]:
            index += 1
        elif not arg.startswith("-"):
            words.append(arg)
    return len(words) >= 2 and " ".join(words[:2]) in known["gh_commands_that_bring_files"]
