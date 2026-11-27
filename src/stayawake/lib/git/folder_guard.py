#!/usr/bin/env python3
"""The settings and environment that keep a folder's own git configuration from starting a program
while the operator's git command runs there. Which keys run a program, and how each is kept from
running, is read from `lib/data/git_exec_keys.json`. Nothing in the folder is run."""
from __future__ import annotations

import os
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping

from stayawake.lib.git import command_line, exec_surface, operator_config, replay, typed_command
from stayawake.lib.git.exec_keys import (ENABLES_TRANSPORT, HOOKS_DIRECTORY, UNLESS_BOOLEAN, ExecKey,
                                         always_set, exec_keys, rule_for, subsection)
from stayawake.lib.git.run import one_pass, stalls_recorded
from stayawake.utils import env as saw_env

NO_HOOKS_FOLDER = ("saw", "git-runs-no-hooks")
VALUE_VARIABLE_PREFIX = "SAW_GUARD_VALUE_"
ALLOWED_PROTOCOLS = "GIT_ALLOW_PROTOCOL"
SUBCOMMANDS_THAT_REPORT_SETTINGS = frozenset({"config", "var"})
_EDITS_SETTINGS = frozenset({"-e", "--edit"})
_ASKS_ONLY_ABOUT_GIT = frozenset({None, "version"})
_UNREADABLE = "�"


@dataclass(frozen=True)
class Guard:
    """The answer for one command in one folder: the settings to give git in order, the arguments
    that give them, the environment variables to set, or why saw cannot vouch for the command."""

    folder: Path
    settings: tuple[tuple[str, str], ...] = ()
    arguments: tuple[str, ...] = ()
    environment: tuple[tuple[str, str], ...] = ()
    refusal: str = ""

    def run_with(self) -> dict:
        """Describe how to run the command: git's own options to put before its arguments, the
        settings they give in order, and the environment variables to set."""
        return {"arguments": list(self.arguments),
                "settings": [{"key": key, "value": value} for key, value in self.settings],
                "environment": dict(self.environment)}


def guard(folder: str | Path, args: list[str], environ: Mapping[str, str]) -> Guard:
    """Work out the settings and environment that keep a git command in a folder from starting what
    the folder's own configuration names. Takes the folder, the arguments without the program name,
    and the environment the command runs in. Returns the answer."""
    with one_pass(), stalls_recorded() as stalled, exec_surface.each_file_listed_once():
        answer = _guard(Path(folder), list(args), environ)
    if stalled and not answer.refusal:
        return Guard(answer.folder, refusal=f"git did not answer: {stalled[0]}")
    return answer


def _guard(folder: Path, args: list[str], environ: Mapping[str, str]) -> Guard:
    located = command_line.read("git", args, folder, alias_of=_no_alias)
    if not located.readable:
        return Guard(folder, refusal=f"this command line cannot be read: {located.reason}")
    where = located.folder or folder
    reading = command_line.read("git", args, folder)
    if reading.readable and _reports_settings(reading.subcommand, reading.rest):
        return Guard(where)
    command = typed_command.read(list(args), dict(environ))
    if isinstance(command, str):
        if located.subcommand in _ASKS_ONLY_ABOUT_GIT:
            return Guard(where)
        return Guard(where, refusal=f"this command line cannot be read: {command}")
    hooks, why = no_hooks_folder()
    if hooks is None:
        return Guard(where, refusal=why)
    git_dir, why = _repository(where, command)
    if why:
        return Guard(where, refusal=why)
    operator = operator_config.operator_entries(git_dir or where)
    if operator is None:
        return Guard(where, refusal=f"your own git settings did not load in {where}")
    commands, why = _folder_commands(git_dir, where) if git_dir is not None else ([], "")
    if why:
        return Guard(where, refusal=why)
    settings, environment, why = _overrides(commands, operator, hooks, environ)
    if why:
        return Guard(where, refusal=why)
    if reading.readable and reading.subcommand == "rev-parse" and "--git-path" in reading.rest:
        hooks_keys = {rule.key for rule in exec_keys() if rule.runs == HOOKS_DIRECTORY}
        settings = [(key, value) for key, value in settings if key.lower() not in hooks_keys]
    arguments, values = _arguments(settings)
    return Guard(where, tuple(settings), tuple(arguments), tuple({**environment, **values}.items()))


def _no_alias(_folder: Path, _name: str) -> None:
    """Read no alias, for finding the folder a command line names before any alias expands."""
    return None


def _reports_settings(subcommand: str | None, rest: tuple[str, ...]) -> bool:
    """Whether a command only reads or writes settings: it runs no program and reports what the
    settings say. Takes the subcommand after aliases and its arguments."""
    if subcommand not in SUBCOMMANDS_THAT_REPORT_SETTINGS:
        return False
    positionals = [arg for arg in rest if not arg.startswith("-")]
    if subcommand == "config" and _names_a_blob(rest):
        return False
    return not (_EDITS_SETTINGS & set(rest) or (subcommand == "config" and positionals[:1] == ["edit"]))


def _names_a_blob(rest: tuple[str, ...]) -> bool:
    """Whether a `git config` command line reads its settings from a blob, which git may fetch. Takes
    the arguments after the subcommand. Returns the answer."""
    for arg in rest:
        if arg in ("--", "--end-of-options"):
            return False
        name = arg.split("=", 1)[0]
        if len(name) > 3 and "--blob".startswith(name):
            return True
    return False


def _repository(where: Path, command: typed_command.TypedCommand) -> tuple[Path | None, str]:
    """Find the git directory a command acts on, the way git finds it: by its options, its
    environment or the folder. Takes the folder and the command. Returns the git directory, None
    when there is no repository, or why the one it acts on cannot be read."""
    location = replay.locate(where, command)
    if not isinstance(location, str):
        shared = exec_surface.common_dir_of(location.git_dir)
        if os.path.realpath(shared) != os.path.realpath(location.common_dir):
            return None, "the command names a common directory of its own"
        return location.git_dir, ""
    if command.names_its_repository or _looks_like_a_repository(where):
        return None, f"{where}: {location}"
    return None, ""


def no_hooks_folder() -> tuple[Path | None, str]:
    """The empty folder saw keeps for git to run hooks from, made when missing. Returns it, or
    None and why it cannot be used."""
    folder = Path(saw_env.xdg_state_home()).joinpath(*NO_HOOKS_FOLDER)
    try:
        folder.mkdir(mode=0o700, parents=True, exist_ok=True)
        found = os.lstat(folder)
        if not stat.S_ISDIR(found.st_mode):
            return None, f"saw's empty hooks folder {folder} is not a folder"
        getuid = getattr(os, "getuid", None)
        if getuid is not None and found.st_uid != getuid():
            return None, f"saw's empty hooks folder {folder} belongs to someone else"
        with os.scandir(folder) as entries:
            if next(entries, None) is not None:
                return None, f"saw's empty hooks folder {folder} holds files; remove them"
    except OSError as error:
        return None, f"saw's empty hooks folder {folder} could not be used: {error.strerror or error}"
    return folder, ""


def _folder_commands(git_dir: Path, where: Path) -> tuple[list[exec_surface.Command], str]:
    """Read every program-running entry of a repository's own configuration: its own, its worktrees'
    and submodules', and what they include. Takes its git directory and the folder the command runs
    in. Returns them, or no entries and why they could not all be read."""
    surface = exec_surface.read_exec_surface(git_dir, git_dir=git_dir)
    if surface is None:
        return [], f"the git settings of {where} did not load"
    if surface.unexamined:
        return [], f"part of the git settings of {where} did not load: {surface.unexamined[0]}"
    return surface.commands, ""


def _looks_like_a_repository(where: Path) -> bool:
    """Whether git could find a repository at or above a folder. Takes the folder."""
    for place in (where, *where.resolve().parents):
        if os.path.lexists(place / ".git") or exec_surface.is_git_directory(place):
            return True
    return False


def _overrides(commands: list[exec_surface.Command], operator: list[tuple[str, str | None]], hooks: Path,
               environ: Mapping[str, str]) -> tuple[list[tuple[str, str]], dict[str, str], str]:
    """Decide every setting and environment variable the command runs with. Takes the folder's
    program-running entries, the operator's own entries, saw's empty hooks folder and the
    environment. Returns the settings in order, the environment, and the reason the command may not
    run, empty when it may."""
    own = _operator_values(operator)
    settings: list[tuple[str, str]] = []
    environment: dict[str, str] = {}
    cleared: set[str] = set()
    for rule in exec_keys():
        if rule.runs == HOOKS_DIRECTORY:
            settings.append((rule.key, _hooks_path(own.get(rule.key), hooks)))
        elif rule.runs == ENABLES_TRANSPORT:
            settings.append(_instead(rule, rule.key))
    settings += always_set()
    for command in commands:
        rule, key, value = command.rule, command.entry.key, command.entry.value
        if rule.runs in (HOOKS_DIRECTORY, ENABLES_TRANSPORT):
            continue
        if _UNREADABLE in key:
            return [], {}, "a setting in this folder has a name that is not valid text"
        override = rule.override
        if override.refuse:
            return [], {}, f"this folder's settings name a program in {key} that cannot be kept from running"
        if override.environment:
            if override.environment in environ:
                continue
            if any(rule.matches(own_key) for own_key, _ in operator):
                return [], {}, f"both your settings and this folder's set {key}"
            environment[override.environment] = override.value
        elif override.reset:
            if override.reset not in cleared:
                cleared.add(override.reset)
                settings.append((override.reset, ""))
                settings += [(k, v) for k, v in operator
                             if v is not None and _same_list(k, override.reset)]
        elif override.setting:
            settings.append(_instead(rule, key))
        else:
            settings.append((key, own.get(key, _runs_nothing(rule))))
    environment.update(_protocols_left(settings, environ))
    return _once(settings), environment, ""


def _operator_values(operator: list[tuple[str, str | None]]) -> dict[str, str]:
    """The value git takes for each key the operator sets: the last one. Takes the operator's
    entries. Returns them by key, a bare key read as true."""
    return {key: "true" if value is None else value for key, value in operator}


def _hooks_path(own: str | None, hooks: Path) -> str:
    """The folder git runs hooks from: the operator's own, when it names a folder outside any
    repository, else saw's empty one. Takes the operator's value and saw's folder."""
    if own and os.path.isabs(os.path.expanduser(own)):
        return own
    return str(hooks)


def _instead(rule: ExecKey, key: str) -> tuple[str, str]:
    """The setting that stands for a key whose own value cannot be set again. Takes the rule and the
    listed key."""
    if not rule.override.setting:
        return key, rule.override.value
    return rule.override.setting.format(subsection=subsection(key) or ""), rule.override.value


def _same_list(key: str, reset: str) -> bool:
    """Whether a key adds to the list `reset` clears. Takes the key and the clearing key."""
    rule = rule_for(key)
    return rule is not None and rule.override.reset == reset


def _runs_nothing(rule: ExecKey) -> str:
    """The value that makes a key run nothing. Takes its rule."""
    return "false" if rule.runs == UNLESS_BOOLEAN else ""


def _protocols_left(settings: list[tuple[str, str]], environ: Mapping[str, str]) -> dict[str, str]:
    """Take out of the environment's allowed transports every one a setting turns off. Takes the
    settings and the environment. Returns the variable to set, when it changes."""
    allowed = environ.get(ALLOWED_PROTOCOLS)
    if allowed is None:
        return {}
    turned_off = {key.split(".")[1] for key, value in settings
                  if key.startswith("protocol.") and key.endswith(".allow") and key.count(".") == 2
                  and value == "never"}
    kept = [name for name in allowed.split(":") if name not in turned_off]
    return {} if kept == allowed.split(":") else {ALLOWED_PROTOCOLS: ":".join(kept)}


def _once(settings: list[tuple[str, str]]) -> list[tuple[str, str]]:
    """Drop a setting given again with the same value, unless it clears a list. Takes the settings.
    Returns them in order."""
    seen: set[tuple[str, str]] = set()
    kept: list[tuple[str, str]] = []
    for key, value in settings:
        lowered = (key.lower(), value)
        if lowered in seen and not _clears_a_list(key):
            continue
        seen.add(lowered)
        kept.append((key, value))
    return kept


def _clears_a_list(key: str) -> bool:
    """Whether a key adds to a list an empty value clears. Takes the key."""
    rule = rule_for(key)
    return rule is not None and rule.override.reset is not None


def _arguments(settings: list[tuple[str, str]]) -> tuple[list[str], dict[str, str]]:
    """Spell the settings in git's global options. Takes them. Returns the options, and the
    environment variables holding the value of a setting whose name holds `=`."""
    arguments: list[str] = []
    values: dict[str, str] = {}
    for key, value in settings:
        if "=" in key:
            name = f"{VALUE_VARIABLE_PREFIX}{len(values) + 1}"
            values[name] = value
            arguments.append(f"--config-env={key}={name}")
        else:
            arguments += ["-c", f"{key}={value}"]
    return arguments, values
