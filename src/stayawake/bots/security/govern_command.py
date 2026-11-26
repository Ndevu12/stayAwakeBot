#!/usr/bin/env python3
"""Answer a git command before saw replays it: settings that make git run files from the folder, a
command the stand-in reads as bringing no files and sends for what it names, a command saw does not
replay, and a command acting on a repository with no working tree."""
from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from stayawake.lib.git import incoming, replay, runs_directly, runs_from_the_folder, subcommand_options
from stayawake.lib.git.run import UNTRUSTED, stdout
from stayawake.lib.git.typed_command import TypedCommand, folder_it_creates

PASSTHROUGH = "passthrough"
ASKS = "asks"
UNCHECKED = "unchecked"
CONTINUES_A_REBASE = "continues-a-rebase"
WRITES_A_FILE = "the command writes a file saw does not check"
FETCHES = "the command fetches outside the check; fetch with git fetch instead"
UPDATES_SUBMODULES = "a command that also updates submodules cannot be checked"
PUSHES_INTO_A_FOLDER = "a push into a repository with files on this machine cannot be checked"
RUNS_A_PROGRAM = "a command that runs a program it names cannot be checked"
READS_A_REPOSITORY_HERE = "a command that reads a repository on this machine cannot be checked"
LETS_A_PUSH_WRITE = "the command lets a push change this folder's files; check it first"
NO_WORKING_TREE = "the repository the command acts on has no working tree"
_PUSH_PROGRAM_OPTIONS = ("--receive-pack", "--exec")
_LS_REMOTE_PROGRAM_OPTIONS = ("--upload-pack", "--exec")
_OPENS_FILES_IN_A_PROGRAM = "--open-files-in-pager"
_PUSH_OPTIONS_WITH_A_VALUE = frozenset({"--repo", "-o", "--push-option", "--receive-pack", "--exec"})
_LOCAL_PREFIXES = ("/", "./", "../", "~", "file:")
_SCHEDULES_FETCHES = frozenset({"start", "register"})
_SAYS_NO = frozenset({"no", "false", "off", "0"})
_WRITES_AN_OUTPUT = frozenset({"diff", "diff-files", "diff-index", "diff-tree", "log", "show", "whatchanged",
                               "range-diff", "format-patch"})
_BRINGS_NOTHING_BY_WORD = {"worktree": subcommand_options.WORKTREE_WORDS_THAT_BRING_NOTHING,
                           "submodule": subcommand_options.SUBMODULE_WORDS_THAT_BRING_NOTHING}


@dataclass(frozen=True)
class Answer:
    """An answer given before a replay: its kind, the sentence, and the folder the command creates
    when it creates one."""

    kind: str
    reason: str = ""
    created: "str | None" = None


def before_replay(folder: Path, command: TypedCommand, brings_no_files: bool) -> "Answer | None":
    """Answer a git command before it is replayed: one saw would replay, or that only fetches, runs
    as typed in a repository with no working tree. Takes where it runs, the command and whether the
    stand-in reads it as one that brings no files. Returns the answer, or None for a command saw
    replays."""
    answer = _answer_before_replay(folder, command, brings_no_files)
    if (answer is None or answer.reason == FETCHES) and _without_a_working_tree(folder, command):
        return Answer(PASSTHROUGH, NO_WORKING_TREE)
    return answer


def _without_a_working_tree(folder: Path, command: TypedCommand) -> bool:
    """Tell whether git gives a command no working tree in the repository it acts on, that
    repository lies outside every working tree, and the command writes no files without one. Takes
    where it runs and the command. Returns the answer."""
    rules = replay.REPLAYED.get(command.sub)
    if rules is not None and rules.writes_files_without_a_working_tree:
        return False
    location = replay.locate(folder, command)
    return (not isinstance(location, str) and not location.has_a_working_tree
            and not runs_from_the_folder.lies_in_a_working_tree(str(location.git_dir.parent), folder))


def _answer_before_replay(folder: Path, command: TypedCommand, brings_no_files: bool) -> "Answer | None":
    """Answer a git command before it is replayed, whatever repository it acts on. Takes where it
    runs, the command and whether the stand-in reads it as one that brings no files. Returns the
    answer, or None for a command saw replays."""
    top = top_of_working_tree(folder)
    runs = runs_from_the_folder.settings_running_working_tree_files(folder, top, command.settings)
    if runs:
        return Answer(ASKS, _runs(runs))
    named_files = _setting_files_running_folder_files(folder, top, command.setting_files)
    if named_files:
        return Answer(ASKS, _runs(named_files))
    if _lets_a_push_write(command.settings) and command.sub == "push":
        return Answer(UNCHECKED, PUSHES_INTO_A_FOLDER)
    if brings_no_files:
        return _sent_for_what_it_names(folder, top, command)
    if command.sub == "merge" and command.rest == ("--continue",):
        return Answer(PASSTHROUGH, "the command brings no files in")
    if incoming.continues_a_rebase(command):
        return Answer(CONTINUES_A_REBASE)
    words = _BRINGS_NOTHING_BY_WORD.get(command.sub)
    if words is not None:
        word = next((arg for arg in command.rest if not arg.startswith("-")), "")
        if word in words:
            return Answer(PASSTHROUGH, "the command brings no files in")
        return Answer(UNCHECKED, replay.NOT_REPLAYED, folder_it_creates(command))
    why = replay.refusal(command)
    if why:
        return Answer(UNCHECKED, why, folder_it_creates(command))
    if _updates_submodules(folder, top, command):
        return Answer(UNCHECKED, UPDATES_SUBMODULES)
    return None


def _updates_submodules(folder: Path, top: "Path | None", command: TypedCommand) -> bool:
    """Tell whether a command would also update submodules in the folder, which a replay never
    does. Takes where it runs, the folder's top and the command. Returns the answer."""
    reading = subcommand_options.read(command.sub, list(command.rest))
    asked = reading.last("--recurse-submodules", "--no-recurse-submodules")
    if asked == "--recurse-submodules":
        values = reading.values("--recurse-submodules")
        recurses = not (values and values[-1].lower() in _SAYS_NO)
    elif asked:
        recurses = False
    else:
        given = [value for key, value in command.settings if key.lower() == "submodule.recurse"]
        if given:
            recurses = given[-1] is None or given[-1].strip().lower() in ("true", "yes", "on", "1")
        else:
            recurses = stdout(folder, ["config", "--type=bool", "--get", "submodule.recurse"],
                              context=UNTRUSTED).strip() == "true"
    if not recurses or top is None:
        return False
    listed = stdout(top, ["ls-files", "--stage", "-z"], context=UNTRUSTED)
    return (top / ".gitmodules").exists() or any(entry.startswith("160000 ") for entry in listed.split("\0"))


def _sent_for_what_it_names(folder: Path, top: "Path | None", command: TypedCommand) -> Answer:
    """Answer a command the stand-in reads as bringing no files and sends for an option, a setting
    or the environment it names. Takes where it runs, the folder's top, and the command. Returns the
    answer."""
    rest = command.rest
    before_paths = rest[:rest.index("--")] if "--" in rest else rest
    if command.sub in _WRITES_AN_OUTPUT and any(arg == "--output" or arg.startswith("--output=")
                                                 for arg in before_paths):
        return Answer(UNCHECKED, WRITES_A_FILE)
    if command.sub == "remote":
        words = [arg for arg in before_paths if not arg.startswith("-")]
        if words[:1] == ["update"] or (words[:1] == ["add"] and any(
                arg in ("-f", "--fetch") for arg in before_paths)):
            return Answer(UNCHECKED, FETCHES)
    if command.sub == "push":
        return _push(folder, rest)
    if command.sub == "ls-remote":
        return _ls_remote(folder, rest)
    if command.sub == "grep" and _opens_files_in_a_program(rest):
        return Answer(UNCHECKED, RUNS_A_PROGRAM)
    if command.sub == "maintenance":
        return _maintenance(folder, rest)
    if command.sub == "init":
        template = runs_from_the_folder.template_named(rest, command.template, command.settings) or stdout(
            folder, ["config", "--get", "init.templateDir"], context=UNTRUSTED).strip()
        if template and runs_from_the_folder.lies_in_a_working_tree(template, folder):
            return Answer(ASKS, f"the command copies hooks from {template}, a folder in a git working tree; "
                                "check it first")
    if command.sub == "config":
        settings = runs_from_the_folder.config_settings(rest)
        if isinstance(settings, str):
            return Answer(ASKS, settings)
        runs = runs_from_the_folder.settings_running_working_tree_files(folder, top, settings)
        if runs:
            return Answer(ASKS, _runs(runs))
        if _lets_a_push_write(settings):
            return Answer(ASKS, LETS_A_PUSH_WRITE)
    return Answer(PASSTHROUGH, "the command brings no files in")


def _setting_files_running_folder_files(folder: Path, top: "Path | None", files: tuple[str, ...]) -> tuple[str, ...]:
    """Pick the configuration files the environment names that lie in a working tree, the
    command's own or any other, or whose settings make git run a file or folder there. Takes where
    the command runs, the top of its working tree, None when it has none, and the files. Returns
    each picked file or setting."""
    picked: list[str] = []
    for name in files:
        path = Path(os.path.expanduser(name))
        path = path if path.is_absolute() else folder / path
        if runs_from_the_folder.lies_in_any_working_tree(path, top, folder):
            picked.append(name)
            continue
        listed = stdout(folder, ["config", "--file", str(path), "--includes", "--list", "-z"], context=UNTRUSTED)
        settings = [(key, value) for key, _, value in (entry.partition("\n") for entry in listed.split("\0")) if key]
        picked += runs_from_the_folder.settings_running_working_tree_files(folder, top, settings, path.parent)
    return tuple(picked)


def _lets_a_push_write(settings) -> bool:
    """Tell whether settings let a push into this repository update its working tree. Takes the
    (key, value) settings. Returns the answer."""
    return any(key.lower() == "receive.denycurrentbranch" and (value or "").strip().lower() == "updateinstead"
               for key, value in settings)


def _push(folder: Path, rest: tuple[str, ...]) -> Answer:
    """Answer a push: one that runs a program it names, or that reaches a repository with a working
    tree on this machine, asks first. Takes where it runs and its arguments. Returns the answer."""
    if runs_directly.names_a_program(list(rest), _PUSH_PROGRAM_OPTIONS):
        return Answer(UNCHECKED, RUNS_A_PROGRAM)
    words: list[str] = []
    named = ""
    index = 0
    while index < len(rest) and rest[index] != "--":
        arg = rest[index]
        index += 1
        name, joined, value = arg.partition("=")
        if name in _PUSH_OPTIONS_WITH_A_VALUE:
            given = value if joined else (rest[index] if index < len(rest) else "")
            index += 0 if joined else 1
            named = given if name == "--repo" else named
        elif not arg.startswith("-"):
            words.append(arg)
    targets = [named or words[0]] if (named or words) else _remotes(folder)
    for target in targets:
        place = _local_place(folder, target)
        if place is not None and stdout(place, ["rev-parse", "--is-bare-repository"],
                                        context=UNTRUSTED).strip() != "true":
            return Answer(UNCHECKED, PUSHES_INTO_A_FOLDER)
    return Answer(PASSTHROUGH, "the command brings no files in")


def _ls_remote(folder: Path, rest: tuple[str, ...]) -> Answer:
    """Answer an ls-remote: one that runs a program it names, or that reads a repository on this
    machine, asks first. Takes where it runs and its arguments. Returns the answer."""
    if runs_directly.names_a_program(list(rest), _LS_REMOTE_PROGRAM_OPTIONS):
        return Answer(UNCHECKED, RUNS_A_PROGRAM)
    words = subcommand_options.read("ls-remote", list(rest)).words
    targets = words[:1] or tuple(_remotes(folder, push=False))
    if any(_local_place(folder, target, push=False) is not None for target in targets):
        return Answer(UNCHECKED, READS_A_REPOSITORY_HERE)
    return Answer(PASSTHROUGH, "the command brings no files in")


def _opens_files_in_a_program(rest: tuple[str, ...]) -> bool:
    """Tell whether a grep opens the files it finds in a program. Takes its arguments. Returns the
    answer."""
    names = subcommand_options.read("grep", list(rest)).names()
    return any(name == "-O" or (len(name) > 3 and _OPENS_FILES_IN_A_PROGRAM.startswith(name)) for name in names)


def _remotes(folder: Path, *, push: bool = True) -> list[str]:
    """List the remotes a push or a read with no repository named may reach. Takes where it runs and
    whether it pushes. Returns their names."""
    pattern = r"^remote\..*\.(push)?url$" if push else r"^remote\..*\.url$"
    listed = stdout(folder, ["config", "--name-only", "--get-regexp", pattern], context=UNTRUSTED)
    return list(dict.fromkeys(line.removeprefix("remote.").rpartition(".")[0] for line in listed.splitlines() if line))


def _local_place(folder: Path, target: str, *, push: bool = True) -> "Path | None":
    """Find the folder on this machine a push or read target reaches, through the remote's address
    when it names a remote. Takes where the command runs, the target and whether it pushes. Returns
    the folder, or None for a target elsewhere."""
    address = target
    if not target.startswith(_LOCAL_PREFIXES) and target not in (".", "..") and not (folder / target).is_dir():
        asked = ["remote", "get-url", *(["--push"] if push else []), target]
        address = stdout(folder, asked, context=UNTRUSTED).strip() or target
    if address.startswith("file://"):
        address = address[len("file://"):]
    elif address.startswith("file:"):
        address = address[len("file:"):]
    elif "://" in address or not runs_directly.is_local_address(address):
        return None
    path = Path(os.path.expanduser(address))
    path = path if path.is_absolute() else folder / path
    return path if path.exists() else None


def _maintenance(folder: Path, rest: tuple[str, ...]) -> Answer:
    """Answer a maintenance command: scheduling runs, or a run that fetches, asks first. Takes where
    it runs and its arguments. Returns the answer."""
    words = [arg for arg in rest if not arg.startswith("-")]
    if words[:1] and words[0] in _SCHEDULES_FETCHES:
        return Answer(UNCHECKED, FETCHES)
    if words[:1] != ["run"]:
        return Answer(PASSTHROUGH, "the command brings no files in")
    tasks = [arg.partition("=")[2] for arg in rest if arg.startswith("--task=")]
    tasks += [rest[index + 1] for index, arg in enumerate(rest[:-1]) if arg == "--task"]
    scheduled = any(arg == "--schedule" or arg.startswith("--schedule=") or arg == "--auto" for arg in rest)
    prefetch_on = stdout(folder, ["config", "--type=bool", "--get", "maintenance.prefetch.enabled"],
                         context=UNTRUSTED).strip() == "true"
    if "prefetch" in tasks or scheduled or (not tasks and prefetch_on):
        return Answer(UNCHECKED, FETCHES)
    return Answer(PASSTHROUGH, "the command brings no files in")


def _runs(settings: tuple[str, ...]) -> str:
    """Say which settings make git run files from the folder. Takes them. Returns the sentence."""
    return (f"the command makes git run files from this folder ({', '.join(settings)}); "
            "check them first")


def top_of_working_tree(folder: Path) -> "Path | None":
    """Find the top of the working tree a folder is in. Takes the folder. Returns it, or None."""
    top = stdout(folder, ["rev-parse", "--show-toplevel"], context=UNTRUSTED).strip()
    return Path(top) if top else None
