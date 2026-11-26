#!/usr/bin/env python3
"""Answer a git command before saw replays it: settings that make git run files from the folder, a
command the stand-in reads as bringing no files and sends for what it names, and a command saw does
not replay."""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from stayawake.lib.git import incoming, replay, runs_from_the_folder, subcommand_options
from stayawake.lib.git.run import UNTRUSTED, stdout
from stayawake.lib.git.typed_command import TypedCommand, folder_it_creates

PASSTHROUGH = "passthrough"
ASKS = "asks"
UNCHECKED = "unchecked"
CONTINUES_A_REBASE = "continues-a-rebase"
WRITES_A_FILE = "the command writes a file saw does not check"
FETCHES = "the command fetches outside the check; fetch with git fetch instead"
UPDATES_SUBMODULES = "a command that also updates submodules cannot be checked"
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
    """Answer a git command before it is replayed. Takes where it runs, the command and whether the
    stand-in reads it as one that brings no files. Returns the answer, or None for a command saw
    replays."""
    top = _top(folder)
    runs = runs_from_the_folder.settings_running_folder_files(top, command.settings)
    if runs:
        return Answer(ASKS, _runs(runs))
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
    if command.sub == "init":
        template = runs_from_the_folder.template_named(rest, command.template, command.settings)
        if template and runs_from_the_folder.lies_in_a_working_tree(template, folder):
            return Answer(ASKS, f"the command copies hooks from {template}, a folder in a git working tree; "
                                "check it first")
    if command.sub == "config":
        settings = runs_from_the_folder.config_settings(rest)
        if isinstance(settings, str):
            return Answer(ASKS, settings)
        runs = runs_from_the_folder.settings_running_folder_files(top, settings)
        if runs:
            return Answer(ASKS, _runs(runs))
    return Answer(PASSTHROUGH, "the command brings no files in")


def _runs(settings: tuple[str, ...]) -> str:
    """Say which settings make git run files from the folder. Takes them. Returns the sentence."""
    return (f"the command makes git run files from this folder ({', '.join(settings)}); "
            "check them first")


def _top(folder: Path) -> "Path | None":
    """Find the top of the working tree a folder is in. Takes the folder. Returns it, or None."""
    top = stdout(folder, ["rev-parse", "--show-toplevel"], context=UNTRUSTED).strip()
    return Path(top) if top else None
