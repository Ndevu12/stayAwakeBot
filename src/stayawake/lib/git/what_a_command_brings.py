#!/usr/bin/env python3
"""Decide what a git subcommand does to the open folder, from its arguments and what saw reads about
the folder."""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Callable

from stayawake.lib.git import subcommand_options
from stayawake.lib.git.subcommand_options import Reading, read

CHECKED_IN_A_HOLDING_COPY = "checked-in-a-holding-copy"
CHECKED_BEFORE_IT_STAGES = "checked-before-it-stages"
BRINGS_NOTHING = "brings-nothing"
LEFT_TO_YOU = "left-to-you"

REPLAYED_AS_TYPED = frozenset({"pull", "merge", "rebase", "fetch"})
_RESETS_THE_FILES = ("--hard", "--merge", "--keep")
_RESET_MODES = ("--soft", "--mixed", *_RESETS_THE_FILES)
_THE_CURRENT_COMMIT = ("HEAD", "@")
_SPELLED_AS_AN_ANCESTOR = re.compile(r"(?:HEAD|@)(?:[~^][0-9]*)*")
_SAYS_NO = frozenset({"no", "false", "off", "0"})


@dataclass(frozen=True)
class Folder:
    """What saw reads about the folder a command acts on: whether a revision is its current commit,
    one of that commit's ancestors or no commit at all, and whether a command that may update
    submodules updates them there, given what its command line asks."""

    holds_in_its_history: Callable[[str], bool]
    updates_submodules: Callable[["bool | None"], bool]


def spelled_as_an_ancestor(revision: str) -> bool:
    """Tell whether a revision names the current commit or an ancestor by its spelling alone, such
    as HEAD~1. Takes the revision. Returns the answer."""
    return _SPELLED_AS_AN_ANCESTOR.fullmatch(revision) is not None


COMMAND_LINE_ONLY = Folder(spelled_as_an_ancestor, lambda asked: asked is True)


def decide(sub: str, rest: list[str], folder: Folder = COMMAND_LINE_ONLY) -> str:
    """Decide what a git subcommand does to the open folder. Takes the subcommand, its arguments and
    what saw reads about the folder. Returns CHECKED_IN_A_HOLDING_COPY, CHECKED_BEFORE_IT_STAGES,
    BRINGS_NOTHING or LEFT_TO_YOU."""
    if sub in REPLAYED_AS_TYPED:
        return CHECKED_IN_A_HOLDING_COPY
    decider = _DECIDERS.get(sub)
    return decider(rest, folder) if decider else LEFT_TO_YOU


def folder_it_creates(sub: str, rest: list[str]) -> "str | None":
    """Find the folder a clone or a `worktree add` creates, named the way git names it. Takes the
    subcommand and its arguments. Returns the folder relative to where git runs, or None when it
    cannot be told."""
    if sub == "worktree" and rest[:1] == ["add"]:
        words = read("worktree add", rest[1:]).words
        return words[0] if words else None
    if sub != "clone":
        return None
    reading = read("clone", rest)
    words = list(reading.words) + list(reading.paths)
    if len(words) >= 2:
        return words[1]
    if not words:
        return None
    name = words[0].rstrip("/")
    name = name[:-len("/.git")] if name.endswith("/.git") else name
    name = re.split(r"[/:]", name)[-1]
    for suffix in (".git", ".bundle"):
        name = name[:-len(suffix)] if name.endswith(suffix) else name
    bare = reading.last("--bare", "--no-bare", "--mirror", "--no-mirror") in ("--bare", "--mirror")
    return (name + ".git" if bare else name) or None


def cacheinfo_entries(rest: list[str]) -> "list[tuple[str, str]] | None":
    """List the files an `update-index` names with --cacheinfo, in either of git's spellings. Takes
    its arguments. Returns each path with its object id, or None when an entry cannot be read."""
    entries: list[tuple[str, str]] = []
    index = 0
    while index < len(rest) and rest[index] != "--":
        arg = rest[index]
        index += 1
        if arg != "--cacheinfo" and not arg.startswith("--cacheinfo="):
            continue
        joined = arg.partition("=")[2] if "=" in arg else (rest[index] if index < len(rest) else "")
        index += 0 if "=" in arg else 1
        fields = joined.split(",", 2)
        if len(fields) != 3:
            fields = [joined, *rest[index:index + 2]]
            index += 2
        if len(fields) != 3 or not all(fields):
            return None
        entries.append((fields[2], fields[1]))
    return entries


def _unless_it_updates_submodules(decision: str, reading: Reading, folder: Folder) -> str:
    """Leave to you a command that brings nothing itself but would update submodules. Takes the
    decision reached, the reading and the folder. Returns the decision."""
    if decision != BRINGS_NOTHING:
        return decision
    asked = reading.last("--recurse-submodules", "--no-recurse-submodules")
    if asked == "--recurse-submodules":
        values = reading.values("--recurse-submodules")
        explicit = not (values and values[-1].lower() in _SAYS_NO)
    else:
        explicit = False if asked else None
    return LEFT_TO_YOU if folder.updates_submodules(explicit) else BRINGS_NOTHING


def _moves_to_a_commit(sub: str):
    """Build the decider for checkout or switch, which checks a command that names a commit. Takes
    the subcommand. Returns the decider."""
    def decide_it(rest: list[str], folder: Folder) -> str:
        reading = read(sub, rest)
        if reading.words:
            return CHECKED_IN_A_HOLDING_COPY
        return _unless_it_updates_submodules(BRINGS_NOTHING, reading, folder) if reading.known else LEFT_TO_YOU
    return decide_it


def _reset(rest: list[str], folder: Folder) -> str:
    """Decide what a reset does to the folder. Takes its arguments and the folder. Returns the
    decision."""
    reading = read("reset", rest)
    if not reading.known:
        return LEFT_TO_YOU
    commit = reading.words[0] if reading.words else None
    if (reading.last(*_RESET_MODES) or "--mixed") in _RESETS_THE_FILES:
        if commit is None or commit in _THE_CURRENT_COMMIT:
            return _unless_it_updates_submodules(BRINGS_NOTHING, reading, folder)
        return CHECKED_IN_A_HOLDING_COPY
    if commit is None or folder.holds_in_its_history(commit):
        return BRINGS_NOTHING
    names_paths = len(reading.words) > 1 or reading.paths or reading.last("-p", "--patch", "--pathspec-from-file")
    return LEFT_TO_YOU if names_paths else CHECKED_BEFORE_IT_STAGES


def _restore(rest: list[str], folder: Folder) -> str:
    """Decide what a restore does to the folder. Takes its arguments and the folder. Returns the
    decision."""
    reading = read("restore", rest)
    if not reading.known:
        return LEFT_TO_YOU
    names_a_source = reading.last("-s", "--source", "--no-source") in ("-s", "--source")
    source = reading.values("-s", "--source")[-1] if names_a_source else None
    staged = reading.last("-S", "--staged", "--no-staged") in ("-S", "--staged")
    worktree = reading.last("-W", "--worktree", "--no-worktree") in ("-W", "--worktree")
    writes_the_folder = worktree or not staged
    if source is not None and (writes_the_folder or not folder.holds_in_its_history(source)):
        return LEFT_TO_YOU
    return _unless_it_updates_submodules(BRINGS_NOTHING, reading, folder) if writes_the_folder else BRINGS_NOTHING


def _read_tree(rest: list[str], folder: Folder) -> str:
    """Decide what a read-tree does to the folder. Takes its arguments and the folder. Returns the
    decision."""
    reading = read("read-tree", rest)
    if not reading.known:
        return LEFT_TO_YOU
    if reading.last("-n", "--dry-run", "--no-dry-run") in ("-n", "--dry-run"):
        return BRINGS_NOTHING
    if reading.last("-u") or not all(folder.holds_in_its_history(tree) for tree in reading.words):
        return LEFT_TO_YOU
    return BRINGS_NOTHING


def _commits_onto_the_branch(sub: str):
    """Build the decider for cherry-pick or revert, which checks a command that commits the commits
    it names. Takes the subcommand. Returns the decider."""
    def decide_it(rest: list[str], folder: Folder) -> str:
        reading = read(sub, rest)
        if not reading.known or not reading.words or reading.last("--continue", "--skip"):
            return LEFT_TO_YOU
        if reading.last("-n", "--no-commit", "--commit") in ("-n", "--no-commit"):
            return LEFT_TO_YOU
        return CHECKED_IN_A_HOLDING_COPY
    return decide_it


def _update_index(rest: list[str], folder: Folder) -> str:
    """Decide what an update-index does to the folder. Takes its arguments and the folder. Returns
    the decision."""
    reading = read("update-index", rest)
    if not reading.known or reading.last("--index-info"):
        return LEFT_TO_YOU
    entries = cacheinfo_entries(rest)
    if entries is None:
        return LEFT_TO_YOU
    return CHECKED_BEFORE_IT_STAGES if entries else BRINGS_NOTHING


def _update_ref(rest: list[str], folder: Folder) -> str:
    """Decide what an update-ref does to the folder. Takes its arguments and the folder. Returns the
    decision."""
    reading = read("update-ref", rest)
    if not reading.known or reading.last("--stdin", "--no-stdin") == "--stdin":
        return LEFT_TO_YOU
    if reading.last("-d") or len(reading.words) < 2 or folder.holds_in_its_history(reading.words[1]):
        return BRINGS_NOTHING
    return LEFT_TO_YOU


def _stash(rest: list[str], folder: Folder) -> str:
    """Decide what a stash command does to the folder. Takes its arguments and the folder. Returns
    the decision."""
    word = "push" if not rest or rest[0].startswith("-") else rest[0]
    if word in subcommand_options.STASH_WORDS_THAT_BRING_NOTHING:
        return BRINGS_NOTHING
    return LEFT_TO_YOU


def _worktree(rest: list[str], folder: Folder) -> str:
    """Decide what a worktree command does to the folder. Takes its arguments and the folder.
    Returns the decision."""
    if rest[:1] and rest[0] in subcommand_options.WORKTREE_WORDS_THAT_BRING_NOTHING:
        return BRINGS_NOTHING
    return LEFT_TO_YOU


def _submodule(rest: list[str], folder: Folder) -> str:
    """Decide what a submodule command does to the folder. Takes its arguments and the folder.
    Returns the decision."""
    word = next((arg for arg in rest if not arg.startswith("-")), "")
    if word in subcommand_options.SUBMODULE_WORDS_SAW_CHECKS:
        return CHECKED_IN_A_HOLDING_COPY
    if word in subcommand_options.SUBMODULE_WORDS_THAT_BRING_NOTHING:
        return BRINGS_NOTHING
    return LEFT_TO_YOU


_DECIDERS = {
    "checkout": _moves_to_a_commit("checkout"),
    "switch": _moves_to_a_commit("switch"),
    "reset": _reset,
    "restore": _restore,
    "read-tree": _read_tree,
    "cherry-pick": _commits_onto_the_branch("cherry-pick"),
    "revert": _commits_onto_the_branch("revert"),
    "update-index": _update_index,
    "update-ref": _update_ref,
    "stash": _stash,
    "worktree": _worktree,
    "submodule": _submodule,
}
