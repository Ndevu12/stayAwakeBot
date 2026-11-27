#!/usr/bin/env python3
"""The options and words git lists for the subcommands saw reads, read from
`lib/data/git_subcommand_options.json`, which is built into saw's git stand-in too, and readers that
split a subcommand's arguments the way git does."""
from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class Listed:
    """The options git lists for one subcommand, by the value each takes: the next word, only what
    is joined to a short option, or none. `takes_no_word` is None where saw does not list them.
    Also the options whose value names a program to run, those that name a file git writes and
    those that fetch,
    whether `git <subcommand> --help-all` lists its options, and whether git passes an option it
    does not take through as output."""

    takes_the_next_word: frozenset[str]
    takes_the_rest_of_its_word: frozenset[str] = frozenset()
    takes_no_word: "frozenset[str] | None" = None
    runs_a_program: frozenset[str] = frozenset()
    writes_a_file: frozenset[str] = frozenset()
    fetches: frozenset[str] = frozenset()
    lists_its_options: bool = True
    echoes_options_it_does_not_take: bool = False

    def long_names(self) -> frozenset[str]:
        """Return every long option listed, with or without a value."""
        every = self.takes_the_next_word | self.takes_the_rest_of_its_word | (self.takes_no_word or frozenset())
        return frozenset(name for name in every if name.startswith("--"))


_VALUE_KINDS = ("takes_the_next_word", "takes_the_rest_of_its_word", "takes_no_word")


def _listed(entry: dict, groups: dict) -> Listed:
    """Build one subcommand's options from its entry in the table and the groups it takes, each
    option the entry lists keeping the entry's reading. Takes the entry and the table's groups.
    Returns the options."""
    own = frozenset(name for key in _VALUE_KINDS for name in entry.get(key) or ())
    parts = [entry, *(groups[name] for name in entry.get("with", ()))]

    def joined(key: str) -> frozenset[str]:
        return frozenset(name for part in parts for name in part.get(key) or ()
                         if part is entry or key not in _VALUE_KINDS or name not in own)
    no_word = None if entry.get("takes_no_word", ()) is None else joined("takes_no_word")
    return Listed(joined("takes_the_next_word"), joined("takes_the_rest_of_its_word"), no_word,
                  joined("runs_a_program"), joined("writes_a_file"), joined("fetches"),
                  entry.get("lists_its_options", True),
                  entry.get("echoes_options_it_does_not_take", False))


def _load(path: Path) -> tuple[dict[str, Listed], frozenset[str]]:
    """Read the table of the options git takes. Takes its file. Returns each subcommand's options and
    the options every subcommand takes."""
    table = json.loads(path.read_text(encoding="utf-8"))
    groups = table["option_groups"]
    listed = {sub: _listed(entry, groups) for sub, entry in table["subcommands"].items()}
    return listed, frozenset(table["every_subcommand_takes"])


TABLE_FILE = Path(__file__).resolve().parent.parent / "data" / "git_subcommand_options.json"
LISTED, EVERY_SUBCOMMAND_TAKES = _load(TABLE_FILE)

STASH_WORDS_THAT_BRING_NOTHING = frozenset({"push", "save", "list", "show", "drop", "clear", "create", "store",
                                            "import", "export"})
STASH_WORDS_SAW_LEAVES_TO_YOU = frozenset({"apply", "pop", "branch"})
WORKTREE_WORDS_THAT_BRING_NOTHING = frozenset({"list", "lock", "unlock", "move", "prune", "remove", "repair"})
WORKTREE_WORDS_SAW_LEAVES_TO_YOU = frozenset({"add"})
SUBMODULE_WORDS_THAT_BRING_NOTHING = frozenset({"", "status", "init", "deinit", "sync", "summary",
                                                "absorbgitdirs", "set-branch", "set-url"})
SUBMODULE_WORDS_SAW_LEAVES_TO_YOU = frozenset({"add", "foreach"})
SUBMODULE_WORDS_SAW_CHECKS = frozenset({"update"})


@dataclass(frozen=True)
class Given:
    """An option git reads: how it is written, its full name, its value and whether that value is
    the next word."""

    written: str
    name: str
    value: "str | None"
    value_is_the_next_word: bool = False


def full_long_name(listed: Listed, written: str) -> "str | None":
    """Name the long option git reads a written one for: itself, or the one option it begins. Takes
    the subcommand's options and the written name. Returns None for any other."""
    names = listed.long_names()
    if written in names:
        return written
    leading = [name for name in names if name.startswith(written)] if len(written) > 2 else []
    return leading[0] if len(leading) == 1 else None


@dataclass(frozen=True)
class Resolved:
    """A subcommand's arguments read the way git reads them: its options, and its words, those after
    `--` or `--end-of-options` included."""

    options: tuple[Given, ...]
    words: tuple[str, ...]

    def last(self, *names: str) -> "str | None":
        """Return which of the full `names` was given last, or None when none was."""
        for option in reversed(self.options):
            if option.name in names:
                return option.name
        return None

    def values(self, name: str) -> list[str]:
        """List the values given to the option with this full name, in order."""
        return [option.value for option in self.options if option.name == name and option.value is not None]


def resolve(sub: str, args: list[str]) -> "Resolved | None":
    """Read a subcommand's arguments the way git does: each option up to `--` or `--end-of-options`
    in full from a unique leading part, its `--no-` form, a bundle of short options, and a value
    joined to it or in the next word. Each other argument is a word. Takes the subcommand and its
    arguments. Returns its options and words, None for an option git does not take or cannot tell
    apart."""
    listed = LISTED.get(sub)
    if listed is None or listed.takes_no_word is None:
        return None
    given: list[Given] = []
    words: list[str] = []
    word_seen = False
    index = 0
    while index < len(args):
        arg = args[index]
        index += 1
        if arg in ("--", "--end-of-options"):
            words += args[index:]
            break
        if arg == "-" or not arg.startswith("-"):
            if not word_seen and f"{sub} {arg}" in LISTED:
                listed = LISTED[f"{sub} {arg}"]
            word_seen = True
            words.append(arg)
            continue
        if arg in EVERY_SUBCOMMAND_TAKES or listed.echoes_options_it_does_not_take:
            given.append(Given(arg, arg, None))
            continue
        if arg.startswith("--"):
            written, joined, value = arg.partition("=")
            name = full_long_name(listed, written)
            if name is None:
                return None
            if not joined and name in listed.takes_the_next_word:
                given.append(Given(written, name, args[index] if index < len(args) else None, True))
                index += 1
            else:
                given.append(Given(written, name, value if joined else None))
            continue
        bundle = arg[1:]
        while bundle:
            if bundle[0].isdigit() and "-NUM" in (listed.takes_no_word or ()):
                digits = len(bundle) - len(bundle.lstrip("0123456789"))
                given.append(Given("-" + bundle[:digits], "-NUM", None))
                bundle = bundle[digits:]
                continue
            name, bundle = "-" + bundle[0], bundle[1:]
            if name in listed.takes_the_next_word:
                if bundle:
                    given.append(Given(name, name, bundle))
                else:
                    given.append(Given(name, name, args[index] if index < len(args) else None, True))
                    index += 1
                break
            if name in listed.takes_the_rest_of_its_word:
                given.append(Given(name, name, bundle or None))
                break
            if name not in (listed.takes_no_word or ()):
                return None
            given.append(Given(name, name, None))
    return Resolved(tuple(given), tuple(words))


def options_saw_checks(sub: str) -> tuple[frozenset[str], frozenset[str], frozenset[str]]:
    """List the options of a subcommand, and of the words it takes, whose value names a program to
    run, those that name a file git writes, and those that fetch. Takes the subcommand. Returns all
    three."""
    parts = [listed for name, listed in LISTED.items() if name == sub or name.startswith(sub + " ")]
    return (frozenset(name for listed in parts for name in listed.runs_a_program),
            frozenset(name for listed in parts for name in listed.writes_a_file),
            frozenset(name for listed in parts for name in listed.fetches))
