#!/usr/bin/env python3
"""The options and words git lists for the subcommands saw reads, and a reader that splits a
subcommand's arguments the way git does."""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Listed:
    """The options git lists for one subcommand, by the value each takes: the next word, only what
    is joined to a short option, or none. `takes_no_word` is None where saw does not list them."""

    takes_the_next_word: frozenset[str]
    takes_the_rest_of_its_word: frozenset[str] = frozenset()
    takes_no_word: "frozenset[str] | None" = None


@dataclass(frozen=True)
class Reading:
    """A subcommand's arguments read by git's rules: its options as written with their values, its
    words, the paths after `--`, and whether every option is one git lists, spelled in full."""

    options: tuple[tuple[str, "str | None"], ...]
    words: tuple[str, ...]
    paths: tuple[str, ...]
    known: bool

    def names(self) -> list[str]:
        """List the options as written, without their values."""
        return [name for name, _value in self.options]

    def last(self, *names: str) -> "str | None":
        """Return which of `names` was given last, or None when none was."""
        for name, _value in reversed(self.options):
            if name in names:
                return name
        return None

    def values(self, *names: str) -> list[str]:
        """List the values given to any of `names`, in order."""
        return [value for name, value in self.options if name in names and value is not None]


def _negations(*names: str) -> frozenset[str]:
    """Return the `--no-` form of each long name."""
    return frozenset("--no-" + name[2:] for name in names if name.startswith("--") and not name.startswith("--no-"))


def _with_negations(*names: str) -> frozenset[str]:
    """Return the names with the `--no-` form of each long one."""
    return frozenset(names) | _negations(*names)


LISTED = {
    "checkout": Listed(
        frozenset({"-b", "-B", "--orphan", "--conflict", "--pathspec-from-file", "-U", "--unified",
                   "--inter-hunk-context"}),
        frozenset({"-t"}),
        _with_negations("--auto-advance", "--detach", "--force", "--guess", "--ignore-other-worktrees",
                        "--ignore-skip-worktree-bits", "--merge", "--ours", "--overlay", "--overwrite-ignore",
                        "--patch", "--pathspec-file-nul", "--progress", "--quiet", "--recurse-submodules",
                        "--theirs", "--track", "-2", "-3", "-d", "-f", "-l", "-m", "-p", "-q")
        | _negations("--orphan", "--conflict", "--pathspec-from-file")),
    "switch": Listed(
        frozenset({"-c", "-C", "--create", "--force-create", "--orphan", "--conflict"}),
        frozenset({"-t"}),
        _with_negations("--detach", "--discard-changes", "--force", "--guess", "--ignore-other-worktrees",
                        "--merge", "--overwrite-ignore", "--progress", "--quiet", "--recurse-submodules",
                        "--track", "-d", "-f", "-m", "-q")
        | _negations("--create", "--force-create", "--orphan", "--conflict")),
    "pull": Listed(
        frozenset({"-s", "--strategy", "-X", "--strategy-option", "--depth", "--deepen", "--shallow-since",
                   "--shallow-exclude", "-o", "--server-option", "--upload-pack", "--negotiation-tip",
                   "--negotiation-include", "--negotiation-restrict", "--cleanup", "--refmap"}),
        frozenset({"-S", "-j", "-r"})),
    "merge": Listed(
        frozenset({"-m", "--message", "-F", "--file", "-s", "--strategy", "-X", "--strategy-option",
                   "--into-name", "--cleanup"}),
        frozenset({"-S"})),
    "rebase": Listed(
        frozenset({"--onto", "-s", "--strategy", "-X", "--strategy-option", "-x", "--exec", "-C",
                   "--whitespace", "--empty", "--trailer"}),
        frozenset({"-S", "-r"})),
    "fetch": Listed(
        frozenset({"-o", "--server-option", "--depth", "--deepen", "--shallow-since", "--shallow-exclude",
                   "-j", "--jobs", "--upload-pack", "--negotiation-tip", "--negotiation-include",
                   "--negotiation-restrict", "--refmap", "--filter", "--recurse-submodules-default",
                   "--submodule-prefix"})),
    "reset": Listed(
        frozenset({"-U", "--unified", "--inter-hunk-context", "--pathspec-from-file"}),
        frozenset(),
        _with_negations("--auto-advance", "--intent-to-add", "--patch", "--pathspec-file-nul", "--quiet",
                        "--recurse-submodules", "-N", "-p", "-q")
        | _negations("--pathspec-from-file")
        | {"--hard", "--keep", "--merge", "--mixed", "--soft", "--no-refresh", "--refresh"}),
    "restore": Listed(
        frozenset({"-s", "--source", "--conflict", "-U", "--unified", "--inter-hunk-context",
                   "--pathspec-from-file"}),
        frozenset(),
        _with_negations("--ignore-skip-worktree-bits", "--ignore-unmerged", "--merge", "--ours", "--overlay",
                        "--patch", "--pathspec-file-nul", "--progress", "--quiet", "--recurse-submodules",
                        "--staged", "--theirs", "--worktree", "-2", "-3", "-S", "-W", "-m", "-p", "-q")
        | _negations("--source", "--conflict", "--pathspec-from-file")),
    "read-tree": Listed(
        frozenset({"--index-output", "--prefix", "--exclude-per-directory", "--super-prefix"}),
        frozenset(),
        _with_negations("--aggressive", "--debug-unpack", "--dry-run", "--empty", "--quiet",
                        "--recurse-submodules", "--reset", "--sparse-checkout", "--trivial", "--verbose",
                        "-i", "-m", "-n", "-q", "-u", "-v")
        | _negations("--super-prefix")),
    "cherry-pick": Listed(
        frozenset({"--cleanup", "-m", "--mainline", "--strategy", "-X", "--strategy-option", "--empty"}),
        frozenset({"-S"}),
        _with_negations("--abort", "--allow-empty", "--allow-empty-message", "--commit", "--continue",
                        "--edit", "--ff", "--gpg-sign", "--keep-redundant-commits", "--quit",
                        "--rerere-autoupdate", "--signoff", "--skip", "-e", "-n", "-r", "-s", "-x")
        | _negations("--cleanup", "--mainline", "--strategy", "--strategy-option")),
    "revert": Listed(
        frozenset({"--cleanup", "-m", "--mainline", "--strategy", "-X", "--strategy-option"}),
        frozenset({"-S"}),
        _with_negations("--abort", "--commit", "--continue", "--edit", "--gpg-sign", "--quit", "--reference",
                        "--rerere-autoupdate", "--signoff", "--skip", "-e", "-n", "-r", "-s")
        | _negations("--cleanup", "--mainline", "--strategy", "--strategy-option")),
    "clone": Listed(
        frozenset({"-b", "--branch", "-c", "--config", "--depth", "--filter", "-j", "--jobs", "-o", "--origin",
                   "--ref-format", "--reference", "--reference-if-able", "--revision", "--separate-git-dir",
                   "--server-option", "--shallow-exclude", "--shallow-since", "--template", "-u",
                   "--upload-pack", "--bundle-uri"}),
        frozenset(),
        _with_negations("--also-filter-submodules", "--bare", "--checkout", "--dissociate", "--hardlinks",
                        "--ipv4", "--ipv6", "--local", "--mirror", "--naked", "--progress", "--quiet",
                        "--recurse-submodules", "--recursive", "--reject-shallow", "--remote-submodules",
                        "--shallow-submodules", "--shared", "--single-branch", "--sparse", "--tags",
                        "--verbose", "-4", "-6", "-l", "-n", "-q", "-s", "-v")
        | _negations("--branch", "--config", "--depth", "--filter", "--jobs", "--origin", "--ref-format",
                     "--reference", "--reference-if-able", "--revision", "--separate-git-dir", "--server-option",
                     "--shallow-exclude", "--shallow-since", "--template", "--upload-pack", "--bundle-uri")),
    "worktree add": Listed(
        frozenset({"-b", "-B", "--reason"}),
        frozenset(),
        _with_negations("--checkout", "--detach", "--force", "--guess-remote", "--lock", "--orphan", "--quiet",
                        "--relative-paths", "--track", "-d", "-f", "-q")
        | _negations("--reason")),
    "grep": Listed(
        frozenset({"-A", "-B", "-C", "-e", "-f", "-m", "--after-context", "--before-context", "--context",
                   "--max-count", "--max-depth", "--threads"}),
        frozenset({"-O"})),
    "update-index": Listed(
        frozenset({"--cacheinfo", "--chmod", "--index-version"}),
        frozenset(),
        _with_negations("--add", "--again", "--force-remove", "--force-untracked-cache", "--force-write-index",
                        "--fsmonitor", "--ignore-missing", "--ignore-skip-worktree-entries",
                        "--ignore-submodules", "--info-only", "--remove", "--replace", "--show-index-version",
                        "--split-index", "--test-untracked-cache", "--untracked-cache", "--unmerged",
                        "--verbose")
        | _negations("--index-version")
        | {"--assume-unchanged", "--no-assume-unchanged", "--clear-resolve-undo", "--fsmonitor-valid",
           "--no-fsmonitor-valid", "--index-info", "--really-refresh", "--refresh", "--skip-worktree",
           "--no-skip-worktree", "--stdin", "--unresolve", "-g", "-q", "-z"}),
    "update-ref": Listed(
        frozenset({"-m"}),
        frozenset(),
        _with_negations("--batch-updates", "--create-reflog", "--stdin", "-0")
        | {"--deref", "--no-deref", "-d", "-z"}),
}

STASH_WORDS_THAT_BRING_NOTHING = frozenset({"push", "save", "list", "show", "drop", "clear", "create", "store",
                                            "import", "export"})
STASH_WORDS_SAW_LEAVES_TO_YOU = frozenset({"apply", "pop", "branch"})
WORKTREE_WORDS_THAT_BRING_NOTHING = frozenset({"list", "lock", "unlock", "move", "prune", "remove", "repair"})
WORKTREE_WORDS_SAW_LEAVES_TO_YOU = frozenset({"add"})
SUBMODULE_WORDS_THAT_BRING_NOTHING = frozenset({"", "status", "init", "deinit", "sync", "summary",
                                                "absorbgitdirs", "set-branch", "set-url"})
SUBMODULE_WORDS_SAW_LEAVES_TO_YOU = frozenset({"add", "foreach"})
SUBMODULE_WORDS_SAW_CHECKS = frozenset({"update"})


def read(sub: str, args: list[str]) -> Reading:
    """Split a subcommand's arguments the way git does. Takes the subcommand, as `LISTED` names it,
    and the arguments after it. Returns the reading: an option saw does not list is read without a
    value, unless it is the leading part of a long option that takes the next word."""
    listed = LISTED.get(sub, Listed(frozenset()))
    next_word = listed.takes_the_next_word
    rest_of_word = listed.takes_the_rest_of_its_word
    no_word = listed.takes_no_word
    known = no_word is not None
    options: list[tuple[str, str | None]] = []
    words: list[str] = []
    index = 0
    options_end = False
    while index < len(args):
        arg = args[index]
        index += 1
        if arg == "--":
            return Reading(tuple(options), tuple(words), tuple(args[index:]), known)
        if options_end or arg == "-" or not arg.startswith("-"):
            words.append(arg)
            continue
        if arg == "--end-of-options":
            options_end = True
            continue
        if arg.startswith("--"):
            name, joined, value = arg.partition("=")
            if joined:
                options.append((name, value))
                known = known and (name in next_word or name in no_word)
            elif name in next_word:
                options.append((name, args[index] if index < len(args) else None))
                known = known and index < len(args)
                index += 1
            elif no_word is not None and name in no_word:
                options.append((name, None))
            elif len(name) > 2 and any(option.startswith(name) for option in next_word if option.startswith("--")):
                options.append((name, args[index] if index < len(args) else None))
                known = False
                index += 1
            else:
                options.append((name, None))
                known = False
            continue
        bundle = arg[1:]
        while bundle:
            name, bundle = "-" + bundle[0], bundle[1:]
            if name in next_word:
                value = bundle or (args[index] if index < len(args) else None)
                known = known and value is not None
                index += 0 if bundle else 1
                options.append((name, value))
                break
            if name in rest_of_word:
                options.append((name, bundle or None))
                break
            options.append((name, None))
            known = known and no_word is not None and name in no_word
    return Reading(tuple(options), tuple(words), (), known)
