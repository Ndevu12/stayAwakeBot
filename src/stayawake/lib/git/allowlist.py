#!/usr/bin/env python3
"""Which git commands each context may run, held as data."""
from __future__ import annotations

from dataclasses import dataclass

from stayawake.lib.git.contexts import (Context, UNTRUSTED, SAW_OWNED, OPERATOR_PUSH,
                                        OPERATOR_CONFIG, KEYS_A_CALLER_MAY_NOT_SET)

_GLOBAL_OPTIONS_WITH_VALUE = frozenset({"-c", "-C", "--git-dir", "--work-tree", "--namespace",
                                        "--exec-path", "--config-env"})

UNTRUSTED_SUBCOMMANDS = frozenset({
    "cat-file", "ls-tree", "rev-list", "rev-parse", "for-each-ref", "show-ref", "merge-base",
    "diff", "diff-tree", "log", "show", "ls-files", "hash-object", "read-tree", "write-tree",
    "update-index", "commit-tree", "mktree", "update-ref", "config", "symbolic-ref", "remote",
    "tag", "worktree", "check-attr",
})

DIFF_SUBCOMMANDS = frozenset({"diff", "diff-tree", "log", "show"})
"""Run with `--no-textconv --no-ext-diff` inserted, so no diff driver the repository names runs."""

_SIGNATURE_READERS = frozenset({"--show-signature"})
_TEXT_CONVERTERS = frozenset({"--textconv", "--ext-diff", "--filters"})

_REFUSED_ARGUMENTS = {
    "cat-file": _TEXT_CONVERTERS | {"--path"},
    "diff": _TEXT_CONVERTERS | _SIGNATURE_READERS | {"--no-index"},
    "diff-tree": _TEXT_CONVERTERS | _SIGNATURE_READERS,
    "log": _TEXT_CONVERTERS | _SIGNATURE_READERS,
    "show": _TEXT_CONVERTERS | _SIGNATURE_READERS,
    "rev-list": _SIGNATURE_READERS,
    "ls-files": frozenset({"-m", "--modified", "-d", "--deleted", "-k", "--killed", "--eol"}),
    "read-tree": frozenset({"-u"}),
    "update-index": frozenset({"--refresh", "--really-refresh", "--again", "-g", "--add"}),
    "config": frozenset({"--add", "--unset", "--unset-all", "--replace-all", "--rename-section",
                         "--remove-section", "-e", "--edit"}),
    "tag": frozenset({"-a", "--annotate", "-s", "--sign", "-u", "--local-user", "-m", "--message",
                      "-F", "--file", "-d", "--delete", "-v", "--verify", "-f", "--force", "-e",
                      "--edit"}),
    "symbolic-ref": frozenset({"-d", "--delete", "-m"}),
}

_REQUIRED_ONE_OF = {
    "hash-object": frozenset({"--no-filters"}),
    "update-index": frozenset({"--cacheinfo", "--index-info", "--force-remove", "--remove"}),
    "config": frozenset({"--get", "--get-all", "--get-regexp", "--get-urlmatch", "--list", "-l"}),
    "tag": frozenset({"-l", "--list", "--points-at", "--contains", "--no-contains", "--merged",
                      "--no-merged"}),
}

_ON_A_PRIVATE_INDEX = frozenset({"read-tree", "write-tree", "update-index"})
_UPDATE_INDEX_ADDS_BY_NAME = frozenset({"--cacheinfo", "--index-info"})

RAISE_ON_REFUSAL = False
"""Raise `GitRefused` instead of answering a refused command as a failure. The test suite sets it."""


class GitRefused(RuntimeError):
    """A git command saw asked for that its context does not allow."""


NETWORK_SUBCOMMANDS = frozenset({"push", "fetch", "ls-remote", "clone", "pull"})
OPERATOR_CONFIG_SUBCOMMANDS = frozenset({"config", "credential"})


@dataclass(frozen=True)
class Verdict:
    """Whether a command may run, why not, and whether it reads configuration as data."""

    refusal: str = ""
    subcommand: str = ""
    reads_configuration: bool = False


def split(args: list[str]) -> tuple[list[str], str, list[str]]:
    """Separate git's own options from the subcommand and its arguments. Takes the arguments.
    Returns `(global options, subcommand, the rest)`; the subcommand is "" when there is none."""
    i = 0
    while i < len(args) and args[i].startswith("-"):
        i += 2 if args[i] in _GLOBAL_OPTIONS_WITH_VALUE else 1
    if i >= len(args):
        return list(args), "", []
    return list(args[:i]), args[i], list(args[i + 1:])


def _named(arg: str, flags: frozenset[str]) -> bool:
    return arg in flags or arg.split("=", 1)[0] in flags


def _config_keys_set(global_options: list[str]) -> list[str]:
    keys, i = [], 0
    while i < len(global_options):
        if global_options[i] == "-c" and i + 1 < len(global_options):
            keys.append(global_options[i + 1].split("=", 1)[0].lower())
            i += 2
            continue
        if global_options[i] == "--config-env" or global_options[i].startswith("--config-env="):
            keys.append("*")
        i += 1
    return keys


def _positionals_before_separator(rest: list[str]) -> list[str]:
    out = []
    for arg in rest:
        if arg == "--":
            break
        if not arg.startswith("-"):
            out.append(arg)
    return out


def _reads_signatures(rest: list[str]) -> bool:
    for arg in rest:
        if arg.startswith(("--format=", "--pretty=")) and "%G" in arg:
            return True
        if "%(signature" in arg:
            return True
    return False


def _untrusted(sub: str, rest: list[str], env: dict | None) -> str:
    if sub not in UNTRUSTED_SUBCOMMANDS:
        return f"`git {sub}` can run code a repository configures"
    refused = _REFUSED_ARGUMENTS.get(sub, frozenset())
    for arg in rest:
        if arg == "--":
            break
        if _named(arg, refused):
            if sub == "update-index" and arg == "--add" and any(
                    _named(a, _UPDATE_INDEX_ADDS_BY_NAME) for a in rest):
                continue
            return f"`git {sub} {arg}` can run code a repository configures, or writes"
    required = _REQUIRED_ONE_OF.get(sub)
    if required and not any(_named(a, required) for a in rest):
        return f"`git {sub}` without one of {sorted(required)}"
    if _reads_signatures(rest):
        return f"`git {sub}` verifying a signature runs the repository's signature program"
    if sub in _ON_A_PRIVATE_INDEX and not (env or {}).get("GIT_INDEX_FILE"):
        return f"`git {sub}` outside a private GIT_INDEX_FILE touches the operator's index"
    if sub == "diff":
        revisions = _positionals_before_separator(rest)
        if len(revisions) < 2 and not any(".." in r for r in revisions):
            return "`git diff` against the working tree or index runs the repository's filters"
    if sub == "remote" and rest[:1] != ["get-url"]:
        return "`git remote` other than get-url"
    if sub == "worktree" and rest[:1] != ["list"]:
        return "`git worktree` other than list"
    if sub == "symbolic-ref" and len(_positionals_before_separator(rest)) != 1:
        return "`git symbolic-ref` writing a ref"
    return ""


def _reads_configuration(sub: str, rest: list[str]) -> bool:
    if sub == "config":
        return True
    return sub == "rev-parse" and any(a == "--git-path" for a in rest)


def judge(context: Context, args: list[str], env: dict | None) -> Verdict:
    """Decide whether `args` may run under `context`. Takes the context, the arguments and the
    caller's environment. Returns the verdict."""
    global_options, sub, rest = split(args)
    for key in _config_keys_set(global_options):
        if key == "*" or key in KEYS_A_CALLER_MAY_NOT_SET or key.startswith("protocol."):
            return Verdict(f"a caller may not set `{key}`", sub)
    if not sub:
        return Verdict("no git subcommand was named", sub)
    if context is UNTRUSTED:
        why = _untrusted(sub, rest, env)
        return Verdict(why, sub, not why and _reads_configuration(sub, rest))
    if context is SAW_OWNED:
        if sub in NETWORK_SUBCOMMANDS:
            return Verdict(f"`git {sub}` reaches a remote; that is OPERATOR_PUSH", sub)
        return Verdict("", sub)
    if context is OPERATOR_PUSH:
        if sub not in NETWORK_SUBCOMMANDS - {"pull"}:
            return Verdict(f"`git {sub}` is not a push, fetch, ls-remote or clone", sub)
        return Verdict("", sub)
    if context is OPERATOR_CONFIG:
        if sub not in OPERATOR_CONFIG_SUBCOMMANDS:
            return Verdict(f"`git {sub}` is not a configuration or credential question", sub)
        if sub == "credential" and rest != ["fill"]:
            return Verdict("`git credential` other than fill", sub)
        return Verdict("", sub)
    return Verdict(f"unknown context {context!r}", sub)
