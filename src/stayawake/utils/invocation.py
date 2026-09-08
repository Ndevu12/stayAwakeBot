#!/usr/bin/env python3
"""Resolve one command line into what it executes.

`resolve_invocation(argv)` returns an `Invocation` naming the interpreter, the file it runs, the
arguments that are code, and whether the program arrives on standard input.
"""
from __future__ import annotations

import os
import re
from dataclasses import dataclass


POSIX_SHELLS = ("sh", "bash", "zsh", "dash", "ksh")


_INTERPRETERS = frozenset({
    "node", "nodejs", "deno", "bun", "python", "python2", "python3", "ruby", "perl", "php",
    "sh", "bash", "zsh", "dash", "ksh", "osascript", "tsx", "ts-node"})


_STDIN_FLAGS = {
    **{shell: frozenset({"-s"}) for shell in POSIX_SHELLS},
    "python": frozenset({"-"}), "python2": frozenset({"-"}), "python3": frozenset({"-"}),
    "node": frozenset({"-"}), "nodejs": frozenset({"-"}), "deno": frozenset({"-"}),
    "bun": frozenset({"-"}), "ruby": frozenset({"-"}), "perl": frozenset({"-"}),
    "php": frozenset({"-r-"}),
}


_CODE_FLAGS = {
    **{shell: frozenset({"-c"}) for shell in POSIX_SHELLS},
    "python": frozenset({"-c"}), "python2": frozenset({"-c"}), "python3": frozenset({"-c"}),
    "node": frozenset({"-e", "--eval", "-p", "--print"}),
    "nodejs": frozenset({"-e", "--eval", "-p", "--print"}),
    "deno": frozenset({"-e", "--eval"}), "bun": frozenset({"-e", "--eval"}),
    "ruby": frozenset({"-e"}), "perl": frozenset({"-e", "-E"}), "php": frozenset({"-r"}),
    "osascript": frozenset({"-e"}),
}

_MODULE_FLAGS = {"python": frozenset({"-m"}), "python2": frozenset({"-m"}),
                 "python3": frozenset({"-m"})}

_SHELL_C_FLAG = re.compile(r"-[A-Za-z]{0,4}c")

_EXEC_WRAPPERS = frozenset({"env", "sudo", "nohup", "nice", "setsid", "exec", "command", "stdbuf",
                            "time", "doas"})
_WRAPPER_VALUE_OPTS = {
    "sudo":   frozenset({"-u", "--user", "-g", "--group", "-p", "--prompt", "-C", "--close-from",
                         "-h", "--host", "-r", "--role", "-t", "--type", "-U", "--other-user"}),
    "doas":   frozenset({"-u", "-C"}),
    "env":    frozenset({"-u", "--unset", "-C", "--chdir", "-S", "--split-string"}),
    "nice":   frozenset({"-n", "--adjustment"}),
    "stdbuf": frozenset({"-i", "--input", "-o", "--output", "-e", "--error"}),
    "time":   frozenset({"-f", "--format", "-o", "--output"}),
}
_SYSTEM_BIN_DIRS = frozenset({"/bin", "/usr/bin", "/usr/local/bin", "/sbin", "/usr/sbin",
                              "/opt/homebrew/bin", "/opt/local/bin"})
_ASSIGNMENT = re.compile(r"[A-Za-z_]\w{0,255}=")

_EXE_SUFFIXES = frozenset({"exe", "bat", "cmd", "com"})


@dataclass(frozen=True)
class Invocation:
    """What one command line actually executes, resolved ONCE.

    Four consumers used to answer this separately — which file to read, whether referenced content is
    shell, which arguments are code, which lines take shell grammar — from argv[0] or from a regex over
    the joined argv. Four partial answers to one question is how they disagreed."""
    interpreter: str | None = None
    is_posix_shell: bool = False
    payload_path: str | None = None
    code_args: tuple[str, ...] = ()
    reads_stdin: bool = False


def _program_name(arg: str) -> str:
    """The comparable name of a program path: `/usr/bin/Node` → `node`, `python3.12` → `python3`.

    ONE authority — interpreters, shells, carriers, wrappers and boundaries all compare through it,
    so a name added to any of those sets matches every spelling of it. Two defects came from having
    three spellings of this question, and both were silent:

    Case. 

    Suffix. Stripping everything after the first dot read `/tmp/.x/node.evil.js` as the *interpreter*
    `node`, so the payload's own path was lost and its CONTENT was never read: naming a dropper after
    an interpreter bought it less analysis than naming it anything else. Only a trailing version
    component or an executable extension is a suffix; `.js`, `.sh` and `.backdoor` are part of the
    name."""
    name = os.path.basename(arg).casefold()
    while True:
        stem, dot, suffix = name.rpartition(".")
        if not dot or not (suffix.isdigit() or suffix in _EXE_SUFFIXES):
            return name
        name = stem


def _wrapper_name(arg: str) -> str | None:
    """The wrapper this token names, or None. The basename must match EXACTLY and sit unqualified or
    in a system bin dir — otherwise a payload at `/tmp/.x/env.sh` or `/tmp/.x/command` is skipped as a
    wrapper and the scratch path it names is never checked."""
    name = _program_name(arg)
    if name not in _EXEC_WRAPPERS:
        return None
    parent = os.path.dirname(arg)
    return name if parent == "" or parent in _SYSTEM_BIN_DIRS else None


def _program_index(argv: list[str]) -> int:
    """Index of the real program — the first token that is not a wrapper, a wrapper's option, or a
    `VAR=value` assignment."""
    i = 0
    while i < len(argv):
        wrapper = _wrapper_name(argv[i])
        if wrapper is None:
            break
        value_opts = _WRAPPER_VALUE_OPTS.get(wrapper, frozenset())
        i += 1
        while i < len(argv):
            arg = argv[i]
            if arg in value_opts:
                i += 2
            elif (arg.startswith("-") and arg != "-") or _ASSIGNMENT.match(arg):
                i += 1
            else:
                break
    return i


def resolve_invocation(argv) -> Invocation:
    """Resolve ONE command line — which file it runs. Per command line, never per entry: `entry.argv`
    is only the first of them, and `_invocations` covers the rest.

    Every field is a POSITIVE identification or absent. A walk that loses the line returns no payload
    rather than a guess: guessing resolved `su -c '<payload>' user` to the command STRING as a path,
    which matched the scratch check by luck and handed an invented path to the file reader."""
    argv = list(argv or [])
    if not argv:
        return Invocation()
    i = _program_index(argv)
    if i >= len(argv) or argv[i].startswith("-"):
        return Invocation()                    # the walk lost the line — say so, do not invent
    interp, rest = argv[i], argv[i + 1:]
    base = _program_name(interp)
    if base not in _INTERPRETERS:
        return Invocation(interpreter=interp, payload_path=interp)
    code_flags = _CODE_FLAGS.get(base, frozenset())
    module_flags = _MODULE_FLAGS.get(base, frozenset())
    stdin_flags = _STDIN_FLAGS.get(base, frozenset())
    code, path, from_stdin = [], None, False
    for n, arg in enumerate(rest):
        if arg in stdin_flags:
            from_stdin = True
        if arg in code_flags or (base in POSIX_SHELLS and _SHELL_C_FLAG.fullmatch(arg)):
            if n + 1 < len(rest):
                code.append(rest[n + 1])
            break              # what follows the code is an argument TO it ($0, $@) — never a path
        if arg in module_flags:
            break              # a module NAME, and what follows is the module's own argv
        if not arg.startswith("-"):
            path = arg
            break
    # No script argument means there is no file this runs: the code is inline, or it names a module.
    # Reporting the interpreter would send the reader 133 KB of `/bin/sh` to content-scan.
    return Invocation(interpreter=interp, is_posix_shell=base in POSIX_SHELLS,
                      payload_path=path, code_args=tuple(code), reads_stdin=from_stdin)
