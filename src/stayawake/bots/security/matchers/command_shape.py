#!/usr/bin/env python3
"""The shape of a command line git hands to a program: whether it is one plain program call, and
whether a stage that downloads feeds a stage that runs what it is given."""
from __future__ import annotations

import os
import re
import shlex

SHELLS = frozenset({"sh", "bash", "zsh", "dash", "ksh", "mksh", "ash", "fish", "pwsh",
                    "powershell", "cmd", "source", "."})
_INLINE_FLAGS = {"python": "c", "pypy": "c", "node": "ep", "nodejs": "ep", "bun": "e",
                 "deno": "", "perl": "eE", "ruby": "e", "php": "r", "rscript": "e", "lua": "e",
                 "luajit": "e", "osascript": "e", "tclsh": "", "awk": "", "gawk": "", "mawk": ""}
INTERPRETERS = frozenset(_INLINE_FLAGS)
_WRAPPERS = frozenset({"env", "sudo", "doas", "command", "exec", "nohup", "nice", "setsid",
                       "stdbuf", "time", "timeout", "busybox", "xargs", "chronic", "unbuffer"})
FETCHERS = frozenset({"curl", "wget", "nc", "ncat", "netcat", "socat", "aria2c", "fetch", "ftp",
                      "tftp", "scp", "sftp", "rsync", "ssh", "http", "https", "lwp-request",
                      "lwp-download", "get"})
_OPERATORS = frozenset({"|", "||", "&", "&&", ";", ";;", "<", ">", ">>", "<<", "<<<", "(", ")",
                        "|&", "<&", ">&", "<>", ">|"})
_EXPANSION = re.compile(r"\$[({']|`")
_VERSIONED = re.compile(r"^([a-z]+?)[\d.]*(?:\.exe)?$")
_ANSI_C = re.compile(r"\$'((?:[^'\\]|\\.){0,4096})'")
_MAX_DEPTH = 3


def _decoded(text: str) -> str:
    """`text` with each `$'…'` string written out as bash reads it. Takes the text."""
    def expand(found: re.Match) -> str:
        try:
            return shlex.quote(found.group(1).encode("latin-1", "backslashreplace")
                               .decode("unicode_escape"))
        except (UnicodeError, ValueError):
            return found.group(0)
    return _ANSI_C.sub(expand, text)


def _tokens(text: str) -> list[str] | None:
    """Split a command line as a POSIX shell would, keeping operators as tokens. Takes the text.
    Returns the tokens, or None when it does not split."""
    try:
        lexer = shlex.shlex(_decoded(text), posix=True, punctuation_chars=True)
        lexer.whitespace_split = True
        return list(lexer)
    except ValueError:
        return None


def _name(token: str) -> str:
    base = os.path.basename(token).lower()
    found = _VERSIONED.match(base)
    return found.group(1) if found else base


def program(words: list[str]) -> tuple[str, list[str]]:
    """The program a simple command runs, past any wrapper and assignment. Takes its words.
    Returns the program's name and its arguments."""
    rest = list(words)
    while rest:
        head = rest[0]
        if "=" in head and not head.startswith(("-", "/", ".")) and head.split("=", 1)[0].isidentifier():
            rest.pop(0)
            continue
        name = _name(head)
        if name in _WRAPPERS:
            rest.pop(0)
            while rest and (rest[0].startswith("-") or rest[0].replace(".", "").isdigit()
                            or ("=" in rest[0] and rest[0].split("=", 1)[0].isidentifier())):
                rest.pop(0)
            continue
        return name, rest[1:]
    return "", []


def _commands(tokens: list[str]) -> list[list[list[str]]]:
    """Group tokens into pipelines of simple commands. Takes the tokens. Returns the pipelines."""
    pipelines: list[list[list[str]]] = [[[]]]
    for token in tokens:
        if token in ("|", "|&"):
            pipelines[-1].append([])
        elif token in _OPERATORS:
            pipelines.append([[]])
        else:
            pipelines[-1][-1].append(token)
    return [[stage for stage in line if stage] for line in pipelines if any(line)]


def _inline(name: str, args: list[str]) -> bool:
    letters = _INLINE_FLAGS.get(name)
    if letters is None:
        return False
    if name == "deno":
        return "eval" in args
    if not letters:
        return bool(args)
    for arg in args:
        if arg.startswith("-") and not arg.startswith("--"):
            flag = re.match(r"-([A-Za-z]+)", arg)
            if flag and any(c in flag.group(1) for c in letters):
                return True
    return False


def _shell_scripts(tokens: list[str]) -> list[str]:
    """The scripts a shell in these tokens is handed with `-c`. Takes the tokens. Returns them."""
    scripts = []
    for line in _commands(tokens):
        for words in line:
            name, args = program(words)
            if name not in SHELLS:
                continue
            for i, arg in enumerate(args[:-1]):
                if arg.startswith("-") and not arg.startswith("--") and "c" in arg[1:]:
                    scripts.append(args[i + 1])
                    break
    return scripts


def not_plain(text: str) -> list[str]:
    """Why a command line is more than one plain program call. Takes the text. Returns the
    reasons, empty when it is one program run with arguments."""
    tokens = _tokens(text)
    if tokens is None:
        return ["its command line does not parse"]
    reasons = []
    if any(t in _OPERATORS for t in tokens) or _EXPANSION.search(text):
        reasons.append("it is a shell command line, not a single program")
    for line in _commands(tokens):
        for words in line:
            name, args = program(words)
            if name in SHELLS:
                reasons.append(f"it runs a shell ({name})")
            elif _inline(name, args):
                reasons.append(f"it hands code to {name} inline")
    return list(dict.fromkeys(reasons))


def feeds_a_download_to_a_runner(text: str, _depth: int = 0) -> bool:
    """Whether a stage that downloads feeds, through a pipe, a later stage that runs what it is
    given, or a shell reads a download through process substitution, including inside a script a
    shell is handed with `-c`. Takes the text."""
    tokens = _tokens(text)
    if tokens is None:
        return False
    if _depth < _MAX_DEPTH and any(feeds_a_download_to_a_runner(script, _depth + 1)
                                   for script in _shell_scripts(tokens)):
        return True
    for line in _commands(tokens):
        names = [program(words)[0] for words in line]
        for i, name in enumerate(names):
            if name in FETCHERS and any(n in SHELLS or n in INTERPRETERS for n in names[i + 1:]):
                return True
    substituted = re.search(r"<\(\s*([^\s()]+)", text)
    if substituted and _name(substituted.group(1)) in FETCHERS:
        return any(program(words)[0] in SHELLS for line in _commands(tokens) for words in line)
    return False
