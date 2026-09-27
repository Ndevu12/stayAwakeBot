#!/usr/bin/env python3
"""The shape of a command line git hands to a program: whether it is one plain call of a named
program, and whether a stage that downloads feeds a stage that runs what it reads as code."""
from __future__ import annotations

import os
import re
import shlex

SHELLS = frozenset({"sh", "bash", "zsh", "dash", "ksh", "mksh", "ash", "fish", "tcsh", "csh",
                    "yash", "rbash", "pwsh", "powershell", "cmd", "source", "."})
_CODE_FROM_INPUT = frozenset({"python", "pypy", "node", "nodejs", "bun", "deno", "perl", "ruby",
                              "php", "lua", "luajit", "rscript", "r", "julia", "tclsh", "osascript"})
_INLINE_FLAGS = {"python": "c", "pypy": "c", "node": "ep", "nodejs": "ep", "bun": "e",
                 "perl": "eE", "ruby": "e", "php": "rR", "rscript": "e", "r": "e", "lua": "e",
                 "luajit": "e", "julia": "e", "osascript": "e"}
_INLINE_LONG = frozenset({"--eval", "--print", "--command", "--execute", "--exec", "--run"})
_WRAPPERS = frozenset({"env", "sudo", "doas", "command", "exec", "nohup", "nice", "setsid",
                       "stdbuf", "time", "timeout", "busybox", "xargs", "chronic", "unbuffer",
                       "flock", "script", "su", "runuser", "chroot", "ionice", "taskset"})
FETCHERS = frozenset({"curl", "wget", "nc", "ncat", "netcat", "socat", "aria2c", "fetch", "ftp",
                      "tftp", "scp", "sftp", "rsync", "ssh", "http", "https", "lwp-request",
                      "lwp-download", "get"})
_OPERATORS = frozenset({"|", "||", "&", "&&", ";", ";;", "<", ">", ">>", "<<", "<<<", "(", ")",
                        "|&", "<&", ">&", "<>", ">|"})
_SHELL_SYNTAX = re.compile(r"[$`\\\n\r;|&<>(){}\[\]*?!#]")
_POSITIONAL = re.compile(r"(?<![\w$])\$[0-9@*](?![\w{(])")
_PLAIN_WORD = re.compile(r"[\w./%:=@+,~-]+")
_VERSIONED = re.compile(r"^([a-z]+?)[\d.]*(?:\.exe)?$")
_ANSI_C = re.compile(r"\$'((?:[^'\\]|\\.){0,4096})'")
_SHELL_READS_DOWNLOAD = re.compile(
    r"(?:^|[\s;&|(])(?:\S*/)?(?:sh|bash|zsh|dash|ksh|ash|source|\.)(?:\s+-\S+){0,4}\s*<?\s*<\(\s*"
    r"(?:\S*/)?(?:curl|wget|nc|ncat|socat|aria2c|ssh|scp|rsync|ftp|tftp)\b")
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
    """Split a command line as a POSIX shell would, keeping operators as tokens and a newline as
    a separator. Takes the text. Returns the tokens, or None when it does not split."""
    try:
        lexer = shlex.shlex(_decoded(text).replace("\n", " ; "), posix=True,
                            punctuation_chars=True)
        lexer.whitespace_split = True
        return list(lexer)
    except ValueError:
        return None


def name_of(token: str) -> str:
    """A program's name as a word names it: its basename, lowercased, version suffix dropped."""
    base = os.path.basename(token).lower()
    found = _VERSIONED.match(base)
    return found.group(1) if found else base


def plain_words(text: str) -> list[str] | None:
    """The words of `text` when it is one plain program call: nothing a shell reads as syntax,
    only plain words, each optionally quoted; the arguments git appends may be named as `$1`,
    `$@` and the like. Takes the text. Returns None otherwise."""
    text = _POSITIONAL.sub("argument", text)
    if _SHELL_SYNTAX.search(text):
        return None
    try:
        words = shlex.split(text, posix=True)
    except ValueError:
        return None
    if not words or not all(_PLAIN_WORD.fullmatch(w) for w in words):
        return None
    return words


def _runner(words: list[str]) -> tuple[str, list[str]]:
    """The program a simple command runs and its arguments. Takes its words. A wrapper at its head
    is looked through to the first shell or interpreter it names, else its first operand."""
    rest = [w for w in words if not ("=" in w and w.split("=", 1)[0].isidentifier())]
    if not rest:
        return "", []
    if name_of(rest[0]) not in _WRAPPERS:
        return name_of(rest[0]), rest[1:]
    for i, word in enumerate(rest[1:], 1):
        if name_of(word) in SHELLS or name_of(word) in _CODE_FROM_INPUT:
            return name_of(word), rest[i + 1:]
    for i, word in enumerate(rest[1:], 1):
        if not word.startswith("-"):
            return name_of(word), rest[i + 1:]
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
    """Whether a program is handed code as an argument. Takes its name and arguments."""
    if name == "deno":
        return "eval" in args
    if any(a.split("=", 1)[0] in _INLINE_LONG for a in args):
        return name in _INLINE_FLAGS or name in SHELLS
    letters = _INLINE_FLAGS.get(name, "")
    for arg in args:
        flag = None if arg.startswith("--") else re.match(r"-([A-Za-z]+)", arg)
        if flag and any(c in flag.group(1) for c in letters):
            return True
    return False


def _reads_code(name: str, args: list[str]) -> bool:
    """Whether a stage runs what it reads from its input as code. Takes its program and
    arguments."""
    if name in SHELLS:
        dash_c = next((i for i, a in enumerate(args)
                       if a.startswith("-") and not a.startswith("--") and "c" in a[1:]), None)
        return dash_c is None or dash_c == len(args) - 1
    if name in _CODE_FROM_INPUT:
        operands = [a for a in args if not a.startswith("-") or a == "-"]
        return "-m" not in args and not _inline(name, args) and operands in ([], ["-"])
    return False


def _shell_scripts(tokens: list[str]) -> list[str]:
    """The scripts a shell in these tokens is handed with `-c`. Takes the tokens. Returns them."""
    scripts = []
    for line in _commands(tokens):
        for words in line:
            name, args = _runner(words)
            if name not in SHELLS:
                continue
            for i, arg in enumerate(args[:-1]):
                if arg.startswith("-") and not arg.startswith("--") and "c" in arg[1:]:
                    scripts.append(args[i + 1])
                    break
    return scripts


def not_plain(text: str) -> list[str]:
    """Why a command line is more than one plain program call. Takes the text. Returns the
    reasons; empty only when it is plain words."""
    tokens = _tokens(text)
    if tokens is None:
        return ["its command line does not parse"]
    reasons = []
    if _SHELL_SYNTAX.search(_POSITIONAL.sub("argument", text)):
        reasons.append("it is a shell command line, not a single program")
    for line in _commands(tokens):
        for words in line:
            name, args = _runner(words)
            if name in SHELLS:
                reasons.append(f"it runs a shell ({name})")
            elif _inline(name, args):
                reasons.append(f"it hands code to {name} inline")
    return list(dict.fromkeys(reasons))


def feeds_a_download_to_a_runner(text: str, _depth: int = 0) -> bool:
    """Whether a stage that downloads feeds, through a pipe, a later stage that runs what it
    reads as code, or a shell reads a download through process substitution, including inside a
    script a shell is handed with `-c`. Takes the text."""
    if _SHELL_READS_DOWNLOAD.search(_decoded(text)):
        return True
    tokens = _tokens(text)
    if tokens is None:
        return False
    if _depth < _MAX_DEPTH and any(feeds_a_download_to_a_runner(script, _depth + 1)
                                   for script in _shell_scripts(tokens)):
        return True
    for line in _commands(tokens):
        stages = [_runner(words) for words in line]
        for i, (name, _args) in enumerate(stages):
            if name in FETCHERS and any(_reads_code(n, a) for n, a in stages[i + 1:]):
                return True
    return False
