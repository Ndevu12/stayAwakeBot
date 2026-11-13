"""What in a command line marks it as running a payload: a download handed to an interpreter, a font file it
may run, or a known loader."""
from __future__ import annotations

import re
import shlex

from stayawake.bots.security.matchers.command_shape import (
    name_of, not_plain, runs_downloaded_or_decoded_code, simple_commands)
from stayawake.utils.invocation import resolve_invocation

FONT_FILE = re.compile(r"\.(?:woff2?|ttf|otf|eot)\b", re.IGNORECASE)
_EDITOR_VARIABLE = re.compile(r"\$\{[^${}\s]{1,200}\}")
_EXECUTABLE_SUFFIX = re.compile(r"\.(?:exe|cmd|bat)$", re.IGNORECASE)
_OUTPUT_OPTIONS = frozenset({"-o", "--out", "--output", "--out-file", "--output-file"})
_CODE_TAKING_FLAGS = frozenset({"--eval", "--print", "--command", "--execute", "--exec", "--run", "--require",
                                "--import", "--preload", "--loader"})
_SHORT_FLAGS = re.compile(r"-[A-Za-z]{1,20}")
_CODE_TAKING_LETTERS = frozenset("eEpcxr")
_PLAIN_PATH = re.compile(r"[\w./@+-]{1,500}")
_FONT_ENDING = re.compile(r"\.(?:woff2?|ttf|otf|eot)$", re.IGNORECASE)
_NODE = frozenset({"node", "nodejs"})
_JS_SCRIPT_ENDING = re.compile(r"\.[mc]?[jt]sx?$", re.IGNORECASE)


def _runs_a_disguised_asset(line: str) -> bool:
    """Tell whether Node is told to run a file whose extension is not JavaScript or TypeScript — a
    payload posing as a font or other asset, such as `node fa-brand-400.orc`. Takes the line; returns
    the answer."""
    for words in simple_commands(line):
        invocation = resolve_invocation(words)
        if name_of(invocation.interpreter or "") not in _NODE:
            continue
        path = invocation.payload_path
        if not path or path == invocation.interpreter:
            continue
        name = path.rsplit("/", 1)[-1]
        if "." in name and not _JS_SCRIPT_ENDING.search(name):
            return True
    return False


def plain_call(line: str) -> list[str] | None:
    """Return the words of a command line that is one plain call of a program, its program named without
    an executable suffix and in lower case, reading the editor's variables as plain words. Takes the line.
    Returns the words, or None when the line is more than one plain call."""
    plain = _EDITOR_VARIABLE.sub("variable", line)
    words = plain.split()
    if not words or not_plain(plain):
        return None
    return [_EXECUTABLE_SUFFIX.sub("", words[0]).lower(), *words[1:]]


def _one_call_of_a_font_tool(line: str, font_tools: frozenset[str]) -> bool:
    """Tell whether a command line is one plain call of a font tool named without a path. Takes the line
    and the font tools' names. Returns the answer."""
    words = plain_call(line)
    return words is not None and words[0] in font_tools


def _output_values(words: list[str]) -> list[str]:
    """List the values a command line gives its output options. Takes the words. Returns the values."""
    values = []
    for i, word in enumerate(words):
        option, equals, value = word.partition("=")
        if option in _OUTPUT_OPTIONS and (equals or i + 1 < len(words)):
            values.append(value if equals else words[i + 1])
    return values


def _hands_over_code(word: str) -> bool:
    """Tell whether a word is a flag that hands a program code or a file to load, alone or among other
    single-letter flags. Takes the word. Returns the answer."""
    flag = word.partition("=")[0]
    if flag in _CODE_TAKING_FLAGS:
        return True
    return bool(_SHORT_FLAGS.fullmatch(flag)) and not _CODE_TAKING_LETTERS.isdisjoint(flag[1:])


def _only_writes_fonts(line: str) -> bool:
    """Tell whether a command line is one plain call, handed no code or preload by a flag, that names a
    font file only as the file an output option writes, and whose program is not a font. Takes the line.
    Returns the answer."""
    plain = _EDITOR_VARIABLE.sub("variable", line)
    if not_plain(plain):
        return False
    try:
        words = shlex.split(plain)
    except ValueError:
        return False
    if any(_hands_over_code(word) for word in words):
        return False
    written = [value for value in _output_values(words) if FONT_FILE.search(value)]
    if not written or not all(_PLAIN_PATH.fullmatch(value) and _FONT_ENDING.search(value)
                              for value in written):
        return False
    if len(FONT_FILE.findall(plain)) != sum(len(FONT_FILE.findall(value)) for value in written):
        return False
    return not FONT_FILE.search(resolve_invocation(words).payload_path or "")


def may_run_a_font(line: str, font_tools: frozenset[str], *, lifts: bool = True) -> bool:
    """Tell whether a command line runs a font file, or hands Node a file posing as one. Takes the line,
    the font tools' names and whether a plain call of a font tool, or a line that only writes fonts, is
    let through. Returns the answer."""
    if not FONT_FILE.search(line):
        return _runs_a_disguised_asset(line)
    return not (lifts and (_one_call_of_a_font_tool(line, font_tools) or _only_writes_fonts(line)))


def runs_a_payload(line: str, loader_check, font_tools: frozenset[str]) -> bool:
    """Tell whether a command line downloads or decodes code and runs it, names a font file it may run, or
    carries a known loader. Takes the line, the known-loader check (or None) and the font tools' names.
    Returns the answer."""
    return bool(runs_downloaded_or_decoded_code(line) or may_run_a_font(line, font_tools)
                or (loader_check and loader_check(line)))
