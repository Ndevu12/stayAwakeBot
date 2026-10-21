#!/usr/bin/env python3
"""Reading JSON with comments and trailing commas, shared across the scanner (stdlib-only).

`load_jsonc` reads the shape of real-world `package.json`, `tsconfig.json`, VS Code settings and
lockfiles. `code_only` is the one lexer both it and the settings editor (`harden.jsonc`) stand on.
This is a leaf module imported by both `matchers/` and `dependencies/` so that neither package's
`__init__` has to run to reach it. `matchers.base` re-exports `load_jsonc`.
"""
from __future__ import annotations

import json
import re
from typing import Any

_BYTE_ORDER_MARK = "\N{ZERO WIDTH NO-BREAK SPACE}"
_STRING_OR_COMMENT_START = re.compile(r'["/]')
_STRING_OR_TRAILING_COMMA = re.compile(r'"|,(?=\s*[}\]])')
_STRING_END_OR_ESCAPE = re.compile(r'["\\]')
_NOT_NEWLINE = re.compile(r"[^\n]")


def _string_end(text: str, opening_quote: int) -> int:
    """The index just past the string whose opening quote is at `opening_quote`, or `len(text)`
    when the string never closes."""
    index = opening_quote + 1
    closing = text.find('"', index)
    if closing != -1 and text.find("\\", index, closing) == -1:
        return closing + 1
    while True:
        found = _STRING_END_OR_ESCAPE.search(text, index)
        if found is None:
            return len(text)
        if found.group() == '"':
            return found.end()
        index = found.end() + 1


def code_only(text: str) -> str:
    """`text` with every comment blanked out, character for character.

    Takes JSONC text. Returns a string of the same length in which each character of a `//` or
    `/* */` comment outside a string is a space (a newline inside a block comment is kept), so a
    position found in the result is the same position in `text`. An unterminated block comment
    is blanked to the end of the text.
    """
    pieces: list[str] = []
    kept_from, index, size = 0, 0, len(text)
    while True:
        found = _STRING_OR_COMMENT_START.search(text, index)
        if found is None:
            break
        start = found.start()
        if found.group() == '"':
            index = _string_end(text, start)
            continue
        following = text[start + 1:start + 2]
        if following == "/":
            newline = text.find("\n", start)
            end = size if newline == -1 else newline
        elif following == "*":
            close = text.find("*/", start + 2)
            end = size if close == -1 else close + 2
        else:
            index = start + 1
            continue
        pieces.append(text[kept_from:start])
        pieces.append(_NOT_NEWLINE.sub(" ", text[start:end]))
        kept_from = index = end
    pieces.append(text[kept_from:])
    return "".join(pieces)


def _without_trailing_commas(code: str) -> str:
    """`code` with each comma that is followed only by whitespace and then `}` or `]` removed.

    Takes comment-free JSONC text. Commas inside strings are kept.
    """
    pieces: list[str] = []
    kept_from, index = 0, 0
    while True:
        found = _STRING_OR_TRAILING_COMMA.search(code, index)
        if found is None:
            break
        start = found.start()
        if found.group() == '"':
            index = _string_end(code, start)
            continue
        pieces.append(code[kept_from:start])
        kept_from = index = start + 1
    pieces.append(code[kept_from:])
    return "".join(pieces)


def load_jsonc(text: str) -> Any:
    """The value a JSON-with-comments document holds.

    Takes its text, which may open with a byte-order mark. Returns the value, or None when the
    text is not such a document.
    """
    if text.startswith(_BYTE_ORDER_MARK):
        text = text[len(_BYTE_ORDER_MARK):]
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        try:
            return json.loads(_without_trailing_commas(code_only(text)))
        except json.JSONDecodeError:
            return None


def _skip_ws(text: str, index: int, end: int) -> int:
    while index < end and text[index] in " \t\r\n":
        index += 1
    return index


def _matching_end(text: str, open_at: int, open_ch: str, close_ch: str) -> int:
    depth = 0
    index = open_at
    size = len(text)
    while index < size:
        char = text[index]
        if char == '"':
            index = _string_end(text, index)
            continue
        if char == open_ch:
            depth += 1
        elif char == close_ch:
            depth -= 1
            if depth == 0:
                return index + 1
        index += 1
    return size


def _value_span(code: str, key: str) -> tuple[int, int] | None:
    needle = f'"{key}"'
    index = 0
    size = len(code)
    while index < size:
        at = code.find(needle, index)
        if at == -1:
            return None
        after = _skip_ws(code, at + len(needle), size)
        if after < size and code[after] == ":":
            after = _skip_ws(code, after + 1, size)
            if after < size and code[after] in "{[":
                close = "}" if code[after] == "{" else "]"
                return after, _matching_end(code, after, code[after], close)
        index = at + len(needle)
    return None


def object_spans(text: str, key: str) -> list[tuple[int, int]]:
    """The `[start, end)` of each object `key`'s array holds, or of the object itself.

    Takes the document and the key. Returns those spans in order, or none when `key` holds neither
    an object nor an array.
    """
    code = code_only(text)
    found = _value_span(code, key)
    if found is None:
        return []
    start, end = found
    if code[start] == "{":
        return [(start, end)]
    spans: list[tuple[int, int]] = []
    index = start + 1
    while index < end - 1:
        index = _skip_ws(code, index, end)
        if index >= end - 1:
            break
        char = code[index]
        if char == "{":
            obj_end = _matching_end(code, index, "{", "}")
            spans.append((index, obj_end))
            index = obj_end
        elif char == "[":
            index = _matching_end(code, index, "[", "]")
        elif char == '"':
            index = _string_end(code, index)
        else:
            index += 1
    return spans


def _quoted(value: str) -> list[str]:
    plain = json.dumps(value, ensure_ascii=False)
    escaped = json.dumps(value)
    return [plain] if plain == escaped else [plain, escaped]


def _holds(code: str, value: str, at: int, end: int) -> bool:
    if any(code.startswith(form, at) and at + len(form) <= end for form in _quoted(value)):
        return True
    if at >= end or code[at] != '"':
        return False
    stop = _string_end(code, at)
    if stop > end:
        return False
    try:
        return json.loads(code[at:stop]) == value
    except json.JSONDecodeError:
        return False


def _keys(code: str, key: str, start: int, end: int):
    needle = f'"{key}"'
    index = start
    while index < end:
        at = code.find(needle, index, end)
        if at == -1:
            return
        after = _skip_ws(code, at + len(needle), end)
        if after < end and code[after] == ":":
            yield at, _skip_ws(code, after + 1, end)
        index = at + len(needle)


def _bounded(text: str, span: tuple[int, int] | None):
    if span is None:
        return None
    code = code_only(text)
    start, end = span
    return code, max(0, start), min(end, len(code))


def line_of_entry(text: str, key: str, value: str, span: tuple[int, int] | None) -> int | None:
    """The 1-based line of `key`'s string value.

    Takes the document, the key, the value and the `[start, end)` span to look in. Returns the line
    of that value, or None when the span does not hold it.
    """
    bounded = _bounded(text, span)
    if bounded is None:
        return None
    code, start, end = bounded
    for _at, after in _keys(code, key, start, end):
        if _holds(code, value, after, end):
            return text.count("\n", 0, after) + 1
    return None


def line_of_key(text: str, key: str, span: tuple[int, int] | None) -> int | None:
    """The 1-based line of `key`.

    Takes the document, the key and the `[start, end)` span to look in. Returns the line of that
    key, or None when the span does not hold it.
    """
    bounded = _bounded(text, span)
    if bounded is None:
        return None
    code, start, end = bounded
    for at, _after in _keys(code, key, start, end):
        return text.count("\n", 0, at) + 1
    return None
