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
