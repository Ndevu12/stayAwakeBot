#!/usr/bin/env python3
"""Change one value in a JSONC settings file, and nothing else about the file.

The file belongs to the person running this. It is JSON with comments and trailing commas, so
`json.loads` refuses it and `json.dumps` would hand back a file with their comments gone and every
line reflowed. Either is a worse outcome than the setting this is here to correct.

So the value is replaced where it sits and the rest of the bytes are carried through untouched. The
caller reads the result back afterwards rather than trusting that this did what it says.
"""
from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass(frozen=True)
class Edit:
    """One value to put at one key, and what is there now (`None` when the key is absent)."""

    key: str
    value: str
    was: str | None = None

    @property
    def adds(self) -> bool:
        return self.was is None


def code_only(text: str) -> str:
    """`text` with every comment blanked out, character for character.

    Positions still line up, so a search runs on this and the slice comes from the original.

    TRAP: a settings file is JSONC, and a comment is not code. A regex over raw text edits the
    key inside someone's commented-out note — changing nothing the editor reads while reporting a
    correction, and inverting what they wrote.
    """
    out = list(text)
    index, size, in_string, escaped = 0, len(text), False, False
    while index < size:
        char = text[index]
        if in_string:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                in_string = False
            index += 1
            continue
        if char == '"':
            in_string = True
            index += 1
            continue
        if char == "/" and index + 1 < size and text[index + 1] == "/":
            while index < size and text[index] != "\n":
                out[index] = " "
                index += 1
            continue
        if char == "/" and index + 1 < size and text[index + 1] == "*":
            while index < size and not (text[index] == "/" and index and text[index - 1] == "*"):
                if text[index] != "\n":
                    out[index] = " "
                index += 1
            if index < size:
                out[index] = " "
                index += 1
            continue
        index += 1
    return "".join(out)


def _key_pattern(key: str) -> re.Pattern:
    return re.compile(r'("' + re.escape(key) + r'"\s*:\s*)("[^"]*"|true|false|null|-?[\d.]+)')


def value_at(text: str, key: str) -> str | None:
    """The literal at `key`, or None when the key is not there or holds a structure.

    A structure is not a value this can speak about: an object has no single literal to compare or
    replace, and pretending otherwise is how an edit lands somewhere it was not aimed.
    """
    found = _key_pattern(key).search(code_only(text))
    return found.group(2) if found else None


def set_value(text: str, key: str, value: str) -> tuple[str, Edit] | None:
    """`text` with `key` set to the literal `value`. None when it could not be done exactly once.

    Refuses on more than one match rather than editing the first: a key that appears twice is
    either nested inside another object or duplicated, and neither is a place to guess.
    """
    matches = list(_key_pattern(key).finditer(code_only(text)))
    if len(matches) > 1:
        return None
    if matches:
        found = matches[0]
        if found.group(2) == value:
            return None
        edited = text[:found.start(2)] + value + text[found.end(2):]
        return edited, Edit(key, value, found.group(2))
    return _append_key(text, key, value)


def _append_key(text: str, key: str, value: str) -> tuple[str, Edit] | None:
    """Add `"key": value` as the last member of the outermost object.

    Only when that object is unambiguous: the file has to open with `{` and close with the last
    `}` in it. Anything else is a shape this does not understand well enough to write into.

    TRAP: where the object ENDS and where its last member ends are read from the comment-blanked
    text, and the separating comma goes after the member — never after a trailing comment, which
    swallows it and leaves the file unparseable.
    """
    masked = code_only(text)
    body = masked.rstrip()
    if not body.startswith("{") or not body.endswith("}"):
        return None
    entry = f'"{key}": {value}'
    closing = len(body) - 1
    last_code = len(masked[:closing].rstrip())
    if last_code <= 0:
        return None
    if masked[last_code - 1] == "{":                     # an object with nothing in it yet
        return text[:last_code] + "\n  " + entry + "\n" + text[closing:], Edit(key, value)
    separator = "" if masked[last_code - 1] == "," else ","
    indent = _indent_of(masked[1:closing])
    tail = text[last_code:closing]
    if not tail.endswith("\n"):
        tail += "\n"
    return (text[:last_code] + separator + tail + indent + entry + "\n" + text[closing:],
            Edit(key, value))


def _indent_of(inner: str) -> str:
    """The indentation the file already uses, so an added line matches the ones around it."""
    for line in inner.splitlines():
        if line.strip() and not line.strip().startswith(("//", "/*", "*")):
            return line[:len(line) - len(line.lstrip())] or "  "
    return "  "


def set_member(text: str, key: str, member: str, value: str) -> tuple[str, Edit] | None:
    """Set `member` inside the object at `key` — for a setting whose value is a table of entries.

    Only an existing member is written. Adding one would be inventing an entry the person never
    had, and removing one would be taking away something this cannot put back.
    """
    opened = re.search(r'"' + re.escape(key) + r'"\s*:\s*\{', text)
    if opened is None:
        return None
    depth, end = 0, None
    for index in range(opened.end() - 1, len(text)):
        if text[index] == "{":
            depth += 1
        elif text[index] == "}":
            depth -= 1
            if depth == 0:
                end = index
                break
    if end is None:
        return None
    inside = text[opened.end():end]
    pattern = re.compile(r'("' + re.escape(member) + r'"\s*:\s*)(true|false)')
    matches = list(pattern.finditer(inside))
    if len(matches) != 1 or matches[0].group(2) == value:
        return None
    found = matches[0]
    start = opened.end() + found.start(2)
    stop = opened.end() + found.end(2)
    return text[:start] + value + text[stop:], Edit(f"{key}.{member}", value, found.group(2))
