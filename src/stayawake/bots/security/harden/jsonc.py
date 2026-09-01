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


def _key_pattern(key: str) -> re.Pattern:
    return re.compile(r'("' + re.escape(key) + r'"\s*:\s*)("[^"]*"|true|false|null|-?[\d.]+)')


def value_at(text: str, key: str) -> str | None:
    """The literal at `key`, or None when the key is not there or holds a structure.

    A structure is not a value this can speak about: an object has no single literal to compare or
    replace, and pretending otherwise is how an edit lands somewhere it was not aimed.
    """
    found = _key_pattern(key).search(text)
    return found.group(2) if found else None


def set_value(text: str, key: str, value: str) -> tuple[str, Edit] | None:
    """`text` with `key` set to the literal `value`. None when it could not be done exactly once.

    Refuses on more than one match rather than editing the first: a key that appears twice is
    either nested inside another object or duplicated, and neither is a place to guess.
    """
    matches = list(_key_pattern(key).finditer(text))
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
    """
    body = text.rstrip()
    if not body.startswith("{") or not body.endswith("}"):
        return None
    inner = body[1:-1]
    entry = f'"{key}": {value}'
    if not inner.strip():
        return "{\n  " + entry + "\n}\n", Edit(key, value)
    separator = "" if inner.rstrip().endswith(",") else ","
    indent = _indent_of(inner)
    return (body[:-1].rstrip() + separator + "\n" + indent + entry + "\n}\n",
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
