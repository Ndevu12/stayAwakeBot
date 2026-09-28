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

from stayawake.bots.security.jsonc import code_only


@dataclass(frozen=True)
class Edit:
    """One value to put at one key, and what is there now (`None` when the key is absent)."""

    key: str
    value: str
    was: str | None = None

    @property
    def adds(self) -> bool:
        return self.was is None


_STRING = r'"(?:[^"\\]|\\.)*"'
_NUMBER = r'-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?'


def _key_pattern(key: str) -> re.Pattern:
    return re.compile(r'("' + re.escape(key) + r'"\s*:\s*)(' + _STRING + r'|true|false|null|'
                      + _NUMBER + r')')


def _member_pattern(key: str) -> re.Pattern:
    return re.compile(r'"' + re.escape(key) + r'"\s*:\s*(?=[\[{])')


def value_at(text: str, key: str) -> str | None:
    """The literal at `key`, or None when the key is not there or holds a structure.

    A structure is not a value this can speak about: an object has no single literal to compare or
    replace, and pretending otherwise is how an edit lands somewhere it was not aimed.
    """
    found = _key_pattern(key).search(code_only(text))
    return found.group(2) if found else None


def remove_key(text: str, key: str) -> tuple[str, Edit] | None:
    """`text` with every top-level member at `key` holding a literal taken out.

    Takes the file's text and the key. Returns the text and the last value the key held, or None
    when the key is not there at the top level. The separator that joined each one to its
    neighbour goes with it.
    """
    blanked = code_only(text)
    matches = list(_key_pattern(key).finditer(blanked))
    tops = _at_top_level(blanked, [m.start() for m in matches])
    spans = [(m.start(), m.end(2), m.group(2)) for m in matches if m.start() in tops]
    if not spans:
        return None
    return _cut(text, blanked, [(a, b) for a, b, _ in spans]), Edit(key, "", spans[-1][2])


def _at_top_level(blanked: str, starts) -> set[int]:
    """Which of `starts` lie directly inside the outermost object. Takes comment-free text and
    positions. Returns those positions, found in one pass over the text."""
    found, depth, at, in_string = set(), 0, 0, False
    for position in sorted(set(starts)):
        while at < position:
            ch = blanked[at]
            if in_string:
                if ch == "\\":
                    at += 1
                elif ch == '"':
                    in_string = False
            elif ch == '"':
                in_string = True
            elif ch in "[{":
                depth += 1
            elif ch in "]}":
                depth -= 1
            at += 1
        if depth == 1 and not in_string:
            found.add(position)
    return found


def remove_member(text: str, key: str) -> tuple[str, Edit] | None:
    """`text` with every top-level member at `key` holding an object or a list taken out.

    Takes the file's text and the key. Returns the text and an `Edit` naming the key, or None when
    the key is not there at the top level or one of its values does not close.
    """
    blanked = code_only(text)
    matches = list(_member_pattern(key).finditer(blanked))
    tops = _at_top_level(blanked, [m.start() for m in matches])
    spans = []
    for found in matches:
        if found.start() not in tops:
            continue
        close = _closing(blanked, found.end())
        if close is None:
            return None
        spans.append((found.start(), close + 1))
    if not spans:
        return None
    return _cut(text, blanked, spans), Edit(key, "", "")


def _closing(blanked: str, start: int) -> int | None:
    """The index of the bracket closing the one at `start`. Takes comment-free text. Returns None
    when it never closes."""
    pairs = {"[": "]", "{": "}"}
    depth, index, in_string = 0, start, False
    while index < len(blanked):
        ch = blanked[index]
        if in_string:
            if ch == "\\":
                index += 1
            elif ch == '"':
                in_string = False
        elif ch == '"':
            in_string = True
        elif ch in pairs:
            depth += 1
        elif ch in pairs.values():
            depth -= 1
            if depth == 0:
                return index
        index += 1
    return None


class _Rest:
    """The text after a position, held as pieces so removing from its front costs only what is
    removed. Takes nothing. Pieces pushed later come first."""

    def __init__(self):
        self._pieces: list[tuple[str, str]] = []
        self._offset = 0
        self._front: tuple[int, str] | None = (0, "")

    def push(self, text: str, blanked: str) -> None:
        """Put `text`, with its comment-free twin `blanked`, in front of what is held."""
        if not text:
            return
        if self._offset:
            front_text, front_blanked = self._pieces[-1]
            self._pieces[-1] = (front_text[self._offset:], front_blanked[self._offset:])
            self._offset = 0
        self._pieces.append((text, blanked))
        lead = len(blanked) - len(blanked.lstrip())
        if lead < len(blanked):
            self._front = (lead, blanked[lead])
        elif self._front is not None:
            self._front = (self._front[0] + lead, self._front[1])

    def _chars(self):
        for index in range(len(self._pieces) - 1, -1, -1):
            text, blanked = self._pieces[index]
            for at in range(self._offset if index == len(self._pieces) - 1 else 0, len(text)):
                yield text[at], blanked[at]

    def leading_space(self) -> tuple[int, str]:
        """How many characters at the front are blank once comments are gone, and the first one
        after them (empty at the end)."""
        if self._front is None:
            count, following = 0, ""
            for _, blanked_char in self._chars():
                if not blanked_char.isspace():
                    following = blanked_char
                    break
                count += 1
            self._front = (count, following)
        return self._front

    def take(self, count: int) -> tuple[str, str]:
        """Remove `count` characters from the front. Returns them and their comment-free twin."""
        taken_text, taken_blanked = [], []
        if self._front is not None and count <= self._front[0]:
            self._front = (self._front[0] - count, self._front[1])
        else:
            self._front = None
        while count and self._pieces:
            text, blanked = self._pieces[-1]
            end = min(len(text), self._offset + count)
            taken_text.append(text[self._offset:end])
            taken_blanked.append(blanked[self._offset:end])
            count -= end - self._offset
            if end == len(text):
                self._pieces.pop()
                self._offset = 0
            else:
                self._offset = end
        return "".join(taken_text), "".join(taken_blanked)

    def drop_while(self, characters: str) -> None:
        """Remove characters from the front while they are among `characters`."""
        count = 0
        for text_char, _ in self._chars():
            if text_char not in characters:
                break
            count += 1
        self.take(count)

    def text(self) -> str:
        """Everything held, in order."""
        pieces = [text for text, _ in reversed(self._pieces)]
        if pieces and self._offset:
            pieces[0] = pieces[0][self._offset:]
        return "".join(pieces)


def _cut(text: str, blanked: str, spans: list[tuple[int, int]]) -> str:
    """`text` with each span removed along with the comma that joined it. Takes the text, its
    comment-free twin and the spans, in any order. Returns the text; a comment beside a span stays.
    Runs in time linear in the text."""
    rest, kept_to = _Rest(), len(text)
    for start, end in sorted(spans, reverse=True):
        rest.push(text[end:kept_to], blanked[end:kept_to])
        spaces, following = rest.leading_space()
        if following == ",":
            between, between_blanked = rest.take(spaces)
            rest.take(1)
            if between.strip():
                rest.push(between, between_blanked)
            else:
                rest.drop_while(" \t")
            kept_to = start
            continue
        before = start
        while before > 0 and blanked[before - 1].isspace():
            before -= 1
        if before > 0 and blanked[before - 1] == ",":
            comma = before - 1
            if text[before:start].strip():
                rest.push(text[comma + 1:start], blanked[comma + 1:start])
            kept_to = comma
            continue
        kept_to = start
    return text[:kept_to] + rest.text()


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
