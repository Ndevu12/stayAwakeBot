#!/usr/bin/env python3
"""Matcher base class + shared parsing helpers.

One detection *technique* per sibling module; each subclass sets `handles` to the
signature `matcher` value it serves.
"""
from __future__ import annotations

import json
import re
from fnmatch import fnmatch
from typing import Any

# Font-format magic bytes; a "font" lacking these but carrying text is a payload.
FONT_MAGIC = {
    ".woff2": b"wOF2", ".woff": b"wOFF",
    ".ttf": b"\x00\x01\x00\x00", ".otf": b"OTTO",
}


def evidence(text: str, start: int, end: int, width: int = 80) -> str:
    s = max(0, start - 12)
    snippet = text[s:end + width].replace("\n", " ")
    return (snippet[:width] + "…") if len(snippet) > width else snippet


def globs_ok(relpath: str, sig: dict[str, Any]) -> bool:
    globs = sig.get("file_globs")
    if not globs:
        return True
    base = relpath.rsplit("/", 1)[-1]
    return any(fnmatch(relpath, g) or fnmatch(base, g) for g in globs)


def load_jsonc(text: str) -> Any:
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        cleaned = re.sub(r"/\*.*?\*/", "", text, flags=re.S)
        cleaned = re.sub(r"(^|[^:])//.*$", r"\1", cleaned, flags=re.M)
        cleaned = re.sub(r",(\s*[}\]])", r"\1", cleaned)
        try:
            return json.loads(cleaned)
        except json.JSONDecodeError:
            return None


class Matcher:
    handles: str = ""

    def scan(self, target, signatures: list[dict[str, Any]]):
        raise NotImplementedError
