#!/usr/bin/env python3
"""Render one uncertain file into safe operator text for the keep/remove prompt.

The file's own bytes are attacker-controlled, so every line the file contributes is sanitised with
`textsafe.plain` and shown inside a fixed frame the content cannot forge; binary, unreadable, or
not-human-judgeable content is described rather than printed.
"""
from __future__ import annotations

import unicodedata

from stayawake.bots.security.pr.resolve import UncertainItem
from stayawake.utils import textsafe

_READ_CAP = 4096
_MAX_LINES = 20
_WIDTH = 100
_OPAQUE_CATEGORIES = frozenset({"fake-font", "supply-chain-dep"})
_DIVIDER = "─" * 72
_HEADER = "─── saw is unsure about this file — do NOT trust what the file itself says ───"
_HEADER_CONFIRMED = ("─── saw confirmed this file is malicious but could not clean it automatically "
                     "— do NOT trust what the file itself says ───")
_FOOTER = "─── end of preview ───"


def _is_binary(raw: bytes) -> bool:
    """True when `raw` is not human-readable text: a NUL byte, or over 30% control/undecodable
    characters once decoded."""
    if b"\x00" in raw:
        return True
    if not raw:
        return False
    text = raw.decode("utf-8", errors="replace")
    unreadable = sum(1 for ch in text
                     if ch == "�"
                     or (unicodedata.category(ch)[0] == "C" and ch not in "\t\n\r"))
    return unreadable / len(text) > 0.30


def _origin_line(item: UncertainItem) -> str:
    """One honest line of provenance: what the file arrived with, or that saw could not place it."""
    if item.introduced_by and item.arrived_with_removed:
        n = len(item.arrived_with_removed)
        paths = ", ".join(textsafe.plain(p) for p in item.arrived_with_removed)
        return (f"origin:  arrived in merge {textsafe.plain(item.introduced_by)} with {n} "
                f"file{'' if n == 1 else 's'} saw is already removing: {paths}")
    return "origin:  saw could not determine what this file arrived with — treat with caution"


def _body(item: UncertainItem) -> list[str]:
    """The file content as safe, gutter-prefixed lines, or a note when saw withholds it."""
    if item.category in _OPAQUE_CATEGORIES:
        return ["  saw is not printing the contents — judge this from the finding above, not the bytes"]
    raw = item.preview[:_READ_CAP]
    if not raw or _is_binary(raw):
        return [f"  binary or unreadable content ({len(item.preview)} bytes) — saw is not printing it"]
    lines = raw.decode("utf-8", errors="replace").split("\n")
    out = [f"  {i:>3}│ {textsafe.plain(ln, limit=_WIDTH)}"
           for i, ln in enumerate(lines[:_MAX_LINES], 1)]
    if len(lines) > _MAX_LINES or len(item.preview) > _READ_CAP:
        out.append(f"  … more not shown (showing the first {min(len(lines), _MAX_LINES)} lines) …")
    return out


def render_item(item: UncertainItem) -> str:
    """One uncertain file as a safe multi-line block: a header warning not to trust the file's own
    words, its path/type/why/origin, then a preview or a withheld-content note. The caller adds the
    keep/remove question."""
    head = [
        _HEADER_CONFIRMED if getattr(item, "confirmed", False) else _HEADER,
        f"  path:    {textsafe.plain(item.path)}",
        f"  type:    {textsafe.plain(item.category)}"
        + (f"  ({textsafe.plain(item.signature_id)})" if item.signature_id else ""),
    ]
    if item.description:
        head.append(f"  why:     {textsafe.plain(item.description)}")
    head += ["  " + _origin_line(item), _DIVIDER]
    return "\n".join(head + _body(item) + [_FOOTER])
