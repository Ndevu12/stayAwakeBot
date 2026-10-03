#!/usr/bin/env python3
"""Render what saw puts to the operator into safe text: one uncertain file, or the files one
delivery commit added. Every attacker-controlled field goes through `textsafe.plain`.
"""
from __future__ import annotations

import posixpath
import unicodedata

from stayawake.bots.security.pr.resolve import DeliveryQuestion, UncertainItem
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
    """Say what the file arrived with, that git could not read it, or that it is not tied to one.
    Takes the item. Returns the line."""
    if item.introduced_by and item.arrived_with_removed:
        n = len(item.arrived_with_removed)
        paths = ", ".join(textsafe.plain(p) for p in item.arrived_with_removed)
        return (f"origin:  arrived in commit {textsafe.plain(item.introduced_by)} with {n} "
                f"file{'' if n == 1 else 's'} saw is already removing: {paths}")
    if item.origin_unread:
        return "origin:  git could not read what this file arrived with — treat with caution"
    return "origin:  no commit ties it to the malware — treat with caution"


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
    head.append("  " + _origin_line(item))
    if item.restore_candidate is not None:
        head.append(f"  restore: saw can put back the clean version from "
                    f"{textsafe.plain(item.restore_source) or 'an earlier commit'}")
    head.append(_DIVIDER)
    return "\n".join(head + _body(item) + [_FOOTER])


_DELIVERY_HEADER = ("─── files added in the same commit as the malware saw is removing — saw "
                    "cannot tell them from your own work ───")
FOLDERS_LISTED = 20
NAMES_LISTED_PER_FOLDER = 8
_TOP_LEVEL = "(top level)"


def delivery_groups(question: DeliveryQuestion) -> list[tuple[str, list[str]]]:
    """Group a delivery's files by folder, in the order they are numbered. Takes the question.
    Returns `(folder, paths)` pairs; past the folder limit the files are grouped by their top
    folder."""
    def grouped(folder_of) -> list[tuple[str, list[str]]]:
        folders: dict[str, list[str]] = {}
        for f in sorted(question.files, key=lambda f: f.path):
            folders.setdefault(folder_of(f.path), []).append(f.path)
        return sorted(folders.items())

    groups = grouped(posixpath.dirname)
    if len(groups) > FOLDERS_LISTED:
        groups = grouped(lambda path: path.split("/", 1)[0] if "/" in path else "")
    return groups


def _shown(path: str, folder: str, blobs: dict[str, str], clashes: set[str]) -> str:
    """Name one file inside its group, marked with its blob when its name reads like another's.
    Takes the path, its group's folder, each path's blob and the names that clash. Returns the
    name."""
    name = textsafe.plain(path[len(folder) + 1:] if folder else path)
    return f"{name} [{blobs[path][:12]}]" if textsafe.plain(path) in clashes else name


def render_delivery(question: DeliveryQuestion) -> str:
    """Render one delivery commit and the files it added for the operator to choose from. Takes the
    question. Returns the text; the caller adds the prompt."""
    blobs = {f.path: f.blob for f in question.files}
    names = [textsafe.plain(f.path) for f in question.files]
    clashes = {n for n in names if names.count(n) > 1}
    commit = textsafe.plain(question.commit[:12])
    lines = [_DELIVERY_HEADER,
             f"  commit:  {commit}  ({textsafe.plain(question.date) or 'no date'})  "
             f"the commit says: \"{textsafe.plain(question.subject, 120)}\""]
    if question.recorded:
        lines.append("           saw recorded this commit in an earlier run, before replacing it")
    lines.append("  saw is removing from it:  "
                 + (", ".join(textsafe.plain(p) for p in question.removing) or "its payload"))
    lines.append(f"  it also added {len(question.files)} file(s) with no finding of their own:")
    groups = delivery_groups(question)
    for number, (folder, paths) in enumerate(groups[:FOLDERS_LISTED], 1):
        label = textsafe.plain(folder + "/") if folder else _TOP_LEVEL
        lines.append(f"    {number}  {label}  ({len(paths)} file(s))")
        entries = [f"{number}.{at} {_shown(p, folder, blobs, clashes)}"
                   for at, p in enumerate(paths[:NAMES_LISTED_PER_FOLDER], 1)]
        lines.append("         " + "   ".join(entries))
        hidden = len(paths) - NAMES_LISTED_PER_FOLDER
        if hidden > 0:
            lines.append(f"         … and {hidden} more — choosing {number} takes all of them")
    if len(groups) > FOLDERS_LISTED:
        rest = sum(len(paths) for _folder, paths in groups[FOLDERS_LISTED:])
        lines.append(f"    … and {len(groups) - FOLDERS_LISTED} more folders ({rest} file(s)) — "
                     "'all' takes them too")
    if question.changed:
        shown = question.changed[:NAMES_LISTED_PER_FOLDER]
        hidden = len(question.changed) - len(shown)
        lines.append("  it also changed, and saw leaves to you: "
                     + ", ".join(textsafe.plain(p) for p in shown)
                     + (f" and {hidden} more" if hidden else ""))
    lines.append(_DIVIDER)
    return "\n".join(lines)
