#!/usr/bin/env python3
"""Data passed between amend's core and an injected interactive resolver.

The core produces an `UncertainItem` for each finding it does not act on itself, and asks an injected
`resolve(item) -> Resolution`; a resolver of `None` means the item is left alone. A `Resolution`
names one action: remove the path whole, restore a clean earlier version, supply replacement content,
or keep it.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

REMOVE = "remove"
RESTORE = "restore"
SUPPLY = "supply"
KEEP = "keep"


@dataclass(frozen=True)
class UncertainItem:
    """One finding put to the operator.

    `preview` is the file's own bytes (the caller renders them safely). `introduced_by` is the short
    id of the merge that brought this file, or "" when saw could not tie it to one; `arrived_with_removed`
    are the confirmed paths from that same merge saw is already removing. `restore_candidate` is the
    `(mode, oid)` of an earlier clean version saw can put back, or None when it found none;
    `restore_source` is the short id of the commit that version comes from. `keep_content` is True
    when the operator may keep the file with a clean version (restore or supply), not only remove it.
    """

    path: str
    category: str
    signature_id: str
    description: str
    preview: bytes
    introduced_by: str = ""
    arrived_with_removed: tuple[str, ...] = ()
    confirmed: bool = False
    restore_candidate: tuple[str, str] | None = None
    restore_source: str = ""
    keep_content: bool = False


@dataclass(frozen=True)
class Resolution:
    """The operator's answer for one item.

    `action` is `REMOVE` (delete the path from history), `RESTORE` (put a clean earlier version back
    in place of the payload), `SUPPLY` (put operator-supplied content in its place), or `KEEP` (leave
    the file untouched). `restore` carries the `(mode, oid)` tree entry to put back for `RESTORE`;
    `supply` carries the replacement bytes for `SUPPLY`.
    """

    action: str = KEEP
    restore: tuple[str, str] | None = None
    supply: bytes | None = None


Resolver = Callable[[UncertainItem], Resolution]
