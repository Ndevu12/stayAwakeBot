#!/usr/bin/env python3
"""Data passed between amend's core and an injected interactive resolver.

The core asks an injected `resolve(question)` about each `UncertainItem` it does not act on itself,
answered with a `Resolution`, and about each `DeliveryQuestion`, answered with a `DeliveryAnswer`. A
resolver of `None` means nothing is asked.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

REMOVE = "remove"
RESTORE = "restore"
SUPPLY = "supply"
KEEP = "keep"
TAKE_OUT = "take-out"
UNANSWERED = "unanswered"


@dataclass(frozen=True)
class UncertainItem:
    """One finding put to the operator.

    `preview` is the file's own bytes (the caller renders them safely). `introduced_by` is the short
    id of the commit that added this file beside a payload, or "" when saw tied it to none;
    `arrived_with_removed` are the confirmed paths from that same commit saw is already removing;
    `origin_unread` is True when git could not read what a commit added. `restore_candidate` is the
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
    origin_unread: bool = False


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


@dataclass(frozen=True)
class ArrivedFile:
    """One file a delivery commit added, with the blob it added."""

    path: str
    blob: str


@dataclass(frozen=True)
class DeliveryQuestion:
    """One commit that delivered a payload saw removes, and the files it added that have no finding
    of their own.

    `commit`, `date` and `subject` are as the commit states them. `removing` are the confirmed paths
    saw removes from it. `files` are put to the operator; `changed` are only named. `recorded` is
    True when the question comes from an earlier run's record.
    """

    commit: str
    date: str
    subject: str
    removing: tuple[str, ...]
    files: tuple[ArrivedFile, ...]
    changed: tuple[str, ...] = ()
    recorded: bool = False


@dataclass(frozen=True)
class DeliveryAnswer:
    """The operator's answer for one delivery.

    `action` is `TAKE_OUT` (remove the `chosen` paths as they were added), `KEEP` (leave every file;
    final), or `UNANSWERED` (no answer was given; nothing is removed and it is asked again).
    """

    action: str = UNANSWERED
    chosen: tuple[str, ...] = ()


Resolver = Callable[[UncertainItem | DeliveryQuestion], Resolution | DeliveryAnswer]
