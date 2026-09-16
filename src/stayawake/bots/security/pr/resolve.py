#!/usr/bin/env python3
"""Data passed between amend's core and an injected interactive resolver.

The core produces an `UncertainItem` for each heuristic finding it does not act on itself, and asks
an injected `resolve(item) -> Decision`; a resolver of `None` means the item is left alone.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Callable


@dataclass(frozen=True)
class UncertainItem:
    """One heuristic finding put to the operator.

    `preview` is the file's own bytes (the caller renders them safely); `context` is a short plain
    description of where the file came from.
    """

    path: str
    category: str
    signature_id: str
    description: str
    preview: bytes
    context: str


@dataclass(frozen=True)
class Decision:
    """The operator's answer for one item. `remove` True removes the path; False keeps or skips it."""

    remove: bool


Resolver = Callable[[UncertainItem], Decision]
