#!/usr/bin/env python3
"""Branch-name construction: make one ref-safe segment, and pick a name that is free to push."""
from __future__ import annotations

import re

_UNSAFE = re.compile(r"[^A-Za-z0-9._-]+")


def ref_safe_segment(text: str, *, limit: int = 60, fallback: str = "base") -> str:
    """`text` reduced to a single ref-safe path segment (never empty, never nested)."""
    flat = _UNSAFE.sub("-", (text or "").strip()).replace("..", "-").strip("._-")
    return re.sub(r"-{2,}", "-", flat)[:limit] or fallback


def choose_branch(name: str, *, exists, fast_forwardable, limit: int = 20) -> str:
    """`name`, or a numbered sibling when it is held by unrelated work.

    Reuses a branch our own earlier run can fast-forward; without that test every run would abandon
    a branch it could extend and accumulate suffixes. Exhaustion returns the predictable `name`
    rather than inventing a deep suffix — a refused push reports the reason.
    """
    if not exists(name) or fast_forwardable(name):
        return name
    for n in range(2, limit + 1):
        candidate = f"{name}-{n}"
        if not exists(candidate) or fast_forwardable(candidate):
            return candidate
    return name
