#!/usr/bin/env python3
"""Read a full git object id from text a person wrote."""
from __future__ import annotations

import re

_FULL_OBJECT_ID = re.compile(r"[0-9a-f]{40}(?:[0-9a-f]{24})?")


def full_object_id(text) -> str | None:
    """Read a full git object id from text, 40 hex digits for SHA-1 or 64 for SHA-256 in either
    case. Takes the text. Returns the id in lower case, or None when the text is not a full id."""
    if not isinstance(text, str):
        return None
    lowered = text.lower()
    return lowered if _FULL_OBJECT_ID.fullmatch(lowered) else None
