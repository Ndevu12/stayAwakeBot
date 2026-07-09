#!/usr/bin/env python3
"""Lenient JSON parsing shared across the scanner (stdlib-only, no side effects).

`load_jsonc` reads JSON that may carry JS-style comments and trailing commas — the shape of
real-world `package.json`, `tsconfig.json`, VS Code settings and lockfiles. Kept in this
neutral leaf module (imported by both `matchers/` and `dependencies/`) so neither package's
`__init__` has to be triggered to reach it — that would create an import cycle. `matchers.base`
re-exports it for its existing importers.
"""
from __future__ import annotations

import json
import re
from typing import Any


def _strip_block_comments(text: str) -> str:
    r"""Remove `/* … */` comments in a single LINEAR pass. A regex (`/\*.*?\*/`) re-scans to
    end-of-string at every `/*` when the closing `*/` is absent → O(n^2) ReDoS on a hostile
    `/*`-spam config (#1158). This str.find scan is O(n) and fully correct — a comment ends at the
    FIRST `*/`, and its body may itself contain `/*` (which a tempered regex would mishandle). An
    unterminated `/*` is left in place (as the old regex did → the JSON then fails to parse)."""
    parts, i = [], 0
    while True:
        start = text.find("/*", i)
        if start == -1:
            parts.append(text[i:])
            break
        end = text.find("*/", start + 2)
        if end == -1:
            parts.append(text[i:])          # unterminated comment — leave the rest untouched
            break
        parts.append(text[i:start])         # keep everything before the comment, drop the comment
        i = end + 2
    return "".join(parts)


def load_jsonc(text: str) -> Any:
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        cleaned = _strip_block_comments(text)
        cleaned = re.sub(r"(^|[^:])//.*$", r"\1", cleaned, flags=re.M)
        cleaned = re.sub(r",(\s*[}\]])", r"\1", cleaned)
        try:
            return json.loads(cleaned)
        except json.JSONDecodeError:
            return None
