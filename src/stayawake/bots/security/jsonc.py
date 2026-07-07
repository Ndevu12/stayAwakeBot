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
