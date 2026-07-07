#!/usr/bin/env python3
"""Lockfile parsers shared by more than one resolver (#1123).

Some ecosystems lock dependencies in the *same on-disk shape* despite being otherwise unrelated —
a TOML `[[package]]` array of `{name, version}` is used by Cargo, Poetry and uv alike. That is
genuine shared structure (identical format), so the parser lives here once instead of being copied
per resolver. This is NOT a universal super-parser: format-specific grammars (npm's trees, Ruby's
Gemfile.lock, Go's go.sum, …) stay in their own resolver. Only literally-identical parsers belong
here.
"""
from __future__ import annotations

import tomllib


def toml_packages(text) -> list[tuple[str, str]]:
    """(name, version) for each `[[package]]` table of a TOML lockfile (Cargo.lock, poetry.lock,
    uv.lock). Malformed TOML → []."""
    try:
        data = tomllib.loads(text or "")
    except (tomllib.TOMLDecodeError, ValueError):
        return []
    out: list[tuple[str, str]] = []
    for pkg in (data.get("package") or []):
        if isinstance(pkg, dict):
            name, version = pkg.get("name"), pkg.get("version")
            if isinstance(name, str) and isinstance(version, str):
                out.append((name, version))
    return out
