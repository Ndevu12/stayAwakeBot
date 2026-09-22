#!/usr/bin/env python3
"""Remove a named dependency from the `package.json` files that declare it."""
from __future__ import annotations

import json
import re
from pathlib import Path

from stayawake.bots.security.jsonc import load_jsonc
from stayawake.bots.security.models import SAW_DIR
from stayawake.utils.pathsafe import is_safe_write_target

MANIFEST = "package.json"
_DEP_FIELDS = ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies")
_NOT_WALKED = frozenset({".git", "node_modules", SAW_DIR, ".venv"})
_TRAILING_COMMA = re.compile(r",(\s*[}\]])")
_MAX_MANIFEST_BYTES = 2_000_000


def _entry(name: str) -> re.Pattern:
    """Takes a package name. Returns the pattern matching its own line in a dependency object."""
    return re.compile(r'^\s*"' + re.escape(name) + r'"\s*:\s*"[^"]*"\s*,?\s*$')


def drop_from_manifest(text: str, names: set[str]) -> str | None:
    """Remove `names` from every dependency field of one manifest.

    Takes the manifest text and the package names. Returns the new text, or None when nothing
    changed, the text does not parse, or the edit would not produce exactly the expected result.
    """
    data = load_jsonc(text or "")
    if not isinstance(data, dict):
        return None
    try:
        expected = json.loads(json.dumps(data))
    except (TypeError, ValueError):
        return None
    dropped = False
    for field in _DEP_FIELDS:
        deps = expected.get(field)
        if not isinstance(deps, dict):
            continue
        for name in [n for n in deps if n in names]:
            deps.pop(name)
            dropped = True
    if not dropped:
        return None
    patterns = [_entry(n) for n in names]
    kept = [line for line in text.splitlines(keepends=True)
            if not any(p.match(line) for p in patterns)]
    out = _TRAILING_COMMA.sub(r"\1", "".join(kept))
    try:
        if json.loads(out) != expected:
            return None
    except ValueError:
        return None
    return out


def manifests(root: Path) -> list[Path]:
    """Takes a repository root. Returns every manifest saw may rewrite, deepest last."""
    found: list[Path] = []
    stack = [root]
    while stack:
        here = stack.pop()
        try:
            entries = list(here.iterdir())
        except OSError:
            continue
        for entry in entries:
            if entry.is_symlink():
                continue
            if entry.is_dir():
                if entry.name not in _NOT_WALKED:
                    stack.append(entry)
            elif entry.name == MANIFEST:
                found.append(entry)
    return found


def drop_dependencies(root: Path, names: set[str]) -> list[str]:
    """Remove `names` from every manifest under `root`.

    Takes the repository root and the known-malicious package names. Returns the paths rewritten,
    relative to the root. A manifest saw cannot rewrite exactly is left untouched.
    """
    if not names:
        return []
    rewritten: list[str] = []
    for path in manifests(root):
        if not is_safe_write_target(path, root):
            continue
        try:
            if path.stat().st_size > _MAX_MANIFEST_BYTES or path.stat().st_nlink > 1:
                continue
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        out = drop_from_manifest(text, names)
        if out is None:
            continue
        try:
            path.write_text(out, encoding="utf-8")
            if path.read_text(encoding="utf-8") != out:
                continue
        except OSError:
            continue
        rewritten.append(str(path.relative_to(root)))
    return sorted(rewritten)
