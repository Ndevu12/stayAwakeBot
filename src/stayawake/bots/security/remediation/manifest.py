#!/usr/bin/env python3
"""Remove a named dependency from the `package.json` files that declare it."""
from __future__ import annotations

import json
import re
from pathlib import Path

from stayawake.bots.security.dependencies.layout import in_kept_copies
from stayawake.bots.security.dependencies.remediation import MALICIOUS
from stayawake.bots.security.jsonc import load_jsonc
from stayawake.utils.pathsafe import is_safe_write_target

MANIFEST = "package.json"
_DEP_FIELDS = ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies")
_NOT_WALKED = frozenset({".git", "node_modules", ".venv"})
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


def declared_malicious(findings) -> dict[str, tuple[tuple[str, ...], tuple[str, ...]]]:
    """Collect the known-malicious packages the findings name in a manifest. Takes the findings.
    Returns each package name with the versions found and the manifests that declare it."""
    versions: dict[str, set[str]] = {}
    paths: dict[str, set[str]] = {}
    for f in findings:
        name = getattr(f, "package_name", None)
        path = getattr(f, "path", "") or ""
        if getattr(f, "dependency_state", None) != MALICIOUS or not name:
            continue
        if Path(path).name != MANIFEST:
            continue
        package = getattr(f, "package", "") or ""
        versions.setdefault(name, set())
        if package.rfind("@") > 0:
            versions[name].add(package[package.rfind("@") + 1:])
        paths.setdefault(name, set()).add(path)
    return {name: (tuple(sorted(versions[name])), tuple(sorted(paths[name]))) for name in sorted(paths)}


def dropping(findings, chosen: set[str]) -> dict[str, set[str]]:
    """Map each manifest to the chosen packages found malicious in it. Takes the findings and the
    chosen package names. Returns the names by manifest path."""
    within: dict[str, set[str]] = {}
    for name, (_, paths) in declared_malicious(findings).items():
        if name in chosen:
            for path in paths:
                within.setdefault(path, set()).add(name)
    return within


def manifests_cleared(root: Path, findings, rewritten) -> list[str]:
    """Name the rewritten manifests that no longer declare any known-malicious package found in
    them. Takes the root, the findings and the manifests rewritten. Returns those manifests."""
    named: dict[str, set[str]] = {}
    for name, (_, paths) in declared_malicious(findings).items():
        for path in paths:
            named.setdefault(path, set()).add(name)
    return sorted(p for p in rewritten if p in named and not _declares(root / p, named[p]))


def _declares(path: Path, names: set[str]) -> bool:
    """Tell whether a manifest still declares any of the names. Takes the manifest and the names.
    Returns the answer, True when it cannot be read."""
    try:
        data = load_jsonc(path.read_bytes().decode("utf-8"))
    except (OSError, UnicodeDecodeError, ValueError):
        return True
    if not isinstance(data, dict):
        return True
    return any(isinstance(data.get(field), dict) and names & set(data[field]) for field in _DEP_FIELDS)


def manifests(root: Path) -> list[Path]:
    """Takes a repository root. Returns every manifest saw may rewrite, deepest last."""
    found: list[Path] = []
    if in_kept_copies(root):
        return found
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
                if entry.name not in _NOT_WALKED and not in_kept_copies(entry):
                    stack.append(entry)
            elif entry.name == MANIFEST:
                found.append(entry)
    return found


def drop_dependencies(root: Path, names: set[str],
                      within: dict[str, set[str]] | None = None) -> list[str]:
    """Remove packages from the manifests under `root`.

    Takes the repository root, the known-malicious package names, and optionally the names to remove
    from each manifest path, which limits the removal to those manifests. Returns the paths
    rewritten, relative to the root. A manifest saw cannot rewrite exactly is left untouched.
    """
    if not names:
        return []
    rewritten: list[str] = []
    for path in manifests(root):
        rel = str(path.relative_to(root))
        here = names if within is None else names & within.get(rel, set())
        if not here or not is_safe_write_target(path, root):
            continue
        try:
            if path.stat().st_size > _MAX_MANIFEST_BYTES or path.stat().st_nlink > 1:
                continue
            text = path.read_bytes().decode("utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        out = drop_from_manifest(text, here)
        if out is None:
            continue
        try:
            path.write_bytes(out.encode("utf-8"))
            if path.read_bytes() != out.encode("utf-8"):
                continue
        except OSError:
            continue
        rewritten.append(rel)
    return sorted(rewritten)
