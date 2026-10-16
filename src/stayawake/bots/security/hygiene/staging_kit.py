#!/usr/bin/env python3
"""Tell a folder that holds a known worm's staging kit, read from `data/staging_kits.yml`."""
from __future__ import annotations

import functools
import json
import os
import stat
from dataclasses import dataclass
from pathlib import Path

import yaml

from stayawake.utils.pathsafe import read_regular_no_follow

KITS_FILE = Path(__file__).resolve().parents[1] / "data" / "staging_kits.yml"
_LARGEST_MANIFEST = 64 * 1024


@dataclass(frozen=True)
class Kit:
    """One kit: the manifest its folder holds, the only keys that manifest holds, and the packages it
    may depend on."""

    manifest: str
    only_keys: frozenset[str]
    packages: frozenset[str]


def _names(raw: dict, field: str) -> frozenset[str]:
    names = raw.get(field)
    if not isinstance(names, list) or not names or not all(isinstance(n, str) and n for n in names):
        raise ValueError(f"a staging kit needs a non-empty list of names in `{field}`")
    return frozenset(names)


@functools.cache
def kits() -> tuple[Kit, ...]:
    """Read the staging kits. Returns them. Raises ValueError when the data file is malformed."""
    data = yaml.safe_load(KITS_FILE.read_text(encoding="utf-8"))
    entries = data.get("kits") if isinstance(data, dict) else None
    if not isinstance(entries, list) or not entries:
        raise ValueError("the staging kits file names no kit")
    out = []
    for raw in entries:
        manifest = raw.get("manifest") if isinstance(raw, dict) else None
        if not isinstance(manifest, str) or not manifest or "/" in manifest:
            raise ValueError(f"a staging kit needs a manifest file name: {raw!r}")
        out.append(Kit(manifest, _names(raw, "only_keys"), _names(raw, "packages")))
    return tuple(out)


def _manifest(path: Path) -> dict | None:
    """Read a manifest that is a regular file of bounded size, without following a link or waiting on
    anything that is not a file. Takes its path. Returns what it holds, or None when it is not there, not
    a regular file, too large or not JSON. Raises OSError when a regular file is there and cannot be
    read as the file first found there."""
    try:
        first = os.lstat(path)
    except FileNotFoundError:
        return None
    if not stat.S_ISREG(first.st_mode) or first.st_size > _LARGEST_MANIFEST:
        return None
    raw = read_regular_no_follow(path, _LARGEST_MANIFEST, same_as=first)
    if raw is None:
        raise OSError(f"{path} could not be read as the file first found there")
    try:
        held = json.loads(raw)
    except (ValueError, RecursionError):
        return None
    return held if isinstance(held, dict) else None


HELD_ASIDE_MARK = ".saw-held-"
REMOVING_MARK = ".saw-removing-"


def _beside(location: Path, mark: str) -> list[Path]:
    """List the entries beside a location named after it with a mark. Takes the location and the mark.
    Returns them, oldest name first. Raises OSError when the folder they would be in cannot be read."""
    prefix = location.name + mark
    try:
        with os.scandir(location.parent) as entries:
            return sorted(location.parent / e.name for e in entries if e.name.startswith(prefix))
    except FileNotFoundError:
        return []


def held_aside(location: Path) -> list[Path]:
    """List what `saw harden` moved aside from a location. Takes the location. Returns the entries, oldest
    name first. Raises OSError when the folder they would be in cannot be read."""
    return _beside(location, HELD_ASIDE_MARK)


def being_removed(location: Path) -> list[Path]:
    """List what `saw harden` is removing, or could not finish removing, from a location. Takes the
    location. Returns the entries, oldest name first. Raises OSError when the folder they would be in
    cannot be read."""
    return _beside(location, REMOVING_MARK)


def holds_a_kit(folder: Path) -> bool:
    """Tell whether a folder holds a known worm's staging kit: a folder, not a link to one, whose manifest
    holds only the kit's keys, naming one or more of its packages and nothing else. Takes the folder.
    Returns the answer. Raises OSError when the folder or its manifest is there and cannot be read."""
    try:
        if not stat.S_ISDIR(os.lstat(folder).st_mode):
            return False
    except FileNotFoundError:
        return False
    for kit in kits():
        held = _manifest(folder / kit.manifest)
        if held is not None and is_a_kit(kit.manifest, held):
            return True
    return False


def is_a_kit(manifest: str, held: dict) -> bool:
    """Tell whether what a manifest holds is a known worm's staging kit's: only the kit's keys, naming
    one or more of its packages and nothing else. Takes the manifest's file name and what it holds.
    Returns the answer."""
    for kit in kits():
        if kit.manifest != manifest or set(held) != kit.only_keys:
            continue
        if all(isinstance(held[key], dict) and held[key] and set(held[key]) <= kit.packages
               for key in kit.only_keys):
            return True
    return False
