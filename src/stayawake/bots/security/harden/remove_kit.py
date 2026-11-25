#!/usr/bin/env python3
"""Delete the known worm's staging kit from where a denial goes, keeping only the facts about it."""
from __future__ import annotations

import datetime
import hashlib
import json
import os
import re
import sys
from dataclasses import dataclass
from pathlib import Path

from stayawake.bots.security.hygiene import staging_kit
from stayawake.bots.security.hygiene.staging_kit import REMOVING_MARK
from stayawake.utils import atomicwrite, folders, hostdenial, pathsafe

__all__ = ["REMOVING_MARK", "Removal", "facts", "remove"]
_MOST_AT_ONE_TIME = 100
_MOST_MANIFEST_BYTES = 2 * 1024 * 1024
_MOUNT_TABLE = "/proc/self/mountinfo"
_ESCAPED = re.compile(r"\\([0-7]{3})")


@dataclass(frozen=True)
class Removal:
    """What deleting the kit did: whether it is gone, what was left where, and whether something else
    was found in its place."""

    removed: bool = False
    left: Path | None = None
    mismatch: bool = False


def _owned_as_it_should_be(owner: str) -> bool:
    """Tell whether the kit belongs to the account saw acts for, or to root on a run as root. Takes its
    owner's grade: `self`, `root` or `other`. Returns the answer."""
    return owner == "self" or (owner == "root" and hostdenial.privileged())


def _free_name(path: Path, now: datetime.datetime) -> str | None:
    first = f"{path.name}{REMOVING_MARK}{now.strftime('%Y%m%dT%H%M%SZ')}"
    for count in range(1, _MOST_AT_ONE_TIME + 1):
        name = first if count == 1 else f"{first}-{count}"
        if not os.path.lexists(path.parent / name):
            return name
    return None


def _packages(lock: bytes | None) -> list[dict[str, str]]:
    """Return the package names and versions a lockfile records. Takes its bytes."""
    try:
        packages = json.loads(lock or b"{}").get("packages") or {}
    except (ValueError, AttributeError):
        return []
    found = []
    for key, entry in packages.items() if isinstance(packages, dict) else ():
        if isinstance(key, str) and key.startswith("node_modules/") and isinstance(entry, dict):
            version = entry.get("version")
            found.append({"name": key[len("node_modules/"):], "version": version if isinstance(version, str) else ""})
    return sorted(found, key=lambda p: (p["name"], p["version"]))


def facts(folder: Path, when: datetime.datetime, *, read=pathsafe.read_regular_no_follow) -> dict:
    """Return the facts about a staging kit worth keeping once it is gone: when it was made and
    changed, the digests of its manifests, and the packages it holds. Takes the folder, the time and
    what reads a manifest without following a link. Returns the facts."""
    found = folder.lstat()
    manifest = read(folder / "package.json", _MOST_MANIFEST_BYTES)
    lock = read(folder / "package-lock.json", _MOST_MANIFEST_BYTES)
    stamp = lambda seconds: datetime.datetime.fromtimestamp(seconds, datetime.timezone.utc).isoformat()  # noqa: E731
    return {
        "found_at": when.isoformat(),
        "created": stamp(found.st_birthtime) if hasattr(found, "st_birthtime") else None,
        "changed": stamp(found.st_ctime),
        "modified": stamp(found.st_mtime),
        "package_json_sha256": hashlib.sha256(manifest).hexdigest() if manifest is not None else None,
        "package_lock_sha256": hashlib.sha256(lock).hexdigest() if lock is not None else None,
        "packages": _packages(lock),
    }


def _mount_points() -> frozenset[str]:
    """Return every mount point this process can see, where the system lists them."""
    if not sys.platform.startswith("linux"):
        return frozenset()
    try:
        with open(_MOUNT_TABLE, encoding="latin-1") as table:
            return frozenset(_unescaped(line.split()[4]) for line in table if len(line.split()) > 4)
    except OSError:
        return frozenset()


def _unescaped(field: str) -> str:
    """Undo the octal escapes the mount table writes for spaces and other characters. Takes the field
    read as Latin-1, one character per byte. Returns the path."""
    raw = _ESCAPED.sub(lambda m: chr(int(m.group(1), 8)), field)
    return raw.encode("latin-1").decode("utf-8", "surrogateescape")


def _manifest_at(folder: folders.Folder, name: str) -> dict | None:
    """Read a manifest in a held folder, refusing a link or a pipe at its name. Takes the folder and
    the manifest's name. Returns what it holds, or None for anything but a bounded regular file of
    JSON. Raises OSError when it is there and cannot be read."""
    try:
        raw = folder.read_regular(name, _MOST_MANIFEST_BYTES)
    except FileNotFoundError:
        return None
    if raw is None or len(raw) > _MOST_MANIFEST_BYTES:
        return None
    try:
        held = json.loads(raw)
    except (ValueError, RecursionError):
        return None
    return held if isinstance(held, dict) else None


def _holds_a_kit_at(folder: folders.Folder) -> bool:
    """Tell whether a held folder holds a known worm's staging kit, read through the folder. Takes it.
    Returns the answer; raises OSError when a manifest is there and cannot be read."""
    for name in sorted({kit.manifest for kit in staging_kit.kits()}):
        held = _manifest_at(folder, name)
        if held is not None and staging_kit.is_a_kit(name, held):
            return True
    return False


def remove(path: Path, capture_dir: Path, *, named_for: Path | None = None,
           now: datetime.datetime | None = None) -> Removal:
    """Delete the known worm's staging kit at `path`: hold the folder open, and only when what is held
    is a real folder, owned as it should be and holding the kit, rename it beside itself under the name
    of the location it is named for, record its facts in `capture_dir`, and delete it through the held
    folder without leaving its device or following a link. Takes the kit, the folder for the record, the
    location the new name is made from (default: the kit's own) and the time (default: now). Returns what
    was done; whatever could not be deleted is left under the name it was renamed to."""
    now = now or datetime.datetime.now(datetime.timezone.utc)
    try:
        held = folders.hold(path)
    except OSError:
        return Removal()
    with held:
        return _remove_held(path, held, capture_dir, named_for, now)


def _remove_held(path: Path, held: folders.Folder, capture_dir: Path, named_for: Path | None,
                 now: datetime.datetime) -> Removal:
    """Delete the kit `remove` holds open. Takes what `remove` took and the held folder."""
    if not _owned_as_it_should_be(held.owned_by()):
        return Removal()
    try:
        if not _holds_a_kit_at(held):
            return Removal()
    except (OSError, ValueError):
        return Removal()
    name = _free_name(named_for or path, now)
    if name is None or not held.is_at(path):
        return Removal()
    try:
        atomicwrite.rename_beside(path.parent, path.name, name)
    except OSError:
        return Removal()
    renamed = path.parent / name
    if not held.settle_at(renamed):
        try:
            atomicwrite.rename_beside(path.parent, name, path.name)
        except OSError:
            pass
        return Removal(mismatch=True)
    try:
        kept = facts(renamed, now, read=_reading_through(held))
    except OSError:
        kept = {"found_at": now.isoformat()}
    atomicwrite.replace(capture_dir / f"staging-kit-{now.strftime('%Y%m%dT%H%M%SZ')}.json",
                        json.dumps(kept, indent=2), mode=atomicwrite.AS_A_PLAIN_WRITE,
                        at_a_link=atomicwrite.FOLLOW_A_TRUSTED_LINK)
    where = os.path.join(os.path.realpath(path.parent), name)
    if _empty_held(held, held.device(), _mount_points(), where) and held.is_at(renamed):
        try:
            held.remove_at(renamed)
        except OSError:
            pass
    if not os.path.lexists(renamed):
        return Removal(removed=True)
    return Removal(left=renamed)


def _reading_through(held: folders.Folder):
    """Make a reader of the manifests in the held kit, refusing a link at their names. Takes the held
    folder. Returns a function that takes a manifest's path and the most bytes to accept, and gives
    back its bytes, or None for a link, anything but a regular file, a larger file or one it cannot
    read."""
    def read(path: Path, most: int) -> bytes | None:
        try:
            raw = held.read_regular(path.name, most)
        except OSError:
            return None
        return raw if raw is not None and len(raw) <= most else None
    return read


def _empty_held(held: folders.Folder, device: int, mounts: frozenset[str], where: str) -> bool:
    """Delete everything in the held folder on `device`, its manifests last and only once the rest is
    gone, never following a link or entering a mount point or another device. Takes the folder, the
    device, the mount points and the folder's path. Returns True when it is empty."""
    held.make_writable()
    manifests = {kit.manifest for kit in staging_kit.kits()}
    try:
        names = held.names()
    except OSError:
        return False
    complete = True
    for child in sorted(names, key=lambda n: n in manifests):
        if child in manifests and not complete:
            continue
        if not held.remove_on_one_device(child, device, mounts, where):
            complete = False
    return complete
