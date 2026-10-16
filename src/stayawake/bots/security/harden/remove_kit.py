#!/usr/bin/env python3
"""Delete the known worm's staging kit from where a denial goes, keeping only the facts about it."""
from __future__ import annotations

import datetime
import hashlib
import json
import os
import re
import stat
import sys
from dataclasses import dataclass
from pathlib import Path

from stayawake.bots.security.hygiene import staging_kit
from stayawake.bots.security.hygiene.staging_kit import REMOVING_MARK
from stayawake.utils import atomicwrite, hostdenial, operator, pathsafe

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


def _owned_as_it_should_be(seen_uid: int) -> bool:
    """Tell whether the kit is owned by the account saw acts for, or by root on a run as root."""
    return seen_uid == operator.acting_uid() or (hostdenial.privileged() and seen_uid == 0)


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


def facts(folder: Path, when: datetime.datetime) -> dict:
    """Return the facts about a staging kit worth keeping once it is gone: when it was made and
    changed, the digests of its manifests, and the packages it holds. Takes the folder and the time."""
    found = folder.lstat()
    manifest = pathsafe.read_regular_no_follow(folder / "package.json", _MOST_MANIFEST_BYTES)
    lock = pathsafe.read_regular_no_follow(folder / "package-lock.json", _MOST_MANIFEST_BYTES)
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


def _remove_on_one_device(folder: int, name: str, device: int, mounts: frozenset[str], where: str) -> bool:
    """Delete an entry of an open folder and everything under it on `device`, never following a link
    and never entering a mount point or another device. Takes the folder, the entry, the device, the
    mount points and the entry's folder path. Returns True when the entry is gone."""
    try:
        found = os.stat(name, dir_fd=folder, follow_symlinks=False)
    except FileNotFoundError:
        return True
    except OSError:
        return False
    here = os.path.join(where, name)
    if not stat.S_ISDIR(found.st_mode):
        try:
            os.unlink(name, dir_fd=folder)
        except OSError:
            return False
        return True
    if found.st_dev != device or here in mounts:
        return False
    try:
        inner = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=folder)
    except OSError:
        return False
    try:
        opened = os.fstat(inner)
        if (opened.st_dev, opened.st_ino) != (found.st_dev, found.st_ino):
            return False
        try:
            os.fchmod(inner, stat.S_IRWXU)
        except OSError:
            pass
        with os.scandir(inner) as entries:
            names = [entry.name for entry in entries]
        complete = True
        for child in names:
            if not _remove_on_one_device(inner, child, device, mounts, here):
                complete = False
    except (OSError, RecursionError):
        return False
    finally:
        os.close(inner)
    if not complete:
        return False
    try:
        os.rmdir(name, dir_fd=folder)
    except OSError:
        return False
    return True


def _manifest_at(folder: int, name: str) -> dict | None:
    """Read a manifest in a held folder, never through a link or a pipe. Takes the folder's descriptor
    and the manifest's name. Returns what it holds, or None when it is not a bounded regular file of
    JSON; raises OSError when it is there and cannot be read."""
    try:
        opened = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_NONBLOCK", 0), dir_fd=folder)
    except FileNotFoundError:
        return None
    try:
        found = os.fstat(opened)
        if not stat.S_ISREG(found.st_mode) or found.st_size > _MOST_MANIFEST_BYTES:
            return None
        raw = os.read(opened, _MOST_MANIFEST_BYTES + 1)
    finally:
        os.close(opened)
    try:
        held = json.loads(raw)
    except (ValueError, RecursionError):
        return None
    return held if isinstance(held, dict) else None


def _holds_a_kit_at(folder: int) -> bool:
    """Tell whether a held folder holds a known worm's staging kit, read through the descriptor. Takes it.
    Returns the answer; raises OSError when a manifest is there and cannot be read."""
    for name in sorted({kit.manifest for kit in staging_kit.kits()}):
        held = _manifest_at(folder, name)
        if held is not None and staging_kit.is_a_kit(name, held):
            return True
    return False


def _is_held(path: Path, held: int) -> bool:
    """Tell whether `path` names the folder held open, whose inode cannot be given to anything else."""
    try:
        here, opened = path.lstat(), os.fstat(held)
    except OSError:
        return False
    return (here.st_dev, here.st_ino) == (opened.st_dev, opened.st_ino)


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
        held = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    except OSError:
        return Removal()
    try:
        return _remove_held(path, held, capture_dir, named_for, now)
    finally:
        os.close(held)


def _remove_held(path: Path, held: int, capture_dir: Path, named_for: Path | None,
                 now: datetime.datetime) -> Removal:
    """Delete the kit `remove` holds open. Takes what `remove` took and the descriptor."""
    opened = os.fstat(held)
    if not _owned_as_it_should_be(opened.st_uid):
        return Removal()
    try:
        if not _holds_a_kit_at(held):
            return Removal()
    except (OSError, ValueError):
        return Removal()
    name = _free_name(named_for or path, now)
    if name is None or not _is_held(path, held):
        return Removal()
    try:
        atomicwrite.rename_beside(path.parent, path.name, name)
    except OSError:
        return Removal()
    renamed = path.parent / name
    if not _is_held(renamed, held):
        try:
            atomicwrite.rename_beside(path.parent, name, path.name)
        except OSError:
            pass
        return Removal(mismatch=True)
    try:
        kept = facts(renamed, now)
    except OSError:
        kept = {"found_at": now.isoformat()}
    atomicwrite.replace(capture_dir / f"staging-kit-{now.strftime('%Y%m%dT%H%M%SZ')}.json",
                        json.dumps(kept, indent=2), mode=atomicwrite.AS_A_PLAIN_WRITE,
                        at_a_link=atomicwrite.FOLLOW_A_TRUSTED_LINK)
    where = os.path.join(os.path.realpath(path.parent), name)
    if _empty_held(held, opened.st_dev, _mount_points(), where) and _is_held(renamed, held):
        try:
            os.rmdir(renamed)
        except OSError:
            pass
    if not os.path.lexists(renamed):
        return Removal(removed=True)
    return Removal(left=renamed)


def _empty_held(held: int, device: int, mounts: frozenset[str], where: str) -> bool:
    """Delete everything in the held folder on `device`, its manifests last and only once the rest is
    gone, never following a link or entering a mount point or another device. Takes the descriptor, the
    device, the mount points and the folder's path. Returns True when it is empty."""
    try:
        os.fchmod(held, stat.S_IRWXU)
    except OSError:
        pass
    manifests = {kit.manifest for kit in staging_kit.kits()}
    try:
        with os.scandir(held) as entries:
            names = [entry.name for entry in entries]
    except OSError:
        return False
    complete = True
    for child in sorted(names, key=lambda n: n in manifests):
        if child in manifests and not complete:
            continue
        if not _remove_on_one_device(held, child, device, mounts, where):
            complete = False
    return complete
