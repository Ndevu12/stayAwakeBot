#!/usr/bin/env python3
"""Path safety and identity — refuse to write through a symlink, and tell whether two names
refer to one real object."""
from __future__ import annotations

import os
import re
import stat
from pathlib import Path

_WINDOWS_PATH = re.compile(r"^(?:[A-Za-z]:[\\/]|%[A-Za-z_][A-Za-z0-9_()]*%|\\\\|\\SystemRoot\\)")
_WINDOWS_VARIABLE = re.compile(r"%([A-Za-z_][A-Za-z0-9_()]*)%")


def is_windows_path(path: str) -> bool:
    """Tell whether a path is written the Windows way: a drive, a `%VARIABLE%`, a share or
    `\\SystemRoot`. Takes the path. Returns the answer."""
    return bool(_WINDOWS_PATH.match(path or ""))


def comparable(path: str) -> str:
    """Put a path in the form its folders are compared in. Takes the path. Returns a Windows path
    in lower case with forward slashes and its `%VARIABLES%` expanded where they are set, and any
    other path normalised with `~` expanded."""
    if not is_windows_path(path):
        return os.path.normpath(os.path.expanduser(path))
    expanded = _WINDOWS_VARIABLE.sub(lambda m: os.environ.get(m.group(1), m.group(0)), path)
    return expanded.replace("\\", "/").lower()


def is_regular_file(path: Path) -> bool:
    """True iff `path` is a REGULAR file (follows symlinks; not a dir/FIFO/socket/device). Swallows
    OSError → False. The gate every "read an arbitrary file" path shares: opening a FIFO named like a
    real file read-BLOCKS forever, so callers must confirm regular-ness BEFORE `open()`."""
    try:
        return stat.S_ISREG(path.stat().st_mode)
    except OSError:
        return False


def read_regular_bytes(path: Path) -> bytes | None:
    """The bytes of a regular file, or None if it is absent / non-regular / unreadable. NEVER opens a
    non-regular file (a FIFO would block forever —). One shared implementation for every probe
    that reads a possibly-adversarial path on disk."""
    if not is_regular_file(path):
        return None
    try:
        return path.read_bytes()
    except OSError:
        return None


def read_regular_no_follow(path: Path, limit: int, *, same_as: os.stat_result | None = None) -> bytes | None:
    """Read a regular file without following a link and without waiting on anything that is not a
    file. Takes the path, the most bytes to accept and, when given, the file first found there. Returns
    the bytes, or None when the path is not a regular file, is larger than `limit`, is not the file
    first found there, or cannot be read."""
    return _read_regular(path, limit, no_follow_flag(), same_as)


def read_regular_following(path: Path, limit: int) -> bytes | None:
    """Read a regular file, following a link, without waiting on anything that is not a file.
    Takes the path and the most bytes to accept. Returns the bytes, or None when what the path
    names is not a regular file, is larger than `limit`, or cannot be read."""
    return _read_regular(path, limit, 0)


def _read_regular(path: Path, limit: int, extra_flags: int,
                  same_as: os.stat_result | None = None) -> bytes | None:
    """Open, check and read a regular file without blocking. Takes the path, the most bytes to
    accept, extra open flags and, when given, the file it must be. Returns the bytes, or None."""
    try:
        fd = os.open(str(path), os.O_RDONLY | extra_flags | getattr(os, "O_NONBLOCK", 0))
    except OSError:
        return None
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_size > limit:
            return None
        if same_as is not None and (info.st_dev, info.st_ino) != (same_as.st_dev, same_as.st_ino):
            return None
        with os.fdopen(fd, "rb", closefd=False) as fh:
            return fh.read(limit + 1)[:limit]
    except OSError:
        return None
    finally:
        os.close(fd)


def read_regular_text(path: Path, *, errors: str = "replace") -> str | None:
    """The UTF-8 text of a regular file, or None (absent / non-regular / unreadable). Decodes
    tolerantly (`errors="replace"` by default) so a non-UTF-8 byte can't crash a read of an
    attacker-influenced file — the same evasion-safe decoding the scanner uses. Never opens a
    non-regular file."""
    if not is_regular_file(path):
        return None
    try:
        return path.read_text(encoding="utf-8", errors=errors)
    except OSError:
        return None


def grade(path: Path) -> str:
    """'ok', 'absent', or 'unverified'. Never opens a FIFO, socket, or device."""
    try:
        st = path.stat()
    except FileNotFoundError:
        return "absent"
    except OSError:
        return "unverified"
    if stat.S_ISDIR(st.st_mode):
        try:
            for _ in path.iterdir():
                break
        except OSError:
            return "unverified"
        return "ok"
    if stat.S_ISREG(st.st_mode):
        try:
            with path.open("rb"):
                pass
        except OSError:
            return "unverified"
        return "ok"
    return "unverified"


def regular_size(root: Path, names) -> int:
    """Return the total size of the regular files among `names` under `root`, in bytes, without
    following a link. Takes the folder and the relative names."""
    total = 0
    for name in names:
        try:
            found = os.lstat(Path(root) / name)
        except OSError:
            continue
        if stat.S_ISREG(found.st_mode):
            total += found.st_size
    return total


def is_safe_write_target(path: Path, root: Path) -> bool:
    """True only if writing to / deleting `path` stays inside `root` and does NOT go through a symlink.

    Refuses:
      * a symlinked LEAF — `write_text`/`rmtree` would follow it into a planted sink;
      * a path that RESOLVES outside `root` — a symlinked ancestor directory, or a `..` escape.
    Both operands are `resolve()`d, so a `root` that itself lives under a symlink (e.g. macOS
    `/tmp`→`/private/tmp`) does NOT cause a false refusal. Fails CLOSED (returns False) on any resolve
    error — e.g. a symlink loop — so an undecidable path is never treated as writable. Callers write
    only after this returns True (check-then-write; a same-process TOCTOU race on a static checkout is
    out of the threat model).

    NOTE: `root` must be a real (non-symlinked) directory the caller controls — do not pass a
    potentially attacker-planted directory as its OWN root, or a symlinked root would trivially contain
    itself. Pass the fixed parent the target is meant to stay under.
    """
    try:
        if path.is_symlink():
            return False
        return path.resolve().is_relative_to(root.resolve())
    except (OSError, RuntimeError, ValueError):
        return False


def entry_id(path: str | Path) -> tuple[int, int] | None:
    """Name the directory entry at `path`. Takes the path. Returns its device and inode when the
    inode is real, or None when the entry cannot be read or the inode is zero."""
    try:
        info = os.lstat(path)
    except OSError:
        return None
    if not info.st_ino:
        return None
    return (info.st_dev, info.st_ino)


def canonical_id(path: str | Path) -> tuple | str:
    """An identity two names for the same object share.

    `(st_dev, st_ino)` only when `st_ino` is truthy — some mounts report 0, and collapsing on that
    would stop real directories being probed — then non-strict realpath (never `strict=True`: it
    raises on the missing/ELOOP/EACCES paths still worth probing), then the string. Fails OPEN, so
    an unresolvable path stays DISTINCT and means more probing, never less.
    """
    try:
        st = os.stat(path)
        if st.st_ino:
            return (st.st_dev, st.st_ino)
    except (OSError, ValueError):
        pass
    try:
        return os.path.realpath(path)
    except (OSError, ValueError):
        return str(path)


def distinct(paths) -> int:
    """How many of `paths` name genuinely different objects."""
    return len({canonical_id(p) for p in paths})


def trusted_ancestor(path: Path) -> bool:
    """Whether creating under `path` stays where the caller named.

    A symbolic link is only accepted when root owns the link itself: the system's own
    (`/var` → `/private/var`) resolves that way, and nobody without root could have put it there.
    A link anyone else could have planted redirects the write and is refused."""
    try:
        st = path.lstat()
    except OSError:
        return False
    if stat.S_ISLNK(st.st_mode):
        return st.st_uid == 0 and path.is_dir()
    return stat.S_ISDIR(st.st_mode)


def passes_through_a_link(root: Path, path: Path) -> bool:
    """Tell whether a directory between `root` and `path` is a link. Takes both. Returns True
    when one is, and when `path` lies outside `root`."""
    try:
        parts = path.relative_to(root).parts[:-1]
    except ValueError:
        return True
    here = root
    for part in parts:
        here = here / part
        if here.is_symlink():
            return True
    return False


def reached_where_it_was_named(path: Path) -> bool:
    """Whether every step to `path` stays where the caller said. Takes the path. Returns False when
    any ancestor redirects it elsewhere."""
    for ancestor in reversed(path.parents):
        if not trusted_ancestor(ancestor):
            return False
    return True


def every_file_arrived(source: Path, destination: Path) -> bool:
    """Whether the copy holds every regular file the original does.

    Takes the original and the copy. Returns False when a file is missing from the copy, or when
    any part of the original could not be read. Symlinks are skipped: they are copied as links, and
    a dangling one would read as missing.
    """
    unread = False

    def _unreadable(_exc: OSError) -> None:
        nonlocal unread
        unread = True

    try:
        for here, _subdirs, names in os.walk(source, onerror=_unreadable):
            root = Path(here)
            for name in names:
                path = root / name
                if path.is_symlink() or not path.is_file():
                    continue
                if not (destination / path.relative_to(source)).exists():
                    return False
    except OSError:
        return False
    return not unread


def no_follow_flag() -> int:
    """Return the open flag that refuses a link at the final name, or 0 when this system has none."""
    return getattr(os, "O_NOFOLLOW", 0)


def directory_flag() -> int:
    """Return the open flag that requires a folder, or 0 when this system has none."""
    return getattr(os, "O_DIRECTORY", 0)


class RedirectedPath(OSError):
    """A path that reaches somewhere else through a link its writer does not trust."""


def one_entry(name: str) -> None:
    """Refuse a name that is not exactly one entry of a folder. Takes the name. Raises
    `RedirectedPath` for an empty name, `.`, `..`, or one with a separator in it."""
    if name in ("", ".", "..") or os.sep in name or (os.altsep and os.altsep in name):
        raise RedirectedPath(f"{name!r} is not one entry of a folder")


if os.name == "nt":
    from stayawake.utils.winopen import read_regular_no_follow
