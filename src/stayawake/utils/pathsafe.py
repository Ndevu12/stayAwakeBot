#!/usr/bin/env python3
"""Path safety and identity — refuse to write through a symlink, and tell whether two names
refer to one real object."""
from __future__ import annotations

import os
import stat
from pathlib import Path


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


def read_regular_no_follow(path: Path, limit: int) -> bytes | None:
    """Read a regular file without following a link and without waiting on anything that is not a
    file. Takes the path and the most bytes to accept. Returns the bytes, or None when the path is
    not a regular file, is larger than `limit`, or cannot be read."""
    return _read_regular(path, limit, getattr(os, "O_NOFOLLOW", 0))


def read_regular_following(path: Path, limit: int) -> bytes | None:
    """Read a regular file, following a link, without waiting on anything that is not a file.
    Takes the path and the most bytes to accept. Returns the bytes, or None when what the path
    names is not a regular file, is larger than `limit`, or cannot be read."""
    return _read_regular(path, limit, 0)


def _read_regular(path: Path, limit: int, extra_flags: int) -> bytes | None:
    """Open, check and read a regular file without blocking. Takes the path, the most bytes to
    accept and extra open flags. Returns the bytes, or None."""
    try:
        fd = os.open(str(path), os.O_RDONLY | extra_flags | getattr(os, "O_NONBLOCK", 0))
    except OSError:
        return None
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_size > limit:
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


_FOLDER_FLAGS = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0)
_SEARCH_ONLY = getattr(os, "O_SEARCH", 0) or getattr(os, "O_PATH", 0)
_MAX_LINKS = 40


class RedirectedPath(OSError):
    """A path that reaches somewhere else through a link its writer does not trust."""


def trusted_link_owners() -> set[int]:
    """Name who may own a link a write follows: root, and the user writing. Returns their ids."""
    return {0, os.geteuid()}


def _placed_by_trusted(link: os.stat_result, holder: os.stat_result, owners: set[int]) -> bool:
    """Tell whether only a trusted account could have put a link where it is. Takes the link, the
    folder holding it and the trusted owners. Returns True when both belong to a trusted owner and no
    one else can write in the folder, its group included when only root is trusted."""
    writable_by_others = 0o002 | (0o020 if owners == {0} else 0)
    return (link.st_uid in owners and holder.st_uid in owners
            and not holder.st_mode & writable_by_others)


def _open_dir(name: str, dir_fd: int | None, extra: int) -> int:
    """Open a folder to look up names in, even one the writer may pass through but not list. Takes
    its name, the folder it is in and extra flags. Returns the descriptor."""
    try:
        return os.open(name, _FOLDER_FLAGS | extra, dir_fd=dir_fd)
    except PermissionError:
        if not _SEARCH_ONLY:
            raise
        return os.open(name, _SEARCH_ONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0)
                       | extra, dir_fd=dir_fd)


def _enter(name: str, holder: int, seen: os.stat_result) -> int:
    """Open a folder inside an open folder without following a link. Takes its name, the folder and
    what a look at the name found. Returns the descriptor. Raises `RedirectedPath` when what opened is
    not the folder that was looked at."""
    entered = _open_dir(name, holder, os.O_NOFOLLOW)
    found = os.fstat(entered)
    if not stat.S_ISDIR(found.st_mode) or (found.st_dev, found.st_ino) != (seen.st_dev, seen.st_ino):
        os.close(entered)
        raise RedirectedPath(f"{name} changed while it was opened")
    return entered


def open_folder(folder: Path, *, create: bool = False, mode: int = 0o777, start: int | None = None) -> int:
    """Open a folder for writing in, one step at a time, without being redirected. Takes the folder,
    whether to make the missing parts, their mode, and an open folder a relative path starts from.
    Returns an open descriptor the caller closes. Follows a link only when root or the user writing
    owns it and the folder holding it, and no one else can write in that folder; raises
    `RedirectedPath` at any other link and `OSError` when a part is missing or is not a folder."""
    folder = Path(folder)
    if start is not None and not folder.is_absolute():
        parts, fd = list(folder.parts), os.dup(start)
    else:
        parts, fd = list(Path(os.path.abspath(folder)).parts[1:]), _open_dir("/", None, 0)
    owners = trusted_link_owners()
    links = 0
    try:
        while parts:
            part = parts.pop(0)
            if part in ("", "."):
                continue
            try:
                found = os.stat(part, dir_fd=fd, follow_symlinks=False)
            except FileNotFoundError:
                if not create or part == "..":
                    raise
                try:
                    os.mkdir(part, mode, dir_fd=fd)
                except FileExistsError:
                    pass
                found = os.stat(part, dir_fd=fd, follow_symlinks=False)
            if stat.S_ISLNK(found.st_mode):
                links += 1
                if not _placed_by_trusted(found, os.fstat(fd), owners) or links > _MAX_LINKS:
                    raise RedirectedPath(f"{folder} reaches elsewhere through a link at {part}")
                target = os.readlink(part, dir_fd=fd)
                if os.path.isabs(target):
                    os.close(fd)
                    fd = _open_dir("/", None, 0)
                parts[:0] = list(Path(target).parts[1 if os.path.isabs(target) else 0:])
                continue
            following = _enter(part, fd, found)
            os.close(fd)
            fd = following
        return fd
    except BaseException:
        os.close(fd)
        raise


def open_parent(where: Path, *, create: bool = False, mode: int = 0o777) -> tuple[int, str]:
    """Open the folder a file is named in, following a link at the file's own name by the same rule.
    Takes the file, whether to make missing folders on the way to it, and their mode. Returns the open
    folder, which the caller closes, and the file's name in it. Raises `RedirectedPath` at a link the
    writer does not trust."""
    where = Path(where)
    fd = open_folder(where.parent, create=create, mode=mode)
    name = where.name
    try:
        for _ in range(_MAX_LINKS):
            try:
                found = os.stat(name, dir_fd=fd, follow_symlinks=False)
            except FileNotFoundError:
                return fd, name
            if not stat.S_ISLNK(found.st_mode):
                return fd, name
            if not _placed_by_trusted(found, os.fstat(fd), trusted_link_owners()):
                raise RedirectedPath(f"{where} is a link")
            target = Path(os.readlink(name, dir_fd=fd))
            if target.name in ("", ".", ".."):
                raise RedirectedPath(f"{where} is a link to a folder")
            following = open_folder(target.parent, start=fd)
            os.close(fd)
            fd, name = following, target.name
        raise RedirectedPath(f"{where} reaches elsewhere through too many links")
    except BaseException:
        os.close(fd)
        raise
