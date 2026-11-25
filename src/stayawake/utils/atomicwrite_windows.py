#!/usr/bin/env python3
"""Write saw's own files on Windows in one step, or not at all, where they were named and nowhere
else: every folder on the way is held open, and a link or junction anywhere on the way is refused."""
from __future__ import annotations

import contextlib
import ctypes
import errno
import msvcrt
import os
import secrets
import shutil
import stat
from ctypes import wintypes
from pathlib import Path

from stayawake.utils import pathsafe
from stayawake.utils.link_modes import REFUSE_A_LINK, REPLACE_A_LINK

_GENERIC_READ = 0x80000000
_GENERIC_WRITE = 0x40000000
_FILE_READ_ATTRIBUTES = 0x0080
_FILE_SHARE_READ = 0x0001
_FILE_SHARE_WRITE = 0x0002
_FILE_SHARE_DELETE = 0x0004
_CREATE_NEW = 1
_OPEN_EXISTING = 3
_FILE_FLAG_BACKUP_SEMANTICS = 0x02000000
_FILE_FLAG_OPEN_REPARSE_POINT = 0x00200000
_ERROR_NOT_SAME_DEVICE = 17
_INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value

_KERNEL32 = ctypes.WinDLL("kernel32", use_last_error=True)
_CREATE_FILE = _KERNEL32.CreateFileW
_CREATE_FILE.argtypes = (wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, ctypes.c_void_p,
                         wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE)
_CREATE_FILE.restype = wintypes.HANDLE
_CLOSE_HANDLE = _KERNEL32.CloseHandle
_CLOSE_HANDLE.argtypes = (wintypes.HANDLE,)
_CLOSE_HANDLE.restype = wintypes.BOOL


@contextlib.contextmanager
def staged(where: Path, *, mode: int | None = 0o600, binary: bool = False,
           at_a_link: str = REFUSE_A_LINK):
    """Stage a file's new contents beside it and put them in place when the block ends without an
    error. Takes the file, a mode, which Windows does not apply, whether the handle takes bytes, and
    what to do when the file's name is a link: refuse it, or replace it with `REPLACE_A_LINK`. Yields
    the handle. Raises `OSError` when a folder on the way, or a link at the name it may not replace,
    is a link or junction."""
    with _open_target(Path(where), at_a_link, create=True) as target:
        staging = target.with_name(f".saw-{secrets.token_hex(8)}{target.suffix}")
        try:
            fd = _open(staging, _GENERIC_WRITE, 0, _CREATE_NEW, _FILE_FLAG_OPEN_REPARSE_POINT)
            with os.fdopen(fd, "wb" if binary else "w", **({} if binary else
                                                          {"encoding": "utf-8", "newline": ""})) as handle:
                yield handle
                handle.flush()
            os.replace(staging, target)
            staging = None
        finally:
            if staging is not None:
                with contextlib.suppress(OSError):
                    os.unlink(staging)


def read_back(where: Path, limit: int, *, at_a_link: str = REFUSE_A_LINK) -> bytes | None:
    """Read a file saw wrote, through the same folders it was written through. Takes the file, how
    many bytes to read at most, and how its name was written. Returns its bytes, or None when it is
    not a regular file there."""
    try:
        with _open_target(Path(where), at_a_link) as target:
            fd = _open(target, _GENERIC_READ, _FILE_SHARE_READ | _FILE_SHARE_WRITE | _FILE_SHARE_DELETE,
                       _OPEN_EXISTING, _FILE_FLAG_OPEN_REPARSE_POINT)
            with os.fdopen(fd, "rb") as reading:
                found = os.fstat(reading.fileno())
                if _is_a_link(found) or not stat.S_ISREG(found.st_mode):
                    return None
                return reading.read(limit + 1)
    except OSError:
        return None


def make_folder(where: Path, *, mode: int | None = None) -> None:
    """Make a folder and every missing folder above it. Takes the folder and a mode, which Windows does
    not apply. Raises `OSError` when it is reached through a link or junction."""
    with _open_folder(Path(where), create=True):
        pass


def set_mode(where: Path, mode: int) -> None:
    """Check that a file is a regular file of its own, reached without a link or junction. Takes the
    file and a mode, which Windows does not apply. Raises `OSError` when it is reached through a link
    or junction, or is not a regular file."""
    with _open_target(Path(where), REFUSE_A_LINK) as target:
        found = _look_at(target)
        if _is_a_link(found) or not stat.S_ISREG(found.st_mode):
            raise pathsafe.RedirectedPath(f"{where} is not a file of its own")


def new_folder(parent: Path, stem: str, *, mode: int = 0o777, tries: int = 1000) -> Path:
    """Make a new folder named `stem`, or `stem-<n>` when that name is taken. Takes the parent, the
    name, a mode, which Windows does not apply, and how many names to try. Returns its path. Raises
    `OSError` when none could be made."""
    pathsafe.one_entry(stem)
    with _open_folder(Path(parent), create=True) as folder:
        for n in range(tries):
            name = stem if n == 0 else f"{stem}-{n}"
            try:
                os.mkdir(folder / name)
                return Path(parent) / name
            except FileExistsError:
                continue
    raise FileExistsError(f"no free name for {stem} in {parent}")


def rename_in(folder: Path, old: str, new: str) -> None:
    """Rename an entry of a folder reached without a link or junction, replacing what has the new
    name. Takes the folder, the entry's name and its new name. Raises `OSError` when it could not be
    renamed."""
    pathsafe.one_entry(old)
    pathsafe.one_entry(new)
    with _open_folder(Path(folder)) as opened:
        os.replace(opened / old, opened / new)


def move_into(source: Path, folder: Path, name: str) -> None:
    """Move a file or folder, whole, into a folder under a new name, reaching both folders without a
    link or junction. Takes the source, the folder and the name. Raises `OSError` when either folder
    is reached through one, or the move could not be made. A copy that could not be made in full
    leaves the source in place."""
    source = Path(source)
    pathsafe.one_entry(name)
    entry = _entry_name(source)
    with _open_folder(source.parent) as origin, _open_folder(Path(folder)) as destination:
        try:
            os.replace(origin / entry, destination / name)
            return
        except OSError as error:
            if error.winerror != _ERROR_NOT_SAME_DEVICE:
                raise
        if _copy(origin / entry, destination / name):
            shutil.rmtree(origin / entry)
        else:
            os.unlink(origin / entry)


def rename_beside(folder: Path, name: str, new_name: str) -> None:
    """Rename an entry of a folder, a file or folder, to another name in the same folder, never
    replacing what is already there. Takes the folder, reached without a link or junction, the entry
    and its new name. Raises `FileExistsError` when the new name is taken, and `OSError` when the
    folder is reached through a link or the rename could not be made."""
    pathsafe.one_entry(name)
    pathsafe.one_entry(new_name)
    with _open_folder(Path(folder)) as opened:
        os.rename(opened / name, opened / new_name)


@contextlib.contextmanager
def _open_target(where: Path, at_a_link: str, *, create: bool = False):
    """Hold the folder a file is written in and name the file there. Takes the file, what to do at a
    link at its name, and whether to make missing folders. Yields the file's path in the held folder.
    Raises `RedirectedPath` at a link at the name, unless `at_a_link` is `REPLACE_A_LINK`."""
    name = _entry_name(where)
    with _open_folder(where.parent, create=create) as folder:
        target = folder / name
        if at_a_link != REPLACE_A_LINK and _names_a_link(target):
            raise pathsafe.RedirectedPath(f"{where} is a link")
        yield target


@contextlib.contextmanager
def _open_folder(folder: Path, *, create: bool = False):
    """Hold a folder open, and every folder on the way to it from its drive, one step at a time. Takes
    the folder and whether to make the missing parts. Yields its absolute path, held until the block
    ends. Raises `RedirectedPath` at a link or junction on the way, and `OSError` when a part is
    missing or is not a folder."""
    absolute = Path(os.path.abspath(folder))
    here = Path(absolute.anchor)
    held = [_hold_folder(here, folder)]
    try:
        for part in absolute.parts[1:]:
            here = here / part
            held.append(_hold_or_make_folder(here, folder, create))
        yield absolute
    finally:
        for fd in reversed(held):
            os.close(fd)


def _hold_or_make_folder(path: Path, named: Path, create: bool) -> int:
    """Hold one folder on the way to another, making it first when it is missing and `create` is set.
    Takes its path, the folder being opened and whether to make it. Returns a descriptor the caller
    closes."""
    try:
        return _hold_folder(path, named)
    except FileNotFoundError:
        if not create:
            raise
    with contextlib.suppress(FileExistsError):
        os.mkdir(path)
    return _hold_folder(path, named)


def _hold_folder(path: Path, named: Path) -> int:
    """Hold one folder on the way to another. Takes its path and the folder being opened. Returns a
    descriptor the caller closes. Raises `RedirectedPath` at a link or junction, and
    `NotADirectoryError` at anything else that is not a folder."""
    fd = _hold(path)
    try:
        found = os.fstat(fd)
        if _is_a_link(found):
            raise pathsafe.RedirectedPath(f"{named} reaches elsewhere through a link at {path}")
        if not stat.S_ISDIR(found.st_mode):
            raise NotADirectoryError(errno.ENOTDIR, os.strerror(errno.ENOTDIR), str(path))
    except BaseException:
        os.close(fd)
        raise
    return fd


def _hold(path: Path) -> int:
    """Open an entry itself to read its attributes, the link or junction and not what it points to.
    Takes its path. Returns a descriptor the caller closes."""
    return _open(path, _FILE_READ_ATTRIBUTES, _FILE_SHARE_READ | _FILE_SHARE_WRITE, _OPEN_EXISTING,
                 _FILE_FLAG_BACKUP_SEMANTICS | _FILE_FLAG_OPEN_REPARSE_POINT)


def _open(path: Path, access: int, sharing: int, disposition: int, flags: int) -> int:
    """Open a path with the system's own open call. Takes the path, the access, what others may do
    with it while it is open, whether it must exist or be new, and the open flags. Returns a
    descriptor the caller closes."""
    handle = _CREATE_FILE(str(path), access, sharing, None, disposition, flags, None)
    if handle == _INVALID_HANDLE_VALUE:
        failed = ctypes.get_last_error()
        raise OSError(None, ctypes.FormatError(failed), str(path), failed)
    try:
        return msvcrt.open_osfhandle(handle, 0)
    except OSError:
        _CLOSE_HANDLE(handle)
        raise


def _look_at(path: Path) -> os.stat_result:
    """Read an entry's own attributes, those of the link or junction and not of what it points to.
    Takes its path. Returns them."""
    fd = _hold(path)
    try:
        return os.fstat(fd)
    finally:
        os.close(fd)


def _names_a_link(path: Path) -> bool:
    """Tell whether a path names a link or junction itself. Takes the path. Returns the answer, False
    when nothing is there."""
    try:
        return _is_a_link(_look_at(path))
    except FileNotFoundError:
        return False


def _is_a_link(found: os.stat_result) -> bool:
    """Tell whether an entry points elsewhere: a link, a junction or any other reparse point. Takes its
    attributes. Returns the answer."""
    return bool(found.st_file_attributes & stat.FILE_ATTRIBUTE_REPARSE_POINT)


def _entry_name(path: Path) -> str:
    """Name the entry a path ends in. Takes the path. Returns the name. Raises `RedirectedPath` when it
    ends in no entry."""
    if path.name in ("", ".."):
        raise pathsafe.RedirectedPath(f"{path} names no entry")
    return path.name


def _copy(source: Path, copy: Path) -> bool:
    """Copy a file or folder, whole, keeping its times. Takes the source and the copy's path. Returns
    whether it was a folder. Raises `OSError` at a link or junction in it."""
    found = _look_at(source)
    if _is_a_link(found):
        raise OSError(f"{source} is a link")
    times = (found.st_atime_ns, found.st_mtime_ns)
    if stat.S_ISDIR(found.st_mode):
        os.mkdir(copy)
        for child in os.listdir(source):
            _copy(source / child, copy / child)
        os.utime(copy, ns=times)
        return True
    shutil.copyfile(source, copy)
    os.utime(copy, ns=times)
    return False
