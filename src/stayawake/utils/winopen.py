#!/usr/bin/env python3
"""Open files and folders on Windows with the system's own open call, the entry itself and never what
a link or junction at its name points to."""
from __future__ import annotations

import ctypes
import msvcrt
import os
import stat
from ctypes import wintypes
from pathlib import Path

GENERIC_READ = 0x80000000
GENERIC_WRITE = 0x40000000
FILE_READ_DATA = 0x0001
FILE_LIST_DIRECTORY = 0x0001
FILE_READ_ATTRIBUTES = 0x0080
DELETE = 0x00010000
READ_CONTROL = 0x00020000
SYNCHRONIZE = 0x00100000
FILE_SHARE_READ = 0x0001
FILE_SHARE_WRITE = 0x0002
FILE_SHARE_DELETE = 0x0004
OTHERS_MAY_READ_AND_WRITE = FILE_SHARE_READ | FILE_SHARE_WRITE
OTHERS_MAY_DO_ANYTHING = FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE
CREATE_NEW = 1
OPEN_EXISTING = 3
FILE_FLAG_BACKUP_SEMANTICS = 0x02000000
FILE_FLAG_OPEN_REPARSE_POINT = 0x00200000
ENTRY_ITSELF = FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT
_FILE_DISPOSITION_INFO_EX = 21
_DELETE_NOW_EVEN_READ_ONLY = 0x0001 | 0x0002 | 0x0010
_INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value

_KERNEL32 = ctypes.WinDLL("kernel32", use_last_error=True)
_CREATE_FILE = _KERNEL32.CreateFileW
_CREATE_FILE.argtypes = (wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, ctypes.c_void_p,
                         wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE)
_CREATE_FILE.restype = wintypes.HANDLE
_CLOSE_HANDLE = _KERNEL32.CloseHandle
_CLOSE_HANDLE.argtypes = (wintypes.HANDLE,)
_CLOSE_HANDLE.restype = wintypes.BOOL
_SET_FILE_INFORMATION = _KERNEL32.SetFileInformationByHandle
_SET_FILE_INFORMATION.argtypes = (wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD)
_SET_FILE_INFORMATION.restype = wintypes.BOOL


def open_entry(path: Path, access: int, sharing: int, disposition: int, flags: int) -> int:
    """Open a path with the system's own open call. Takes the path, the access, what others may do
    with it while it is open, whether it must exist or be new, and the open flags. Returns a
    descriptor the caller closes."""
    handle = _CREATE_FILE(str(path), access, sharing, None, disposition, flags, None)
    if handle == _INVALID_HANDLE_VALUE:
        _raise_last_error(path)
    try:
        return msvcrt.open_osfhandle(handle, 0)
    except OSError:
        _CLOSE_HANDLE(handle)
        raise


def look_at(path: Path) -> os.stat_result:
    """Read an entry's own attributes, those of the link or junction and not of what it points to.
    Takes its path. Returns them."""
    fd = open_entry(path, FILE_READ_ATTRIBUTES, OTHERS_MAY_DO_ANYTHING, OPEN_EXISTING, ENTRY_ITSELF)
    try:
        return os.fstat(fd)
    finally:
        os.close(fd)


def names_a_link(path: Path) -> bool:
    """Tell whether a path names a link or junction itself. Takes the path. Returns the answer, False
    when nothing is there."""
    try:
        return is_a_link(look_at(path))
    except FileNotFoundError:
        return False


def is_a_link(found: os.stat_result) -> bool:
    """Tell whether an entry points elsewhere: a link, a junction or any other reparse point. Takes its
    attributes. Returns the answer."""
    return bool(found.st_file_attributes & stat.FILE_ATTRIBUTE_REPARSE_POINT)


def read_regular_no_follow(path: Path, limit: int, *, same_as: os.stat_result | None = None) -> bytes | None:
    """Read a regular file itself, never what a link or junction at its name points to. Takes the path,
    the most bytes to accept and, when given, the file first found there. Returns the bytes, or None
    for a link, anything but a regular file, a file larger than `limit`, another file than the one
    first found there, or one that cannot be read."""
    try:
        fd = open_entry(path, GENERIC_READ, OTHERS_MAY_DO_ANYTHING, OPEN_EXISTING,
                        FILE_FLAG_OPEN_REPARSE_POINT)
    except OSError:
        return None
    try:
        with os.fdopen(fd, "rb") as reading:
            info = os.fstat(reading.fileno())
            if is_a_link(info) or not stat.S_ISREG(info.st_mode) or info.st_size > limit:
                return None
            if same_as is not None and (info.st_dev, info.st_ino) != (same_as.st_dev, same_as.st_ino):
                return None
            return reading.read(limit + 1)[:limit]
    except OSError:
        return None


def delete_held(fd: int, path: Path) -> None:
    """Delete the entry a descriptor holds, opened with DELETE, and its name at once, even when it is
    marked read-only. Takes the descriptor and its path. Raises `OSError` when it was not deleted."""
    flags = wintypes.DWORD(_DELETE_NOW_EVEN_READ_ONLY)
    if not _SET_FILE_INFORMATION(msvcrt.get_osfhandle(fd), _FILE_DISPOSITION_INFO_EX,
                                 ctypes.byref(flags), ctypes.sizeof(flags)):
        _raise_last_error(path)


def _raise_last_error(path: Path) -> None:
    """Raise the error the last system call on this thread left. Takes the path it was about. Raises
    the matching `OSError`."""
    failed = ctypes.get_last_error()
    raise OSError(None, ctypes.FormatError(failed), str(path), failed)
