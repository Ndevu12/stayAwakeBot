#!/usr/bin/env python3
"""Hold folders open on Windows against anyone else renaming or deleting them, and change what is in
them, refusing any link or junction on the way."""
from __future__ import annotations

import contextlib
import ctypes
import errno
import msvcrt
import os
import shutil
import stat
from ctypes import wintypes
from pathlib import Path

from stayawake.utils import pathsafe, winlock

_GENERIC_READ = 0x80000000
_GENERIC_WRITE = 0x40000000
_FILE_READ_DATA = 0x0001
_FILE_LIST_DIRECTORY = 0x0001
_FILE_READ_ATTRIBUTES = 0x0080
_DELETE = 0x00010000
_READ_CONTROL = 0x00020000
_SYNCHRONIZE = 0x00100000
_FILE_SHARE_READ = 0x0001
_FILE_SHARE_WRITE = 0x0002
_FILE_SHARE_DELETE = 0x0004
_CREATE_NEW = 1
_OPEN_EXISTING = 3
_FILE_FLAG_BACKUP_SEMANTICS = 0x02000000
_FILE_FLAG_OPEN_REPARSE_POINT = 0x00200000
_ENTRY_ITSELF = _FILE_FLAG_BACKUP_SEMANTICS | _FILE_FLAG_OPEN_REPARSE_POINT
_HOLD_A_FOLDER = _FILE_LIST_DIRECTORY | _FILE_READ_ATTRIBUTES | _READ_CONTROL | _SYNCHRONIZE
_OTHERS_MAY_READ_AND_WRITE = _FILE_SHARE_READ | _FILE_SHARE_WRITE
_OTHERS_MAY_DO_ANYTHING = _FILE_SHARE_READ | _FILE_SHARE_WRITE | _FILE_SHARE_DELETE
_FILE_DISPOSITION_INFO_EX = 21
_DELETE_NOW_EVEN_READ_ONLY = 0x0001 | 0x0002 | 0x0010
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
_SET_FILE_INFORMATION = _KERNEL32.SetFileInformationByHandle
_SET_FILE_INFORMATION.argtypes = (wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD)
_SET_FILE_INFORMATION.restype = wintypes.BOOL


class Folder:
    """A folder held open, with every folder on the way to it."""

    def __init__(self, path: Path, held: list[int]):
        self.path = path
        self._held = held
        self._own = held[-1]
        self._settled: int | None = None

    def __enter__(self) -> Folder:
        return self

    def __exit__(self, *_exc) -> None:
        self.close()

    def close(self) -> None:
        """Let go of the folder and every folder on the way to it. Returns nothing."""
        while self._held:
            os.close(self._held.pop())

    def is_link(self, name: str) -> bool:
        """Tell whether a name in the folder is a link, a junction or another reparse point. Takes the
        name. Returns the answer."""
        return _names_a_link(self._child(name))

    def link_at(self, name: str) -> tuple[bool, Path | None] | None:
        """Look at a link at a name in the folder, held against change while it is read. Takes the name.
        Returns None for anything but a link, else whether it is a symbolic link a trusted account owns
        (the system, the Administrators group or the account saw acts for) and, for such a link, where
        it points."""
        link = self._child(name)
        if not _names_a_link(link):
            return None
        fd = _open(link, _FILE_READ_DATA | _FILE_READ_ATTRIBUTES | _READ_CONTROL, _FILE_SHARE_READ,
                   _OPEN_EXISTING, _ENTRY_ITSELF)
        try:
            held, seen = os.fstat(fd), os.lstat(link)
            if not (stat.S_ISLNK(seen.st_mode) and seen.st_reparse_tag == stat.IO_REPARSE_TAG_SYMLINK
                    and (held.st_dev, held.st_ino) == (seen.st_dev, seen.st_ino)
                    and winlock.trusted_owner(winlock.held_owner_sid(msvcrt.get_osfhandle(fd)),
                                              winlock.current_sid())):
                return False, None
            return True, Path(os.readlink(link))
        finally:
            os.close(fd)

    def open_under(self, path: Path) -> Folder:
        """Open a folder named from this one, by the same rule as `open_folder`. Takes its path,
        relative to this folder or absolute. Returns it held open."""
        return open_folder(Path(os.path.join(self.path, path)))

    @contextlib.contextmanager
    def write_staged(self, name: str, staging: str, mode: int | None, binary: bool):
        """Write a file's new contents under a staging name and rename them over the file when the block
        ends without an error. Takes the file's name, the staging name, a mode, which Windows does not
        apply, and whether the handle takes bytes. Yields the handle."""
        target, staged = self._child(name), self._child(staging)
        fd = _open(staged, _GENERIC_WRITE, 0, _CREATE_NEW, _FILE_FLAG_OPEN_REPARSE_POINT)
        try:
            with os.fdopen(fd, "wb" if binary else "w", **({} if binary else
                                                          {"encoding": "utf-8", "newline": ""})) as handle:
                yield handle
                handle.flush()
            os.replace(staged, target)
            staged = None
        finally:
            if staged is not None:
                with contextlib.suppress(OSError):
                    os.unlink(staged)

    def read_regular(self, name: str, limit: int) -> bytes | None:
        """Read a regular file in the folder itself, never what a link or junction at its name points
        to. Takes the name and how many bytes to read at most. Returns up to `limit` + 1 bytes, or None
        for anything but a regular file. Raises `OSError` when it cannot be opened or read."""
        fd = _open(self._child(name), _GENERIC_READ, _OTHERS_MAY_DO_ANYTHING, _OPEN_EXISTING,
                   _FILE_FLAG_OPEN_REPARSE_POINT)
        with os.fdopen(fd, "rb") as reading:
            found = os.fstat(reading.fileno())
            if _is_a_link(found) or not stat.S_ISREG(found.st_mode):
                return None
            return reading.read(limit + 1)

    def set_own_mode(self, mode: int) -> None:
        """Do nothing: Windows gives folders no mode. Takes the mode. Returns nothing."""

    def set_mode_of(self, name: str, mode: int) -> bool:
        """Check that a file in the folder is a regular file itself, Windows giving files no mode. Takes
        its name and the mode. Returns whether it is one."""
        found = _look_at(self._child(name))
        return not _is_a_link(found) and stat.S_ISREG(found.st_mode)

    def make_dir(self, name: str, mode: int) -> None:
        """Make a folder in this one. Takes its name and mode. Raises `FileExistsError` when the name is
        taken."""
        os.mkdir(self._child(name), mode)

    def rename_to(self, entry: str, folder: Folder, name: str) -> None:
        """Move an entry of this folder into another held folder under a name, replacing what is there.
        Takes the entry, the folder and the name. Raises `OSError` when it was not moved."""
        os.replace(self._child(entry), folder._child(name))

    def rename_no_replace(self, name: str, new_name: str) -> None:
        """Rename an entry of this folder, never replacing what has the new name. Takes the entry and
        its new name. Raises `FileExistsError` when the new name is taken."""
        os.rename(self._child(name), self._child(new_name))

    def copy_into(self, entry: str, folder: Folder, name: str) -> bool:
        """Copy an entry of this folder, whole, into another held folder under a name, keeping its
        times. Takes the entry, the folder and the name. Returns whether it was a folder. Raises
        `OSError` at a link or junction in it."""
        return _copy(self._child(entry), folder._child(name))

    def remove(self, entry: str, is_folder: bool) -> None:
        """Delete an entry of this folder, and everything under it when it is a folder. Takes the entry
        and whether it is a folder. Raises `OSError` when it was not deleted."""
        if is_folder:
            shutil.rmtree(self._child(entry))
        else:
            os.unlink(self._child(entry))

    def owned_by(self) -> str:
        """Grade who owns the folder. Returns `self` for the account saw acts for, `root` for the system
        or the Administrators group, or `other`."""
        return winlock.grade(winlock.held_owner_sid(msvcrt.get_osfhandle(self._own)), winlock.current_sid())

    def device(self) -> int:
        """Name the volume the folder is on. Returns it."""
        return os.fstat(self._own).st_dev

    def is_at(self, path: Path) -> bool:
        """Tell whether `path` names the folder held open. Takes the path. Returns the answer."""
        try:
            here, opened = _look_at(Path(path)), os.fstat(self._own)
        except OSError:
            return False
        return (here.st_dev, here.st_ino) == (opened.st_dev, opened.st_ino)

    def settle_at(self, path: Path) -> bool:
        """Hold the folder at the name it was renamed to, against anyone else renaming or deleting it
        from there. Takes the path. Returns whether `path` names the folder held open and it is now
        held there."""
        try:
            fd = _open(Path(path), _HOLD_A_FOLDER | _DELETE, _OTHERS_MAY_READ_AND_WRITE, _OPEN_EXISTING,
                       _ENTRY_ITSELF)
        except OSError:
            return False
        found, opened = os.fstat(fd), os.fstat(self._own)
        if _is_a_link(found) or (found.st_dev, found.st_ino) != (opened.st_dev, opened.st_ino):
            os.close(fd)
            return False
        self._held.append(fd)
        self._settled = fd
        self.path = Path(os.path.abspath(path))
        return True

    def make_writable(self) -> None:
        """Do nothing: deleting on Windows ignores the read-only mark. Returns nothing."""

    def names(self) -> list[str]:
        """List the folder's entries. Returns their names."""
        return os.listdir(self.path)

    def remove_on_one_device(self, name: str, device: int, mounts: frozenset[str], where: str) -> bool:
        """Delete an entry of the folder and everything under it on `device`: a link or junction itself,
        never what it points to, and never a folder on another volume. Takes the entry, the volume, and
        the mount points and folder path macOS and Linux use. Returns True when the entry is gone."""
        return _remove_on_one_volume(self._child(name), device)

    def remove_at(self, path: Path) -> None:
        """Delete the empty folder held open where it was settled. Takes its path. Raises `OSError`
        when it was not settled there or was not deleted."""
        if self._settled is None:
            raise OSError(errno.EBUSY, "the folder is not held where it is deleted", str(path))
        _delete_held(self._settled, Path(path))

    def _child(self, name: str) -> Path:
        """Name an entry of the folder. Takes its name. Returns its path. Raises `RedirectedPath` when
        the name is not exactly one entry."""
        pathsafe.one_entry(name)
        return self.path / name


def open_folder(folder: Path, *, create: bool = False, mode: int = 0o777) -> Folder:
    """Hold a folder open, and every folder on the way to it from its drive, one step at a time,
    against anyone else renaming or deleting them while held. Takes the folder, whether to make the
    missing parts and their mode. Returns it held open. Raises `RedirectedPath` at a link or junction on the way, and
    `OSError` when a part is missing or is not a folder."""
    absolute = Path(os.path.abspath(folder))
    here = Path(absolute.anchor)
    held = [_hold_folder(here, folder)]
    try:
        for part in absolute.parts[1:]:
            here = here / part
            held.append(_hold_or_make_folder(here, folder, create, mode))
    except BaseException:
        for fd in reversed(held):
            os.close(fd)
        raise
    return Folder(absolute, held)


def hold(path: Path) -> Folder:
    """Hold a folder open by its own name, and every folder on the way to it, refusing a link or
    junction anywhere. The folder itself may still be renamed, by saw or anyone else, until it is
    settled. Takes its path.
    Returns it held open. Raises `OSError` when it is reached through a link or is not a folder."""
    path = Path(path)
    name = path.name
    pathsafe.one_entry(name)
    parent = open_folder(path.parent)
    try:
        own = _hold_folder(parent.path / name, path, sharing=_OTHERS_MAY_DO_ANYTHING)
    except BaseException:
        parent.close()
        raise
    return Folder(parent.path / name, [*parent._held, own])


def is_another_disk(error: OSError) -> bool:
    """Tell whether an error is a rename refused across two volumes. Takes the error. Returns the
    answer."""
    return error.winerror == _ERROR_NOT_SAME_DEVICE


def _hold_or_make_folder(path: Path, named: Path, create: bool, mode: int) -> int:
    """Hold one folder on the way to another, making it first when it is missing and `create` is set.
    Takes its path, the folder being opened, whether to make it and its mode. Returns a descriptor the
    caller closes."""
    try:
        return _hold_folder(path, named)
    except FileNotFoundError:
        if not create:
            raise
    with contextlib.suppress(FileExistsError):
        os.mkdir(path, mode)
    return _hold_folder(path, named)


def _hold_folder(path: Path, named: Path, *, access: int = _HOLD_A_FOLDER,
                 sharing: int = _OTHERS_MAY_READ_AND_WRITE) -> int:
    """Hold one folder open. Takes its path, the path being opened, the access and what others may do
    with it while held. Returns a descriptor the caller closes. Raises `RedirectedPath` at a link or
    junction, and `NotADirectoryError` at anything else that is not a folder."""
    fd = _open(path, access, sharing, _OPEN_EXISTING, _ENTRY_ITSELF)
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


def _open(path: Path, access: int, sharing: int, disposition: int, flags: int) -> int:
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


def _look_at(path: Path) -> os.stat_result:
    """Read an entry's own attributes, those of the link or junction and not of what it points to.
    Takes its path. Returns them."""
    fd = _open(path, _FILE_READ_ATTRIBUTES, _OTHERS_MAY_DO_ANYTHING, _OPEN_EXISTING, _ENTRY_ITSELF)
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


def _delete_held(fd: int, path: Path) -> None:
    """Delete the entry a descriptor holds, opened with DELETE, and its name at once, even when it is
    marked read-only. Takes the descriptor and its path. Raises `OSError` when it was not deleted."""
    flags = wintypes.DWORD(_DELETE_NOW_EVEN_READ_ONLY)
    if not _SET_FILE_INFORMATION(msvcrt.get_osfhandle(fd), _FILE_DISPOSITION_INFO_EX,
                                 ctypes.byref(flags), ctypes.sizeof(flags)):
        _raise_last_error(path)


def _remove_on_one_volume(path: Path, volume: int) -> bool:
    """Delete an entry and everything under it on `volume`: a link or junction itself, never what it
    points to, and never a folder on another volume. Takes the entry and the volume. Returns True when
    the entry is gone."""
    try:
        found = _look_at(path)
    except FileNotFoundError:
        return True
    except OSError:
        return False
    if _is_a_link(found) or not stat.S_ISDIR(found.st_mode):
        return _delete_entry(path)
    if found.st_dev != volume:
        return False
    try:
        held = _hold_folder(path, path, access=_HOLD_A_FOLDER | _DELETE)
    except OSError:
        return False
    try:
        opened = os.fstat(held)
        if (opened.st_dev, opened.st_ino) != (found.st_dev, found.st_ino):
            return False
        complete = True
        for child in os.listdir(path):
            if not _remove_on_one_volume(path / child, volume):
                complete = False
        if complete:
            _delete_held(held, path)
        return complete
    except (OSError, RecursionError):
        return False
    finally:
        os.close(held)


def _delete_entry(path: Path) -> bool:
    """Delete a file, link or junction itself. Takes its path. Returns True when it is gone."""
    try:
        fd = _open(path, _DELETE | _FILE_READ_ATTRIBUTES, _OTHERS_MAY_DO_ANYTHING, _OPEN_EXISTING,
                   _ENTRY_ITSELF)
    except FileNotFoundError:
        return True
    except OSError:
        return False
    try:
        _delete_held(fd, path)
    except OSError:
        return False
    finally:
        os.close(fd)
    return True


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


def _raise_last_error(path: Path) -> None:
    """Raise the error the last system call on this thread left. Takes the path it was about. Raises
    the matching `OSError`."""
    failed = ctypes.get_last_error()
    raise OSError(None, ctypes.FormatError(failed), str(path), failed)
