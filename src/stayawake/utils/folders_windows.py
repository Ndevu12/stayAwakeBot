#!/usr/bin/env python3
"""Hold folders open on Windows against anyone else renaming or deleting them, and change what is in
them, refusing any link or junction on the way."""
from __future__ import annotations

import contextlib
import errno
import msvcrt
import os
import shutil
import stat
from pathlib import Path

from stayawake.utils import pathsafe, winlock, winopen

_HOLD_A_FOLDER = (winopen.FILE_LIST_DIRECTORY | winopen.FILE_READ_ATTRIBUTES | winopen.READ_CONTROL
                  | winopen.SYNCHRONIZE)
_ERROR_NOT_SAME_DEVICE = 17


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
        return winopen.names_a_link(self._child(name))

    def link_at(self, name: str) -> tuple[bool, Path | None] | None:
        """Look at a link at a name in the folder, held against change while it is read. Takes the name.
        Returns None for anything but a link, else whether it is a symbolic link placed as
        `_placed_by_trusted` asks and, for such a link, where it points."""
        link = self._child(name)
        if not winopen.names_a_link(link):
            return None
        fd = winopen.open_entry(link, winopen.FILE_READ_DATA | winopen.FILE_READ_ATTRIBUTES | winopen.READ_CONTROL, winopen.FILE_SHARE_READ,
                   winopen.OPEN_EXISTING, winopen.ENTRY_ITSELF)
        try:
            held, seen = os.fstat(fd), os.lstat(link)
            if not (stat.S_ISLNK(seen.st_mode) and seen.st_reparse_tag == stat.IO_REPARSE_TAG_SYMLINK
                    and (held.st_dev, held.st_ino) == (seen.st_dev, seen.st_ino)
                    and _placed_by_trusted(fd, self._own)):
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
        fd = winopen.open_entry(staged, winopen.GENERIC_WRITE, 0, winopen.CREATE_NEW, winopen.FILE_FLAG_OPEN_REPARSE_POINT)
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
        fd = winopen.open_entry(self._child(name), winopen.GENERIC_READ, winopen.OTHERS_MAY_DO_ANYTHING, winopen.OPEN_EXISTING,
                   winopen.FILE_FLAG_OPEN_REPARSE_POINT)
        with os.fdopen(fd, "rb") as reading:
            found = os.fstat(reading.fileno())
            if winopen.is_a_link(found) or not stat.S_ISREG(found.st_mode):
                return None
            return reading.read(limit + 1)

    def set_own_mode(self, mode: int) -> None:
        """Do nothing: Windows gives folders no mode. Takes the mode. Returns nothing."""

    def set_mode_of(self, name: str, mode: int) -> bool:
        """Check that a file in the folder is a regular file itself, Windows giving files no mode. Takes
        its name and the mode. Returns whether it is one."""
        found = winopen.look_at(self._child(name))
        return not winopen.is_a_link(found) and stat.S_ISREG(found.st_mode)

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
            here, opened = winopen.look_at(Path(path)), os.fstat(self._own)
        except OSError:
            return False
        return (here.st_dev, here.st_ino) == (opened.st_dev, opened.st_ino)

    def settle_at(self, path: Path) -> bool:
        """Hold the folder at the name it was renamed to, against anyone else renaming or deleting it
        from there. Takes the path. Returns whether `path` names the folder held open and it is now
        held there."""
        try:
            fd = winopen.open_entry(Path(path), _HOLD_A_FOLDER | winopen.DELETE, winopen.OTHERS_MAY_READ_AND_WRITE, winopen.OPEN_EXISTING,
                       winopen.ENTRY_ITSELF)
        except OSError:
            return False
        found, opened = os.fstat(fd), os.fstat(self._own)
        if winopen.is_a_link(found) or (found.st_dev, found.st_ino) != (opened.st_dev, opened.st_ino):
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
        """Delete the empty folder held open where it was settled, and let go of it, which is when
        Windows takes its name away. Takes its path. Raises `OSError` when it was not settled there or
        was not deleted."""
        if self._settled is None:
            raise OSError(errno.EBUSY, "the folder is not held where it is deleted", str(path))
        settled, self._settled = self._settled, None
        try:
            winopen.delete_held(settled, Path(path))
        finally:
            for fd in (settled, self._own):
                self._held.remove(fd)
                os.close(fd)

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
        own = _hold_folder(parent.path / name, path, sharing=winopen.OTHERS_MAY_DO_ANYTHING)
    except BaseException:
        parent.close()
        raise
    return Folder(parent.path / name, [*parent._held, own])


def hold_entry(path: Path, *, folder: bool) -> int:
    """Open a folder or a regular file by its own name, reached without a link or junction on the way
    and refusing one at the name, without keeping anyone, saw included, from renaming or deleting it.
    Takes its path and whether it is a folder. Returns a descriptor the caller closes. Raises `OSError`
    when it is reached through a link, is one, or is not what was asked for."""
    path = Path(path)
    name = path.name
    pathsafe.one_entry(name)
    with open_folder(path.parent) as parent:
        fd = winopen.open_entry(parent.path / name, winopen.FILE_READ_ATTRIBUTES | winopen.SYNCHRONIZE,
                                winopen.OTHERS_MAY_DO_ANYTHING, winopen.OPEN_EXISTING,
                                winopen.ENTRY_ITSELF if folder else winopen.FILE_FLAG_OPEN_REPARSE_POINT)
    found = os.fstat(fd)
    if winopen.is_a_link(found) or stat.S_ISDIR(found.st_mode) != folder:
        os.close(fd)
        raise pathsafe.RedirectedPath(f"{path} is a link or not what was asked for")
    return fd


def owner_of(path: Path) -> str:
    """Name who owns an entry. Takes its path. Returns their sid. Raises `OSError` when it cannot be
    read."""
    owner = winlock.owner_sid(path)
    if not owner:
        raise OSError(errno.EACCES, "who owns it could not be read", str(path))
    return owner


def give_to(path: Path, owner: str | None) -> None:
    """Give an entry back to an account. Takes its path and the sid `owner_of` named. Raises `OSError`
    when it cannot be given."""
    if not isinstance(owner, str) or not owner:
        raise OSError(errno.EINVAL, "no account to give it to", str(path))
    current = winlock.owner_sid(path)
    if current and current.upper() == owner.upper():
        return
    if not winlock.give_to(path, owner):
        raise OSError(errno.EPERM, "it could not be given to that account", str(path))


def give_to_root(path: Path) -> None:
    """Give an entry to the Administrators group. Takes its path. Raises `OSError` when it cannot be
    given."""
    if not winlock.give_to_administrators(path):
        raise OSError(errno.EPERM, "it could not be given to an administrator", str(path))


def close_to_writes(path: Path) -> None:
    """Do nothing: Windows gives folders no mode, and the lock that stops writes is the denial set
    on the folder's permissions. Takes its path. Returns nothing."""


def open_to_its_owner(path: Path) -> None:
    """Do nothing: Windows gives folders no mode. Takes its path. Returns nothing."""


def reachable_by(path: Path, owner: str | None) -> bool:
    """Tell whether an account owns a folder and is not denied adding or removing anything in it.
    Takes its path and the sid `owner_of` named. Returns the answer."""
    if not isinstance(owner, str) or not owner:
        return False
    current = winlock.owner_sid(path)
    return bool(current) and current.upper() == owner.upper() and not winlock.write_denied(path, owner)


def is_another_disk(error: OSError) -> bool:
    """Tell whether an error is a rename refused across two volumes. Takes the error. Returns the
    answer."""
    return error.winerror == _ERROR_NOT_SAME_DEVICE


def _placed_by_trusted(link: int, holder: int) -> bool:
    """Tell whether only a trusted account could have put a link where it is: the link and the folder
    holding it belong to the system, the Administrators group or, unless saw runs elevated, the
    account it acts for, and nobody else can add, delete or re-own entries in that folder. Takes the
    link's descriptor and the folder's, both opened with READ_CONTROL. Returns the answer."""
    acting, elevated = winlock.current_sid(), winlock.administrator()
    holder_owner = winlock.held_owner_sid(msvcrt.get_osfhandle(holder))
    if not (winlock.trusted_owner(winlock.held_owner_sid(msvcrt.get_osfhandle(link)), acting, elevated)
            and winlock.trusted_owner(holder_owner, acting, elevated)):
        return False
    writers = {holder_owner, winlock.SYSTEM, winlock.ADMINISTRATORS, winlock.OWNER_RIGHTS}
    if not elevated and acting:
        writers.add(acting)
    return not winlock.others_may_write(msvcrt.get_osfhandle(holder), writers)


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
                 sharing: int = winopen.OTHERS_MAY_READ_AND_WRITE) -> int:
    """Hold one folder open. Takes its path, the path being opened, the access and what others may do
    with it while held. Returns a descriptor the caller closes. Raises `RedirectedPath` at a link or
    junction, and `NotADirectoryError` at anything else that is not a folder."""
    fd = winopen.open_entry(path, access, sharing, winopen.OPEN_EXISTING, winopen.ENTRY_ITSELF)
    try:
        found = os.fstat(fd)
        if winopen.is_a_link(found):
            raise pathsafe.RedirectedPath(f"{named} reaches elsewhere through a link at {path}")
        if not stat.S_ISDIR(found.st_mode):
            raise NotADirectoryError(errno.ENOTDIR, os.strerror(errno.ENOTDIR), str(path))
    except BaseException:
        os.close(fd)
        raise
    return fd


def _remove_on_one_volume(path: Path, volume: int) -> bool:
    """Delete an entry and everything under it on `volume`: a link or junction itself, never what it
    points to, and never a folder on another volume. Takes the entry and the volume. Returns True when
    the entry is gone."""
    try:
        found = winopen.look_at(path)
    except FileNotFoundError:
        return True
    except OSError:
        return False
    if winopen.is_a_link(found) or not stat.S_ISDIR(found.st_mode):
        return _delete_entry(path)
    if found.st_dev != volume:
        return False
    try:
        held = _hold_folder(path, path, access=_HOLD_A_FOLDER | winopen.DELETE)
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
            winopen.delete_held(held, path)
        return complete
    except (OSError, RecursionError):
        return False
    finally:
        os.close(held)


def _delete_entry(path: Path) -> bool:
    """Delete a file, link or junction itself. Takes its path. Returns True when it is gone."""
    try:
        fd = winopen.open_entry(path, winopen.DELETE | winopen.FILE_READ_ATTRIBUTES, winopen.OTHERS_MAY_DO_ANYTHING, winopen.OPEN_EXISTING,
                   winopen.ENTRY_ITSELF)
    except FileNotFoundError:
        return True
    except OSError:
        return False
    try:
        winopen.delete_held(fd, path)
    except OSError:
        return False
    finally:
        os.close(fd)
    return True


def _copy(source: Path, copy: Path) -> bool:
    """Copy a file or folder, whole, keeping its times. Takes the source and the copy's path. Returns
    whether it was a folder. Raises `OSError` at a link or junction in it."""
    found = winopen.look_at(source)
    if winopen.is_a_link(found):
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
