#!/usr/bin/env python3
"""Write saw's own files in one step, or not at all, where they were named and nowhere else."""
from __future__ import annotations

import contextlib
import ctypes
import errno
import os
import secrets
import shutil
import stat
import sys
from pathlib import Path

from stayawake.utils import pathsafe

AS_A_PLAIN_WRITE = None
REFUSE_A_LINK = "refuse"
FOLLOW_A_TRUSTED_LINK = "follow"
REPLACE_A_LINK = "replace"
_CREATE = (os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0))
_READ = os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_CLOEXEC", 0)


@contextlib.contextmanager
def staged(where: Path, *, mode: int | None = 0o600, binary: bool = False,
           at_a_link: str = REFUSE_A_LINK):
    """Stage a file's new contents beside it and put them in place when the block ends without an
    error. Takes the file, its mode (`AS_A_PLAIN_WRITE`: the mode the file has, or the umask's for a
    new one), whether the handle takes bytes, and what to do when the file's name is a link: refuse,
    write through it when the writer trusts it, or replace it. Yields the handle. Raises `OSError`
    when a folder on the way, or a link at the name it may not replace, is one the writer does not
    trust."""
    folder, name = _open_target(Path(where), at_a_link, create=True)
    staging = f".saw-{secrets.token_hex(8)}{Path(name).suffix}"
    try:
        kept = _mode_of(name, folder) if mode is AS_A_PLAIN_WRITE else mode
        fd = os.open(staging, _CREATE, 0o666 if mode is AS_A_PLAIN_WRITE else 0o600, dir_fd=folder)
        try:
            with os.fdopen(fd, "wb" if binary else "w", **({} if binary else
                                                          {"encoding": "utf-8", "newline": ""})) as handle:
                yield handle
                handle.flush()
                if kept is not None:
                    os.fchmod(handle.fileno(), kept)
            os.rename(staging, name, src_dir_fd=folder, dst_dir_fd=folder)
            staging = None
        finally:
            if staging is not None:
                with contextlib.suppress(OSError):
                    os.unlink(staging, dir_fd=folder)
    finally:
        os.close(folder)


def replace(where: Path, text: str | bytes, *, mode: int | None = 0o600,
            at_a_link: str = REFUSE_A_LINK) -> bool:
    """Write `text` to `where` in one step. Takes the file, its contents, its mode and what to do at a
    link at its name, as for `staged`. Returns True only when a read-back that never follows an
    untrusted link returns exactly what was written."""
    written = text.encode("utf-8") if isinstance(text, str) else text
    try:
        with staged(where, mode=mode, binary=True, at_a_link=at_a_link) as handle:
            handle.write(written)
    except OSError:
        return False
    return read_back(Path(where), len(written), at_a_link=at_a_link) == written


def read_back(where: Path, limit: int, *, at_a_link: str = REFUSE_A_LINK) -> bytes | None:
    """Read a file saw wrote, through the same folders it was written through. Takes the file, how
    many bytes to read at most, and how its name was written. Returns its bytes, or None when it is
    not a regular file there."""
    try:
        folder, name = _open_target(Path(where), at_a_link)
    except OSError:
        return None
    try:
        fd = os.open(name, _READ, dir_fd=folder)
    except OSError:
        os.close(folder)
        return None
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            return None
        chunks, left = [], limit + 1
        while left > 0:
            chunk = os.read(fd, min(left, 1 << 20))
            if not chunk:
                break
            chunks.append(chunk)
            left -= len(chunk)
        return b"".join(chunks)
    except OSError:
        return None
    finally:
        os.close(fd)
        os.close(folder)


def make_folder(where: Path, *, mode: int | None = None) -> None:
    """Make a folder and every missing folder above it. Takes the folder and the mode to give it, or
    None to make it as `mkdir` would. Raises `OSError` when it is reached through a link the writer
    does not trust."""
    folder = pathsafe.open_folder(Path(where), create=True)
    try:
        if mode is not None:
            os.fchmod(folder, mode)
    finally:
        os.close(folder)


def set_mode(where: Path, mode: int) -> None:
    """Give a file a mode, without following an untrusted link at its name or on the way to it. Takes
    the file and the mode. Raises `OSError` when it is reached through such a link, is not a regular
    file, or shares its contents with another name."""
    folder, name = pathsafe.open_parent(Path(where))
    try:
        fd = os.open(name, _READ, dir_fd=folder)
        try:
            found = os.fstat(fd)
            if not stat.S_ISREG(found.st_mode) or found.st_nlink != 1:
                raise pathsafe.RedirectedPath(f"{where} is not a file of its own")
            os.fchmod(fd, mode)
        finally:
            os.close(fd)
    finally:
        os.close(folder)


def new_folder(parent: Path, stem: str, *, mode: int = 0o777, tries: int = 1000) -> Path:
    """Make a folder no one else made, named `stem` or `stem-<n>`. Takes the parent, the name, the mode
    and how many names to try. Returns its path. Raises `OSError` when none could be made."""
    _one_entry(stem)
    folder = pathsafe.open_folder(Path(parent), create=True)
    try:
        for n in range(tries):
            name = stem if n == 0 else f"{stem}-{n}"
            try:
                os.mkdir(name, mode, dir_fd=folder)
                return Path(parent) / name
            except FileExistsError:
                continue
        raise FileExistsError(f"no free name for {stem} in {parent}")
    finally:
        os.close(folder)


def rename_in(folder: Path, old: str, new: str) -> None:
    """Rename an entry of a folder, reached without following a link the writer does not trust. Takes
    the folder, the entry's name and its new name. Raises `OSError` when it could not be renamed."""
    _one_entry(old)
    _one_entry(new)
    opened = pathsafe.open_folder(Path(folder))
    try:
        os.rename(old, new, src_dir_fd=opened, dst_dir_fd=opened)
    finally:
        os.close(opened)


def move_into(source: Path, folder: Path, name: str) -> None:
    """Move a file, link or folder, whole, into a folder under a new name; both are reached without
    following a link the writer does not trust. Takes the source, the folder and the name. Raises
    `OSError` when either is reached through such a link or the move could not be made; a copy that
    could not be made in full leaves the source in place."""
    source = Path(source)
    _one_entry(name)
    origin = pathsafe.open_folder(source.parent)
    try:
        destination = pathsafe.open_folder(Path(folder))
        try:
            try:
                os.rename(source.name, name, src_dir_fd=origin, dst_dir_fd=destination)
                return
            except OSError as error:
                if error.errno != errno.EXDEV:
                    raise
            if _copy_into(origin, source.name, destination, name):
                shutil.rmtree(source.name, dir_fd=origin)
            else:
                os.unlink(source.name, dir_fd=origin)
        finally:
            os.close(destination)
    finally:
        os.close(origin)


_RENAME_NOREPLACE = 1          # renameat2(2), Linux
_RENAME_EXCL = 0x00000004       # renameatx_np(2), macOS


def rename_beside(folder: Path, name: str, new_name: str) -> None:
    """Rename an entry of a folder, a file, link or folder, to another name in the same folder, never
    replacing what is already there and never following a link the writer does not trust. Takes the
    folder, the entry and its new name. Raises `FileExistsError` when the new name is taken, and
    `OSError` when the folder is reached through such a link or the rename could not be made."""
    _one_entry(name)
    _one_entry(new_name)
    opened = pathsafe.open_folder(Path(folder))
    try:
        if _kernel_rename_no_replace(opened, name, new_name):
            return
        try:
            os.lstat(new_name, dir_fd=opened)
        except FileNotFoundError:
            os.rename(name, new_name, src_dir_fd=opened, dst_dir_fd=opened)
            return
        raise FileExistsError(errno.EEXIST, os.strerror(errno.EEXIST), new_name)
    finally:
        os.close(opened)


def _kernel_rename_no_replace(folder: int, name: str, new_name: str) -> bool:
    """Ask the kernel to rename an entry of an open folder without replacing the new name. Takes the
    folder, the entry and the new name. Returns True when it was renamed, and False when this kernel or
    filesystem has no such rename; raises `OSError` when it refused."""
    try:
        libc = ctypes.CDLL(None, use_errno=True)
        call = libc.renameat2 if sys.platform.startswith("linux") else (
            libc.renameatx_np if sys.platform == "darwin" else None)
    except (OSError, AttributeError):
        return False
    if call is None:
        return False
    call.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
    flag = _RENAME_NOREPLACE if sys.platform.startswith("linux") else _RENAME_EXCL
    if call(folder, os.fsencode(name), folder, os.fsencode(new_name), flag) == 0:
        return True
    failed = ctypes.get_errno()
    if failed in (errno.EINVAL, errno.ENOSYS, errno.ENOTSUP, errno.EOPNOTSUPP):
        return False
    raise OSError(failed, os.strerror(failed), new_name)


def _copy_into(origin: int, entry: str, folder: int, name: str) -> bool:
    """Copy an entry of an open folder, a file, link or folder, into another open folder, keeping its
    mode and times. Takes the source folder, the entry, the destination folder and the new name.
    Returns whether it was a folder."""
    found = os.stat(entry, dir_fd=origin, follow_symlinks=False)
    times = (found.st_atime_ns, found.st_mtime_ns)
    if stat.S_ISLNK(found.st_mode):
        os.symlink(os.readlink(entry, dir_fd=origin), name, dir_fd=folder)
        return False
    if stat.S_ISDIR(found.st_mode):
        given = os.open(entry, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=origin)
        try:
            os.mkdir(name, stat.S_IMODE(found.st_mode) | stat.S_IRWXU, dir_fd=folder)
            inner = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=folder)
            try:
                for child in os.listdir(given):
                    _copy_into(given, child, inner, child)
                os.fchmod(inner, stat.S_IMODE(found.st_mode))
                os.utime(inner, ns=times)
            finally:
                os.close(inner)
        finally:
            os.close(given)
        return True
    if stat.S_ISREG(found.st_mode):
        given = os.open(entry, _READ, dir_fd=origin)
        with os.fdopen(given, "rb") as reading:
            if not stat.S_ISREG(os.fstat(reading.fileno()).st_mode):
                raise OSError(f"{entry} is not a file")
            fd = os.open(name, _CREATE, 0o600, dir_fd=folder)
            with os.fdopen(fd, "wb") as out:
                shutil.copyfileobj(reading, out)
                out.flush()
                os.fchmod(out.fileno(), stat.S_IMODE(found.st_mode))
                os.utime(out.fileno(), ns=times)
        return False
    raise OSError(f"{entry} is not a file, link or folder")


def _open_target(where: Path, at_a_link: str, *, create: bool = False) -> tuple[int, str]:
    """Open the folder a file is written in and name the file there. Takes the file, what to do at a
    link at its name, and whether to make missing folders. Returns the open folder, which the caller
    closes, and the name. Raises `RedirectedPath` at a link at the name it may not use."""
    if at_a_link == FOLLOW_A_TRUSTED_LINK:
        return pathsafe.open_parent(where, create=create)
    folder = pathsafe.open_folder(where.parent, create=create)
    if at_a_link == REFUSE_A_LINK and _is_link(where.name, folder):
        os.close(folder)
        raise pathsafe.RedirectedPath(f"{where} is a link")
    return folder, where.name


def _is_link(name: str, folder: int) -> bool:
    """Tell whether a name in an open folder is a link. Takes the name and the folder. Returns the
    answer."""
    try:
        return stat.S_ISLNK(os.stat(name, dir_fd=folder, follow_symlinks=False).st_mode)
    except FileNotFoundError:
        return False


def _one_entry(name: str) -> None:
    """Refuse a name that is not exactly one entry of a folder. Takes the name. Raises
    `RedirectedPath` for an empty name, `.`, `..`, or one with a separator in it."""
    if name in ("", ".", "..") or os.sep in name or (os.altsep and os.altsep in name):
        raise pathsafe.RedirectedPath(f"{name!r} is not one entry of a folder")


def _mode_of(name: str, folder: int) -> int | None:
    """Name the mode of a regular file in an open folder. Takes its name and the folder. Returns the
    mode, or None when there is no regular file of that name."""
    try:
        found = os.stat(name, dir_fd=folder, follow_symlinks=False)
    except FileNotFoundError:
        return None
    return stat.S_IMODE(found.st_mode) if stat.S_ISREG(found.st_mode) else None
