#!/usr/bin/env python3
"""Write saw's own files in one step, or not at all, where they were named and nowhere else."""
from __future__ import annotations

import contextlib
import errno
import os
import secrets
import shutil
import stat
from pathlib import Path

from stayawake.utils import pathsafe

_CREATE = (os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0))
_READ = os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_CLOEXEC", 0)


@contextlib.contextmanager
def staged(where: Path, *, mode: int = 0o600, folder_mode: int = 0o777, binary: bool = False):
    """Stage a file's new contents beside it and put them in place when the block ends without an
    error. Takes the file, its mode, the mode of folders made on the way, and whether the handle takes
    bytes. Yields the handle. Raises `OSError` when the folder is reached through a link the writer
    does not trust or the file's name is a link."""
    where = Path(where)
    folder = pathsafe.open_folder(where.parent, create=True, mode=folder_mode)
    staging = f".saw-{secrets.token_hex(8)}{where.suffix}"
    try:
        if _is_link(where.name, folder):
            raise pathsafe.RedirectedPath(f"{where} is a link")
        fd = os.open(staging, _CREATE, 0o600, dir_fd=folder)
        try:
            with os.fdopen(fd, "wb" if binary else "w", **({} if binary else
                                                          {"encoding": "utf-8", "newline": ""})) as handle:
                yield handle
                handle.flush()
                os.fchmod(handle.fileno(), mode)
            os.rename(staging, where.name, src_dir_fd=folder, dst_dir_fd=folder)
            staging = None
        finally:
            if staging is not None:
                with contextlib.suppress(OSError):
                    os.unlink(staging, dir_fd=folder)
    finally:
        os.close(folder)


def replace(where: Path, text: str | bytes, *, mode: int = 0o600, folder_mode: int = 0o777) -> bool:
    """Write `text` to `where` in one step. Takes the file, its contents, its mode and the mode of
    folders made on the way. Returns True only when a read-back that never follows a link returns
    exactly what was written."""
    written = text.encode("utf-8") if isinstance(text, str) else text
    try:
        with staged(where, mode=mode, folder_mode=folder_mode, binary=True) as handle:
            handle.write(written)
    except OSError:
        return False
    return read_back(Path(where), len(written)) == written


def read_back(where: Path, limit: int) -> bytes | None:
    """Read a file saw wrote, through the same folders it was written through. Takes the file and
    how many bytes to read at most. Returns its bytes, or None when it is not a regular file there."""
    try:
        folder = pathsafe.open_folder(Path(where).parent)
    except OSError:
        return None
    try:
        fd = os.open(Path(where).name, _READ, dir_fd=folder)
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


def make_folder(where: Path, *, mode: int = 0o777, set_mode: bool = False) -> None:
    """Make a folder and every missing folder above it. Takes the folder, the mode of what is made,
    and whether to give the folder itself that mode when it already exists. Raises `OSError` when it
    is reached through a link the writer does not trust."""
    folder = pathsafe.open_folder(Path(where), create=True, mode=mode)
    try:
        if set_mode:
            os.fchmod(folder, mode)
    finally:
        os.close(folder)


def set_mode(where: Path, mode: int) -> None:
    """Give a file a mode, without following a link at its name or on the way to it. Takes the file
    and the mode. Raises `OSError` when it is reached through a link or is one."""
    folder = pathsafe.open_folder(Path(where).parent)
    try:
        fd = os.open(Path(where).name, _READ, dir_fd=folder)
        try:
            os.fchmod(fd, mode)
        finally:
            os.close(fd)
    finally:
        os.close(folder)


def new_folder(parent: Path, stem: str, *, mode: int = 0o700, tries: int = 1000) -> Path:
    """Make a folder no one else made, named `stem` or `stem-<n>`. Takes the parent, the name, the mode
    and how many names to try. Returns its path. Raises `OSError` when none could be made."""
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


def move_into(source: Path, folder: Path, name: str) -> None:
    """Move a file, link or folder, whole, into a folder under a new name. Takes the source, the folder
    and the name. Raises `OSError` when the folder is reached through a link the writer does not trust
    or the move could not be made; a copy that could not be made in full leaves the source in place."""
    destination = pathsafe.open_folder(Path(folder))
    try:
        try:
            os.rename(source, name, dst_dir_fd=destination)
            return
        except OSError as error:
            if error.errno != errno.EXDEV:
                raise
        _copy_into(Path(source), destination, name)
        if Path(source).is_dir() and not Path(source).is_symlink():
            shutil.rmtree(source)
        else:
            os.unlink(source)
    finally:
        os.close(destination)


def _copy_into(source: Path, folder: int, name: str) -> None:
    """Copy a file, link or folder into an open folder. Takes the source, the folder and the name."""
    found = os.lstat(source)
    if stat.S_ISLNK(found.st_mode):
        os.symlink(os.readlink(source), name, dir_fd=folder)
    elif stat.S_ISDIR(found.st_mode):
        os.mkdir(name, stat.S_IMODE(found.st_mode) | stat.S_IRWXU, dir_fd=folder)
        inner = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=folder)
        try:
            for entry in os.scandir(source):
                _copy_into(Path(entry.path), inner, entry.name)
            os.fchmod(inner, stat.S_IMODE(found.st_mode))
        finally:
            os.close(inner)
    elif stat.S_ISREG(found.st_mode):
        fd = os.open(name, _CREATE, 0o600, dir_fd=folder)
        with os.fdopen(fd, "wb") as out, open(source, "rb") as given:
            shutil.copyfileobj(given, out)
            os.fchmod(out.fileno(), stat.S_IMODE(found.st_mode))
    else:
        raise OSError(f"{source} is not a file, link or folder")


def _is_link(name: str, folder: int) -> bool:
    """Tell whether a name in an open folder is a link. Takes the name and the folder. Returns the
    answer."""
    try:
        return stat.S_ISLNK(os.stat(name, dir_fd=folder, follow_symlinks=False).st_mode)
    except FileNotFoundError:
        return False
