#!/usr/bin/env python3
"""Hold folders open by descriptor on macOS and Linux, and change what is in them without being
redirected through a link the writer does not trust."""
from __future__ import annotations

import contextlib
import ctypes
import errno
import os
import shutil
import stat
import sys
from pathlib import Path

from stayawake.utils import operator, pathsafe
from stayawake.utils.pathsafe import RedirectedPath, directory_flag, no_follow_flag

_FOLDER_FLAGS = os.O_RDONLY | directory_flag() | getattr(os, "O_CLOEXEC", 0)
_SEARCH_ONLY = getattr(os, "O_SEARCH", 0) or getattr(os, "O_PATH", 0)
_MAX_LINKS = 40
_CREATE = (os.O_WRONLY | os.O_CREAT | os.O_EXCL | pathsafe.no_follow_flag()
           | getattr(os, "O_CLOEXEC", 0))
_READ = (os.O_RDONLY | pathsafe.no_follow_flag() | getattr(os, "O_NONBLOCK", 0)
         | getattr(os, "O_CLOEXEC", 0))
_RENAME_NOREPLACE = 1          # renameat2(2), Linux
_RENAME_EXCL = 0x00000004       # renameatx_np(2), macOS


class Folder:
    """A folder held open by its descriptor."""

    def __init__(self, fd: int):
        self.fd = fd

    def __enter__(self) -> Folder:
        return self

    def __exit__(self, *_exc) -> None:
        self.close()

    def close(self) -> None:
        """Let go of the folder. Returns nothing."""
        os.close(self.fd)

    def is_link(self, name: str) -> bool:
        """Tell whether a name in the folder is a link. Takes the name. Returns the answer."""
        return _is_link(name, self.fd)

    def link_at(self, name: str) -> tuple[bool, Path | None] | None:
        """Look at a link at a name in the folder. Takes the name. Returns None for anything but a link,
        else whether root or the user writing placed it in a folder nobody else can write in and, for
        such a link, where it points."""
        try:
            found = os.stat(name, dir_fd=self.fd, follow_symlinks=False)
        except FileNotFoundError:
            return None
        if not stat.S_ISLNK(found.st_mode):
            return None
        if not _placed_by_trusted(found, os.fstat(self.fd), trusted_link_owners()):
            return False, None
        return True, Path(os.readlink(name, dir_fd=self.fd))

    def open_under(self, path: Path) -> Folder:
        """Open a folder named from this one, by the same rule as `open_folder`. Takes its path,
        relative to this folder or absolute. Returns it held open."""
        return Folder(_open_descriptor(path, start=self.fd))

    @contextlib.contextmanager
    def write_staged(self, name: str, staging: str, mode: int | None, binary: bool):
        """Write a file's new contents under a staging name and rename them over the file when the block
        ends without an error. Takes the file's name, the staging name, its mode (None: the mode the
        file has, or the umask's for a new one) and whether the handle takes bytes. Yields the handle."""
        kept = _mode_of(name, self.fd) if mode is None else mode
        fd = os.open(staging, _CREATE, 0o666 if mode is None else 0o600, dir_fd=self.fd)
        try:
            with os.fdopen(fd, "wb" if binary else "w", **({} if binary else
                                                          {"encoding": "utf-8", "newline": ""})) as handle:
                yield handle
                handle.flush()
                if kept is not None:
                    os.fchmod(handle.fileno(), kept)
            os.rename(staging, name, src_dir_fd=self.fd, dst_dir_fd=self.fd)
            staging = None
        finally:
            if staging is not None:
                with contextlib.suppress(OSError):
                    os.unlink(staging, dir_fd=self.fd)

    def read_regular(self, name: str, limit: int) -> bytes | None:
        """Read a regular file in the folder without following a link at its name. Takes the name and
        how many bytes to read at most. Returns up to `limit` + 1 bytes, or None for anything but a
        regular file. Raises `OSError` when it cannot be opened or read."""
        fd = os.open(name, _READ, dir_fd=self.fd)
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
        finally:
            os.close(fd)

    def set_own_mode(self, mode: int) -> None:
        """Give the folder a mode. Takes the mode. Returns nothing."""
        os.fchmod(self.fd, mode)

    def set_mode_of(self, name: str, mode: int) -> bool:
        """Give a file in the folder a mode when it is a regular file that shares its contents with no
        other name. Takes its name and the mode. Returns whether it was given."""
        fd = os.open(name, _READ, dir_fd=self.fd)
        try:
            found = os.fstat(fd)
            if not stat.S_ISREG(found.st_mode) or found.st_nlink != 1:
                return False
            os.fchmod(fd, mode)
            return True
        finally:
            os.close(fd)

    def make_dir(self, name: str, mode: int) -> None:
        """Make a folder in this one. Takes its name and mode. Raises `FileExistsError` when the name is
        taken."""
        os.mkdir(name, mode, dir_fd=self.fd)

    def rename_to(self, entry: str, folder: Folder, name: str) -> None:
        """Move an entry of this folder into another held folder under a name, replacing what is there.
        Takes the entry, the folder and the name. Raises `OSError` when it was not moved."""
        os.rename(entry, name, src_dir_fd=self.fd, dst_dir_fd=folder.fd)

    def rename_no_replace(self, name: str, new_name: str) -> None:
        """Rename an entry of this folder, never replacing what has the new name. Takes the entry and
        its new name. Raises `FileExistsError` when the new name is taken."""
        if _kernel_rename_no_replace(self.fd, name, new_name):
            return
        try:
            os.lstat(new_name, dir_fd=self.fd)
        except FileNotFoundError:
            os.rename(name, new_name, src_dir_fd=self.fd, dst_dir_fd=self.fd)
            return
        raise FileExistsError(errno.EEXIST, os.strerror(errno.EEXIST), new_name)

    def copy_into(self, entry: str, folder: Folder, name: str) -> bool:
        """Copy an entry of this folder, whole, into another held folder under a name, keeping its mode
        and times. Takes the entry, the folder and the name. Returns whether it was a folder."""
        return _copy_into(self.fd, entry, folder.fd, name)

    def remove(self, entry: str, is_folder: bool) -> None:
        """Delete an entry of this folder, and everything under it when it is a folder. Takes the entry
        and whether it is a folder. Raises `OSError` when it was not deleted."""
        if is_folder:
            shutil.rmtree(entry, dir_fd=self.fd)
        else:
            os.unlink(entry, dir_fd=self.fd)

    def owned_by(self) -> str:
        """Grade who owns the folder. Returns `self` for the account saw acts for, `root`, or
        `other`."""
        owner = os.fstat(self.fd).st_uid
        if owner == operator.acting_uid():
            return "self"
        return "root" if owner == 0 else "other"

    def device(self) -> int:
        """Name the device the folder is on. Returns it."""
        return os.fstat(self.fd).st_dev

    def is_at(self, path: Path) -> bool:
        """Tell whether `path` names the folder held open, whose inode cannot be given to anything
        else. Takes the path. Returns the answer."""
        try:
            here, opened = path.lstat(), os.fstat(self.fd)
        except OSError:
            return False
        return (here.st_dev, here.st_ino) == (opened.st_dev, opened.st_ino)

    def settle_at(self, path: Path) -> bool:
        """Tell whether the folder held open was renamed to `path`. Takes the path. Returns the
        answer."""
        return self.is_at(path)

    def make_writable(self) -> None:
        """Let the folder's owner add and remove entries in it, where that can be given. Returns
        nothing."""
        try:
            os.fchmod(self.fd, stat.S_IRWXU)
        except OSError:
            pass

    def names(self) -> list[str]:
        """List the folder's entries. Returns their names."""
        with os.scandir(self.fd) as entries:
            return [entry.name for entry in entries]

    def remove_on_one_device(self, name: str, device: int, mounts: frozenset[str], where: str) -> bool:
        """Delete an entry of the folder and everything under it on `device`, never following a link
        and never entering a mount point or another device. Takes the entry, the device, the mount
        points and the folder's path. Returns True when the entry is gone."""
        return _remove_on_one_device(self.fd, name, device, mounts, where)

    def remove_at(self, path: Path) -> None:
        """Delete the empty folder held open, named `path`. Takes the path. Raises `OSError` when it
        was not deleted."""
        os.rmdir(path)


def open_folder(folder: Path, *, create: bool = False, mode: int = 0o777) -> Folder:
    """Open a folder for writing in, one step at a time, without being redirected. Takes the folder,
    whether to make the missing parts and their mode. Returns it held open. Raises `RedirectedPath` at
    a link the writer does not trust, and `OSError` when a part is missing or is not a folder."""
    return Folder(_open_descriptor(Path(folder), create=create, mode=mode))


def hold(path: Path) -> Folder:
    """Hold a folder open by its own name, refusing a link there. Takes its path. Returns it held
    open. Raises `OSError` when it is a link or not a folder."""
    return Folder(os.open(path, os.O_RDONLY | pathsafe.directory_flag() | pathsafe.no_follow_flag()))


def hold_entry(path: Path, *, folder: bool) -> int:
    """Open a folder or a regular file by its own name, refusing a link there, without keeping anyone
    from renaming or deleting it. Takes its path and whether it is a folder. Returns a descriptor the
    caller closes. Raises `OSError` when it cannot be opened as one."""
    if folder:
        flags = os.O_RDONLY | pathsafe.directory_flag() | pathsafe.no_follow_flag()
    else:
        flags = os.O_RDONLY | pathsafe.no_follow_flag() | getattr(os, "O_NONBLOCK", 0)
    return os.open(path, flags)


def owner_of(path: Path) -> int:
    """Name who owns an entry itself, never what a link at its name points to. Takes its path. Returns
    their account id. Raises `OSError` when it cannot be read."""
    return path.lstat().st_uid


def give_to(path: Path, owner: int) -> None:
    """Give an entry itself back to an account, never what a link at its name points to. Takes its
    path and the account `owner_of` named. Raises `OSError` when it cannot be given."""
    os.chown(path, owner, -1, follow_symlinks=False)


def give_to_root(path: Path) -> None:
    """Give an entry itself to the machine's administrator, never what a link at its name points to.
    Takes its path. Raises `OSError` when it cannot be given."""
    os.chown(path, 0, 0, follow_symlinks=False)


def close_to_writes(path: Path) -> None:
    """Let no one, the owner included, add or remove anything in a folder, never changing what a link
    at its name points to. Takes its path. Raises `OSError` when it cannot be changed."""
    os.chmod(path, 0o555, follow_symlinks=False)


def open_to_its_owner(path: Path) -> None:
    """Let a folder's owner, and only its owner, add and remove entries in it again, never changing
    what a link at its name points to. Takes its path. Raises `OSError` when it cannot be changed."""
    os.chmod(path, 0o700, follow_symlinks=False)


def reachable_by(path: Path, owner: int) -> bool:
    """Tell whether an account can open a folder and remove what is in it, reading the entry itself.
    Takes its path and the account `owner_of` named. Returns the answer."""
    try:
        st = path.lstat()
    except OSError:
        return False
    return st.st_uid == owner and bool(st.st_mode & stat.S_IWUSR)


def is_another_disk(error: OSError) -> bool:
    """Tell whether an error is a rename refused across two disks. Takes the error. Returns the
    answer."""
    return error.errno == errno.EXDEV


def trusted_link_owners() -> set[int]:
    """Name who may own a link a write follows: root, and the user writing. Returns their ids."""
    geteuid = getattr(os, "geteuid", None)
    return {0} if geteuid is None else {0, geteuid()}


def _placed_by_trusted(link: os.stat_result, holder: os.stat_result, owners: set[int]) -> bool:
    """Tell whether only a trusted account could have put a link where it is: the link and the folder
    holding it belong to a trusted owner, and nobody else can write in that folder, its group included
    while root is the only trusted owner. Takes the link, the folder holding it and the trusted owners.
    Returns the answer."""
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
        return os.open(name, _SEARCH_ONLY | directory_flag() | getattr(os, "O_CLOEXEC", 0)
                       | extra, dir_fd=dir_fd)


def _enter(name: str, holder: int, seen: os.stat_result) -> int:
    """Open a folder inside an open folder without following a link. Takes its name, the folder and
    what a look at the name found. Returns the descriptor. Raises `RedirectedPath` when what opened is
    not the folder that was looked at."""
    entered = _open_dir(name, holder, no_follow_flag())
    found = os.fstat(entered)
    if not stat.S_ISDIR(found.st_mode) or (found.st_dev, found.st_ino) != (seen.st_dev, seen.st_ino):
        os.close(entered)
        raise RedirectedPath(f"{name} changed while it was opened")
    return entered


def _open_descriptor(folder: Path, *, create: bool = False, mode: int = 0o777, start: int | None = None) -> int:
    """Open a folder for writing in, one step at a time, without being redirected: follow a link that
    root or the user writing placed in a folder nobody else can write in, resolve `..` where the walk
    is, and make nothing inside a link's target. Takes the folder, whether to make the missing parts,
    their mode, and an open folder a relative path starts from. Returns an open descriptor the caller
    closes. Raises `RedirectedPath` at any other link, and `OSError` when a part is missing or is not
    a folder."""
    folder = Path(folder)
    if start is not None and not folder.is_absolute():
        parts, fd = [(p, False) for p in folder.parts], os.dup(start)
    else:
        absolute = folder if folder.is_absolute() else Path(os.getcwd()) / folder
        parts, fd = [(p, False) for p in absolute.parts[1:]], _open_dir("/", None, 0)
    owners = trusted_link_owners()
    links = 0
    try:
        while parts:
            part, inside_a_link = parts.pop(0)
            if part in ("", "."):
                continue
            try:
                found = os.stat(part, dir_fd=fd, follow_symlinks=False)
            except FileNotFoundError:
                if not create or inside_a_link or part == "..":
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
                parts[:0] = [(p, True) for p in Path(target).parts[1 if os.path.isabs(target) else 0:]]
                continue
            following = _enter(part, fd, found)
            os.close(fd)
            fd = following
        return fd
    except BaseException:
        os.close(fd)
        raise


def _kernel_rename_no_replace(folder: int, name: str, new_name: str) -> bool:
    """Ask the kernel to rename an entry of an open folder without replacing the new name. Takes the
    folder, the entry and the new name. Returns True once renamed, False where this kernel or
    filesystem offers no such rename. Raises `OSError` when it refused."""
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
        given = os.open(entry, os.O_RDONLY | pathsafe.directory_flag() | pathsafe.no_follow_flag(),
                        dir_fd=origin)
        try:
            os.mkdir(name, stat.S_IMODE(found.st_mode) | stat.S_IRWXU, dir_fd=folder)
            inner = os.open(name, os.O_RDONLY | pathsafe.directory_flag() | pathsafe.no_follow_flag(),
                            dir_fd=folder)
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


def _is_link(name: str, folder: int) -> bool:
    """Tell whether a name in an open folder is a link. Takes the name and the folder. Returns the
    answer."""
    try:
        return stat.S_ISLNK(os.stat(name, dir_fd=folder, follow_symlinks=False).st_mode)
    except FileNotFoundError:
        return False


def _mode_of(name: str, folder: int) -> int | None:
    """Name the mode of a regular file in an open folder. Takes its name and the folder. Returns the
    mode, or None when there is no regular file of that name."""
    try:
        found = os.stat(name, dir_fd=folder, follow_symlinks=False)
    except FileNotFoundError:
        return None
    return stat.S_IMODE(found.st_mode) if stat.S_ISREG(found.st_mode) else None


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
        inner = os.open(name, os.O_RDONLY | pathsafe.directory_flag() | pathsafe.no_follow_flag(),
                        dir_fd=folder)
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
