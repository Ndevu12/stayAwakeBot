#!/usr/bin/env python3
"""Write saw's own files in one step, or not at all, where they were named and nowhere else."""
from __future__ import annotations

import contextlib
import secrets
from pathlib import Path

from stayawake.utils import folders, pathsafe

AS_A_PLAIN_WRITE = None
REFUSE_A_LINK = "refuse"
FOLLOW_A_TRUSTED_LINK = "follow"
REPLACE_A_LINK = "replace"
_MOST_LINKS_AT_THE_NAME = 40


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
    with folder, folder.write_staged(name, staging, mode, binary) as handle:
        yield handle


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
    with folder:
        try:
            return folder.read_regular(name, limit)
        except OSError:
            return None


def make_folder(where: Path, *, mode: int | None = None) -> None:
    """Make a folder and every missing folder above it. Takes the folder and the mode to give it, or
    None to make it as `mkdir` would. Raises `OSError` when it is reached through a link the writer
    does not trust."""
    with folders.open_folder(Path(where), create=True) as folder:
        if mode is not None:
            folder.set_own_mode(mode)


def set_mode(where: Path, mode: int) -> None:
    """Give a file a mode, without following an untrusted link at its name or on the way to it. Takes
    the file and the mode. Raises `OSError` when it is reached through such a link, is not a regular
    file, or shares its contents with another name."""
    folder, name = _open_parent(Path(where))
    with folder:
        if not folder.set_mode_of(name, mode):
            raise pathsafe.RedirectedPath(f"{where} is not a file of its own")


def new_folder(parent: Path, stem: str, *, mode: int = 0o777, tries: int = 1000) -> Path:
    """Make a new folder named `stem`, or `stem-<n>` when that name is taken. Takes the parent, the
    name, the mode and how many names to try. Returns its path. Raises `OSError` when none could be
    made."""
    pathsafe.one_entry(stem)
    with folders.open_folder(Path(parent), create=True) as folder:
        for n in range(tries):
            name = stem if n == 0 else f"{stem}-{n}"
            try:
                folder.make_dir(name, mode)
                return Path(parent) / name
            except FileExistsError:
                continue
        raise FileExistsError(f"no free name for {stem} in {parent}")


def rename_in(folder: Path, old: str, new: str) -> None:
    """Rename an entry of a folder, reached without following a link the writer does not trust. Takes
    the folder, the entry's name and its new name. Raises `OSError` when it could not be renamed."""
    pathsafe.one_entry(old)
    pathsafe.one_entry(new)
    with folders.open_folder(Path(folder)) as opened:
        opened.rename_to(old, opened, new)


def move_into(source: Path, folder: Path, name: str) -> None:
    """Move a file, link or folder, whole, into a folder under a new name, reaching both without
    following a link the writer does not trust. Takes the source, the folder and the name. Raises
    `OSError` when either is reached through such a link or the move could not be made. A copy that
    could not be made in full leaves the source in place."""
    source = Path(source)
    pathsafe.one_entry(name)
    with folders.open_folder(source.parent) as origin, folders.open_folder(Path(folder)) as destination:
        try:
            origin.rename_to(source.name, destination, name)
            return
        except OSError as error:
            if not folders.is_another_disk(error):
                raise
        copied_a_folder = origin.copy_into(source.name, destination, name)
        origin.remove(source.name, copied_a_folder)


def rename_beside(folder: Path, name: str, new_name: str) -> None:
    """Rename an entry of a folder, a file, link or folder, to another name in the same folder, never
    replacing what is already there and never following a link the writer does not trust. Takes the
    folder, the entry and its new name. Raises `FileExistsError` when the new name is taken, and
    `OSError` when the folder is reached through such a link or the rename could not be made."""
    pathsafe.one_entry(name)
    pathsafe.one_entry(new_name)
    with folders.open_folder(Path(folder)) as opened:
        opened.rename_no_replace(name, new_name)


def _open_target(where: Path, at_a_link: str, *, create: bool = False) -> tuple[folders.Folder, str]:
    """Open the folder a file is written in and name the file there. Takes the file, what to do at a
    link at its name, and whether to make missing folders. Returns the open folder, which the caller
    closes, and the name. Raises `RedirectedPath` at a link at the name it may not use."""
    if at_a_link == FOLLOW_A_TRUSTED_LINK:
        return _open_parent(where, create=create)
    folder = folders.open_folder(where.parent, create=create)
    if at_a_link == REFUSE_A_LINK and folder.is_link(where.name):
        folder.close()
        raise pathsafe.RedirectedPath(f"{where} is a link")
    return folder, where.name


def _open_parent(where: Path, *, create: bool = False, mode: int = 0o777) -> tuple[folders.Folder, str]:
    """Open the folder a file is named in, following a link at the file's own name that the system
    trusts. Takes the file, whether to make missing folders on the way to it, and their mode. Returns
    the open folder, which the caller closes, and the file's name in it. Raises `RedirectedPath` at a
    link the system does not trust."""
    folder = folders.open_folder(where.parent, create=create, mode=mode)
    name = where.name
    try:
        for _ in range(_MOST_LINKS_AT_THE_NAME):
            link = folder.link_at(name)
            if link is None:
                return folder, name
            trusted, target = link
            if not trusted:
                raise pathsafe.RedirectedPath(f"{where} is a link")
            if target.name in ("", ".", ".."):
                raise pathsafe.RedirectedPath(f"{where} is a link to a folder")
            following = folder.open_under(target.parent)
            folder.close()
            folder, name = following, target.name
        raise pathsafe.RedirectedPath(f"{where} reaches elsewhere through too many links")
    except BaseException:
        folder.close()
        raise
