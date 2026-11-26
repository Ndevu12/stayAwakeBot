#!/usr/bin/env python3
"""Write what a replayed command changes into the folder with saw's own writers: its files, its
index entries, its refs, HEAD, the operation state it removed, the stash's log and what a fetch
wrote to `FETCH_HEAD`. Nothing runs in the folder. Every written file must hold the digest it was
judged with."""
from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from stayawake.lib.git.run import UNTRUSTED, stdout_bytes, stdout_bytes_fed
from stayawake.lib.git.write.branch import update_refs
from stayawake.lib.git.write.transfer import adopt_objects, missing_objects
from stayawake.lib.git.write.working_tree import write_files, written_digest
from stayawake.lib.git.index_copy import copy_index
from stayawake.utils import pathsafe, scratch

ABSENT = "absent"
FOLDER = "folder"
CHANGED_SINCE = "the open folder changed while the update was checked"
NOT_WRITTEN = "the update could not be written into the open folder"
LEFT_PART_WAY = ("the update could not be written into the open folder, and the folder may have changed; "
                 "check it with git status")
_REMOVABLE_STATE = frozenset({"MERGE_HEAD", "MERGE_MSG", "MERGE_MODE", "AUTO_MERGE", "CHERRY_PICK_HEAD",
                              "REVERT_HEAD", "REBASE_HEAD"})
_STASH_LOG = Path("logs") / "refs" / "stash"
_PSEUDO_REFS = frozenset({"ORIG_HEAD", "AUTO_MERGE"})
_LARGEST_STATE_FILE = 16 << 20


@dataclass(frozen=True)
class Written:
    """A replayed result to write: the folder's top and git directory, the holding git directory,
    the commit holding the files as written, each changed file as (path, mode, blob) with its state
    before and the digest it must hold, each changed index path with its entries before and after,
    the refs as (ref, new, old), HEAD before and after, the operation state removed, the stash's new
    log, the commit the folder was on, the commits `ORIG_HEAD` and the like name, and what a fetch
    wrote to `FETCH_HEAD`."""

    top: Path
    git_dir: Path
    holding: Path
    files_after: str
    files: tuple[tuple[str, str, str], ...]
    before: dict
    digests: dict
    index: tuple[tuple[str, tuple, tuple], ...]
    refs: tuple[tuple[str, str, str], ...]
    head_before: str
    head_after: str
    state_removed: tuple[str, ...]
    stash_log: "bytes | None"
    base: str
    pseudo_refs: tuple[tuple[str, str], ...] = ()
    fetch_head: "bytes | None" = None


def state_of(path: Path) -> str:
    """Describe what a path holds now: absent, a folder, or the digest of a file or link. Takes the
    path. Returns the description, or "" when it cannot be read."""
    if not os.path.lexists(path):
        return ABSENT
    if path.is_dir() and not path.is_symlink():
        return FOLDER
    return written_digest(path) or ""


def write(result: Written) -> str:
    """Write a replayed result into the folder. Takes the result. Returns "" when the folder holds
    it, else a sentence that also says when the folder may have changed."""
    top, git_dir = result.top, result.git_dir
    if _read_text(git_dir / "HEAD").strip() != result.head_before.strip():
        return CHANGED_SINCE
    if any(state_of(top / rel) != result.before.get(rel) for rel, _mode, _oid in result.files):
        return CHANGED_SINCE
    current = _index_entries(top)
    if current is None:
        return "the folder was not changed: its index could not be read"
    if any(current.get(os.fsencode(rel), ()) != _entries(before) for rel, before, _after in result.index):
        return CHANGED_SINCE
    tips = [result.files_after, *[new for _ref, new, _old in result.refs if new],
            *[commit for _name, commit in result.pseudo_refs if _is_object_id(commit)],
            *_named_in_fetch_head(result.fetch_head, _read_bytes(git_dir / "FETCH_HEAD"))]
    head = result.head_after.strip()
    if head and not head.startswith("ref: "):
        tips.append(head)
    why = adopt_objects(top, result.holding, tips, [result.base] if result.base else [])
    if why:
        return f"the update could not be copied into the open folder: {why}"
    blobs = sorted({oid.decode() for _rel, _before, after in result.index for _m, oid, _s in _entries(after)})
    if missing_objects(top, blobs) != []:
        return "the update could not be copied into the open folder"
    with _IndexLock(git_dir) as lock:
        if not lock.held or not lock.stage(top, _index_feed(result.index, len(result.base) or 40)):
            return NOT_WRITTEN
        saved = _Backups(top, [rel for rel, _mode, _oid in result.files])
        if not saved.taken:
            return NOT_WRITTEN
        try:
            paths = [os.fsencode(rel) for rel, _mode, _oid in result.files]
            if not (write_files(top, top, result.files_after, paths) and _hold_digests(top, result)):
                return NOT_WRITTEN if saved.put_back() else LEFT_PART_WAY
            if not update_refs(top, list(result.refs)):
                return CHANGED_SINCE if saved.put_back() else LEFT_PART_WAY
            if not lock.swap():
                update_refs(top, [(ref, old, new) for ref, new, old in result.refs])
                return NOT_WRITTEN if saved.put_back() else LEFT_PART_WAY
        finally:
            saved.release()
    if head and head != result.head_before.strip() and not _write_text(git_dir / "HEAD", head + "\n"):
        return LEFT_PART_WAY
    for name in result.state_removed:
        if name in _REMOVABLE_STATE:
            try:
                (git_dir / name).unlink()
            except FileNotFoundError:
                pass
            except OSError:
                return LEFT_PART_WAY
    if result.stash_log is not None and not _write_bytes(_common_dir(top) / _STASH_LOG, result.stash_log):
        return LEFT_PART_WAY
    for name, commit in result.pseudo_refs:
        if name in _PSEUDO_REFS and _is_object_id(commit) and not _write_text(git_dir / name, commit + "\n"):
            return LEFT_PART_WAY
    if result.fetch_head is not None and not _write_bytes(git_dir / "FETCH_HEAD", result.fetch_head):
        return LEFT_PART_WAY
    return ""


def _is_object_id(text: str) -> bool:
    """Tell whether text is a full object id. Takes the text. Returns the answer."""
    return len(text) in (40, 64) and all(char in "0123456789abcdef" for char in text)


def _named_in_fetch_head(fetch_head: "bytes | None", held: bytes) -> list[str]:
    """List the objects the lines of a new `FETCH_HEAD` name that the folder's own lacks. Takes its
    bytes, None when the command wrote none, and the folder's. Returns the object ids."""
    kept = set(held.splitlines())
    named = [line.split(b"\t", 1)[0].decode(errors="replace") for line in (fetch_head or b"").splitlines()
             if line not in kept]
    return [oid for oid in named if _is_object_id(oid)]


def _entries(listed) -> tuple:
    """Turn recorded index entries into the bytes form git lists. Takes (mode, blob, stage) entries,
    as text or bytes. Returns them as bytes."""
    return tuple(tuple(part if isinstance(part, bytes) else str(part).encode() for part in entry)
                 for entry in listed)


def _index_entries(top: Path) -> "dict[bytes, tuple] | None":
    """List the folder's index entries by path. Takes the folder. Returns them, or None."""
    listed = stdout_bytes(top, ["ls-files", "-s", "-z"], context=UNTRUSTED)
    if listed is None:
        return None
    entries: dict[bytes, list] = {}
    for record in listed.split(b"\0"):
        if record:
            info, _, path = record.partition(b"\t")
            entries.setdefault(path, []).append(tuple(info.split(b" ")))
    return {path: tuple(sorted(found, key=lambda entry: entry[2])) for path, found in entries.items()}


def _index_feed(index, width: int) -> bytes:
    """Write the `update-index --index-info` lines that set each changed path. Takes the changed
    index paths and the width of an object id. Returns the lines."""
    zero = b"0" * width
    lines = []
    for rel, _before, after in index:
        path = os.fsencode(rel)
        lines.append(b"0 %s\t%s\0" % (zero, path))
        lines += [b"%s %s %s\t%s\0" % (mode, oid, stage, path) for mode, oid, stage in _entries(after)]
    return b"".join(lines)


def _hold_digests(top: Path, result: Written) -> bool:
    """Tell whether each written file holds the digest it was judged with, and each removed one is
    gone. Takes the folder and the result. Returns the answer."""
    for rel, mode, _oid in result.files:
        now = state_of(top / rel)
        if not mode:
            if now not in (ABSENT, FOLDER):
                return False
        elif now != result.digests.get(rel):
            return False
    return True


class _IndexLock:
    """The folder's index lock, held while a new index is prepared on a private copy."""

    def __init__(self, git_dir: Path):
        self.index, self.lock = git_dir / "index", git_dir / "index.lock"
        self.private = scratch.new_file("the index a replayed command writes")
        self.held = False

    def __enter__(self) -> "_IndexLock":
        try:
            os.close(os.open(self.lock, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o644))
            self.held = True
        except OSError:
            self.held = False
        return self

    def stage(self, top: Path, feed: bytes) -> bool:
        """Copy the index and set the changed paths on the copy. Takes the folder and the lines.
        Returns whether the copy holds them."""
        try:
            if self.index.exists():
                copy_index(self.index, self.private)
            else:
                self.private.unlink(missing_ok=True)
        except OSError:
            return False
        return not feed or stdout_bytes_fed(top, ["update-index", "-z", "--index-info"], feed,
                                            env={**os.environ, "GIT_INDEX_FILE": str(self.private)},
                                            context=UNTRUSTED) is not None

    def swap(self) -> bool:
        """Put the prepared copy in place of the index. Returns whether it is in place."""
        try:
            copy_index(self.private, self.lock)
            os.replace(self.lock, self.index)
            self.held = False
            return True
        except OSError:
            return False

    def __exit__(self, *_exc) -> None:
        if self.held:
            try:
                os.unlink(self.lock)
            except OSError:
                pass
        scratch.release_path(self.private)


class _Backups:
    """Copies of what the folder holds at the paths a write changes, to put back if it fails."""

    def __init__(self, top: Path, paths: list[str]):
        self.top = top
        self.where = scratch.new_dir("what the folder held before an update")
        self.saved: dict[str, "tuple[str, bytes, int] | None"] = {}
        self.taken = True
        for rel in paths:
            path = top / rel
            try:
                if os.path.islink(path):
                    self.saved[rel] = ("link", os.fsencode(os.readlink(path)), 0)
                elif path.is_file():
                    data = pathsafe.read_regular_no_follow(path, os.lstat(path).st_size)
                    if data is None:
                        self.taken = False
                        return
                    self.saved[rel] = ("file", data, os.lstat(path).st_mode)
                elif not os.path.lexists(path):
                    self.saved[rel] = None
            except OSError:
                self.taken = False
                return

    def put_back(self) -> bool:
        """Write every saved path back to what it held. Returns whether each one was."""
        whole = True
        for rel, saved in self.saved.items():
            path = self.top / rel
            if self._holds(path, saved):
                continue
            try:
                if os.path.lexists(path) and not (path.is_dir() and not path.is_symlink()):
                    path.unlink()
                if saved is None:
                    continue
                path.parent.mkdir(parents=True, exist_ok=True)
                kind, data, mode = saved
                if kind == "link":
                    os.symlink(os.fsdecode(data), path)
                else:
                    path.write_bytes(data)
                    os.chmod(path, mode & 0o7777)
            except OSError:
                whole = False
        return whole

    @staticmethod
    def _holds(path: Path, saved: "tuple[str, bytes, int] | None") -> bool:
        """Tell whether a path still holds what was saved for it. Takes the path and the saved
        copy, None for nothing. Returns the answer."""
        if saved is None:
            return not os.path.lexists(path)
        kind, data, mode = saved
        try:
            if kind == "link":
                return os.path.islink(path) and os.fsencode(os.readlink(path)) == data
            found = os.lstat(path)
            return (not os.path.islink(path) and found.st_mode == mode
                    and pathsafe.read_regular_no_follow(path, found.st_size) == data)
        except OSError:
            return False

    def release(self) -> None:
        """Drop the saved copies."""
        scratch.release_path(self.where)


def _common_dir(top: Path) -> Path:
    """Find the folder's common git directory. Takes the folder. Returns it."""
    found = stdout_bytes(top, ["rev-parse", "--path-format=absolute", "--git-common-dir"], context=UNTRUSTED)
    return Path(os.fsdecode((found or b"").strip()) or top / ".git")


def _read_text(path: Path) -> str:
    """Read a small text file without following a link. Takes the path. Returns its text, or ""."""
    data = pathsafe.read_regular_no_follow(path, 4096)
    return data.decode(errors="replace") if data is not None else ""


def _read_bytes(path: Path) -> bytes:
    """Read a state file without following a link. Takes the path. Returns its bytes, or b""."""
    data = pathsafe.read_regular_no_follow(path, _LARGEST_STATE_FILE)
    return data if data is not None else b""


def _write_text(path: Path, text: str) -> bool:
    """Replace a file's text in one step. Takes the path and the text. Returns whether it was."""
    return _write_bytes(path, text.encode())


def _write_bytes(path: Path, data: bytes) -> bool:
    """Replace a file's bytes in one step. Takes the path and the bytes. Returns whether it was."""
    temporary = path.with_name(path.name + ".saw")
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        temporary.write_bytes(data)
        os.replace(temporary, path)
    except OSError:
        return False
    return True
