#!/usr/bin/env python3
"""An operator's checkout read and moved without `status` or `reset --hard`. The index and HEAD are
read as listings, the working tree's bytes are hashed in Python as git hashes a blob, and a
checkout follows its branch by writing the changed paths' raw bytes from a saw-owned repository and
swapping in an index prepared on a private copy."""
from __future__ import annotations

import hashlib
import os
import shutil
import stat
from pathlib import Path

from stayawake.lib.git import operator_config
from stayawake.lib.git.borrowed import borrow
from stayawake.lib.git.run import SAW_OWNED, UNTRUSTED, stdout, stdout_bytes, stdout_bytes_fed
from stayawake.lib.git.write.checkouts import Checkout
from stayawake.utils import scratch

_GITLINK = b"160000"
_SYMLINK = b"120000"
_EXECUTABLE = b"100755"
_RAW_BYTES_ATTRIBUTES = "* -text -eol -filter -ident -working-tree-encoding\n"


class TreeStateUnknown(OSError):
    """git could not list what a checkout holds."""


def _tree_entries(worktree: Path, commit: str) -> dict[bytes, tuple[bytes, bytes]]:
    """`{path: (mode, id)}` for every file `commit` records."""
    out = stdout_bytes(worktree, ["ls-tree", "-r", "-z", "--full-tree", commit], context=UNTRUSTED)
    if out is None:
        raise TreeStateUnknown(f"{commit[:12]} could not be listed")
    entries = {}
    for record in out.split(b"\0"):
        if not record:
            continue
        info, _, path = record.partition(b"\t")
        mode, _kind, oid = info.split(b" ")
        entries[path] = (mode, oid)
    return entries


def _index_entries(worktree: Path) -> dict[bytes, tuple[bytes, bytes, bytes]]:
    """`{path: (mode, id, stage)}` for every index entry of `worktree`."""
    out = stdout_bytes(worktree, ["ls-files", "-s", "-z"], context=UNTRUSTED)
    if out is None:
        raise TreeStateUnknown(f"the index of {worktree} could not be listed")
    entries = {}
    for record in out.split(b"\0"):
        if not record:
            continue
        info, _, path = record.partition(b"\t")
        mode, oid, stage_number = info.split(b" ")
        entries[path] = (mode, oid, stage_number)
    return entries


def _blob_id(data: bytes, object_format: str) -> bytes:
    digest = hashlib.new("sha256" if object_format == "sha256" else "sha1")
    digest.update(b"blob %d\0" % len(data))
    digest.update(data)
    return digest.hexdigest().encode()


def _file_matches(path: Path, mode: bytes, oid: bytes, object_format: str,
                  track_executable: bool) -> bool:
    try:
        info = os.lstat(path)
        if mode == _SYMLINK:
            return stat.S_ISLNK(info.st_mode) and _blob_id(os.fsencode(os.readlink(path)),
                                                          object_format) == oid
        if not stat.S_ISREG(info.st_mode):
            return False
        if track_executable and bool(info.st_mode & stat.S_IXUSR) != (mode == _EXECUTABLE):
            return False
        return _blob_id(path.read_bytes(), object_format) == oid
    except OSError:
        return False


def is_dirty(worktree: str | Path) -> bool:
    """Whether `worktree` holds anything its HEAD does not: a staged change, a conflict, a tracked
    file whose bytes or mode differ, or an untracked file that is not ignored. Content is compared
    as raw bytes, so a file a filter would have normalised reads as changed — the answer errs
    towards dirty. A checkout that cannot be read is dirty."""
    worktree = Path(worktree)
    try:
        head = stdout(worktree, ["rev-parse", "--verify", "--quiet", "HEAD"],
                      context=UNTRUSTED).strip()
        committed = _tree_entries(worktree, head) if head else {}
        indexed = _index_entries(worktree)
    except (TreeStateUnknown, ValueError):
        return True
    if any(stage_number != b"0" for _m, _o, stage_number in indexed.values()):
        return True
    if {p: (m, o) for p, (m, o, _s) in indexed.items()} != committed:
        return True
    object_format = stdout(worktree, ["rev-parse", "--show-object-format"],
                           context=UNTRUSTED).strip() or "sha1"
    track_executable = stdout(worktree, ["config", "--get", "--type=bool", "core.filemode"],
                              context=UNTRUSTED).strip() != "false"
    for path, (mode, oid) in committed.items():
        if mode == _GITLINK:
            continue
        if not _file_matches(worktree / os.fsdecode(path), mode, oid, object_format,
                             track_executable):
            return True
    listing = ["ls-files", "-z", "--others", "--exclude-standard"]
    excludes = operator_config.global_excludes_file()
    if excludes is not None:
        listing.append(f"--exclude-from={excludes}")
    untracked = stdout_bytes(worktree, listing, context=UNTRUSTED)
    return untracked is None or bool(untracked.strip(b"\0"))


def _has_link_above(worktree: Path, rel: bytes) -> bool:
    here = worktree
    for part in os.fsdecode(rel).split("/")[:-1]:
        here = here / part
        if os.path.islink(here):
            return True
    return False


def _write_paths(repo: Path, worktree: Path, commit: str, entries, paths: list[bytes]) -> bool:
    """Write the raw bytes `commit` records at `paths` into `worktree`, and delete every path in
    `paths` it does not record. Returns whether every one was written."""
    deleted = [p for p in paths if p not in entries]
    written = [p for p in paths if p in entries and entries[p][0] != _GITLINK]
    for rel in deleted:
        if _has_link_above(worktree, rel):
            return False
        target = worktree / os.fsdecode(rel)
        try:
            if target.is_dir() and not target.is_symlink():
                shutil.rmtree(target)
            elif os.path.lexists(target):
                target.unlink()
        except OSError:
            return False
        parent = target.parent
        while parent != worktree and parent.is_dir() and not any(parent.iterdir()):
            parent.rmdir()
            parent = parent.parent
    if not written:
        return True
    with borrow(repo) as borrowed:
        (borrowed.path / "info").mkdir(exist_ok=True)
        (borrowed.path / "info" / "attributes").write_text(_RAW_BYTES_ATTRIBUTES, encoding="utf-8")
        index = scratch.new_file("an index to write a checkout from")
        try:
            index.unlink()
            env = {"GIT_INDEX_FILE": str(index)}
            loaded = borrowed.run(["read-tree", commit], env=env)
            if loaded is None or loaded.returncode != 0:
                return False
            done = stdout_bytes_fed(borrowed.path, ["--work-tree", str(worktree), "checkout-index",
                                                    "-f", "-z", "--stdin"],
                                    b"\0".join(written) + b"\0", env=env, context=SAW_OWNED)
            return done is not None
        finally:
            scratch.release_path(index)


class PreparedMove:
    """A checkout about to follow its branch: its index already rewritten on a private copy and
    its `index.lock` held, so nothing else writes the index between the ref move and the swap."""

    def __init__(self, repo: Path, holder: Checkout, old: str, new: str):
        self.repo, self.holder, self.old, self.new = repo, holder, old, new
        self.lock = holder.gitdir / "index.lock"
        self.staged = scratch.new_file("the index a checkout moves to")
        self.paths: list[bytes] = []
        self.target: dict = {}
        self.held = False

    def prepare(self) -> bool:
        """Rewrite a copy of the index to `new` and take the index lock. Returns whether both
        happened; on False nothing is held."""
        try:
            before = _tree_entries(self.holder.worktree, self.old)
            self.target = _tree_entries(self.holder.worktree, self.new)
        except (TreeStateUnknown, ValueError):
            return False
        self.paths = sorted(p for p in set(before) | set(self.target)
                            if before.get(p) != self.target.get(p))
        zero = b"0" * len(self.new)
        feed = b"".join(
            (b"%s %s\t%s\0" % (self.target[p][0], self.target[p][1], p)) if p in self.target
            else (b"0 %s\t%s\0" % (zero, p)) for p in self.paths)
        try:
            shutil.copyfile(self.holder.gitdir / "index", self.staged)
            fd = os.open(self.lock, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o644)
            os.close(fd)
        except OSError:
            return False
        self.held = True
        if feed and stdout_bytes_fed(self.holder.worktree, ["update-index", "-z", "--index-info"],
                                     feed, env={"GIT_INDEX_FILE": str(self.staged)},
                                     context=UNTRUSTED) is None:
            self.release()
            return False
        return True

    def apply(self) -> bool:
        """Write the changed paths and swap in the prepared index. Returns whether both landed;
        on False the index is untouched and the lock released."""
        try:
            if not _write_paths(self.repo, self.holder.worktree, self.new, self.target, self.paths):
                self.release()
                return False
            shutil.copyfile(self.staged, self.lock)
            os.replace(self.lock, self.holder.gitdir / "index")
            self.held = False
            return True
        except OSError:
            self.release()
            return False

    def restore_files(self) -> bool:
        """Write the changed paths back to what `old` records. Returns whether all were."""
        try:
            before = _tree_entries(self.holder.worktree, self.old)
            return _write_paths(self.repo, self.holder.worktree, self.old, before, self.paths)
        except (TreeStateUnknown, OSError, ValueError):
            return False

    def release(self) -> None:
        """Drop the lock if still held, and the private index."""
        if self.held:
            try:
                os.unlink(self.lock)
            except OSError:
                pass
            self.held = False
        scratch.release_path(self.staged)
