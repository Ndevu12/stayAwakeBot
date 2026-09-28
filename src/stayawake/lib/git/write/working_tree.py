#!/usr/bin/env python3
"""An operator's checkout read and moved without `status` or `reset --hard`. The index and HEAD are
read as listings; a tracked file is clean when its recorded stat data still matches, and otherwise
when its bytes, converted by git's built-in end-of-line and ident rules, hash to the recorded blob.
A checkout follows its branch by writing the changed paths with those same conversions from a
saw-owned repository and swapping in an index prepared on a private copy."""
from __future__ import annotations

import hashlib
import os
import re
import shutil
import stat
from dataclasses import dataclass
from pathlib import Path

from stayawake.lib.git import operator_config
from stayawake.lib.git.borrowed import borrow
from stayawake.lib.git.run import SAW_OWNED, UNTRUSTED, stdout, stdout_bytes, stdout_bytes_fed
from stayawake.lib.git.write.checkouts import Checkout
from stayawake.utils import scratch

_GITLINK = b"160000"
_SYMLINK = b"120000"
_EXECUTABLE = b"100755"
_NO_FILTER = b"* -filter\n"
_CONVERSION_ATTRIBUTES = ("filter", "text", "eol", "crlf", "ident", "working-tree-encoding")
_CONVERSION_CONFIG = ("core.autocrlf", "core.eol", "core.safecrlf", "core.checkroundtripencoding")
_STAT_FIELD = re.compile(rb"(ctime|mtime|dev|ino|uid|gid|size|flags): (\S+)")
_SUBMODULE_DEPTH = 8


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


def _recorded_stats(worktree: Path) -> dict[bytes, dict[bytes, bytes]] | None:
    """`{path: {field: value}}` of the stat data the index records for each entry. Takes the
    working tree. Returns None when git could not list it."""
    out = stdout_bytes(worktree, ["ls-files", "-s", "--debug", "-z"], context=UNTRUSTED)
    if out is None:
        return None
    stats: dict[bytes, dict[bytes, bytes]] = {}
    chunks = out.split(b"\0")
    header = chunks[0]
    for chunk in chunks[1:]:
        lines = chunk.split(b"\n")
        fields: dict[bytes, bytes] = {}
        rest = 0
        for rest, line in enumerate(lines):
            found = _STAT_FIELD.findall(line) if line.startswith(b"  ") else []
            if not found:
                break
            fields.update(found)
        else:
            rest = len(lines)
        path = header.partition(b"\t")[2]
        if path:
            stats[path] = fields
        header = b"\n".join(lines[rest:])
    return stats


def _nanoseconds(value: bytes) -> int:
    seconds, _, fraction = value.partition(b":")
    return int(seconds) * 1_000_000_000 + int(fraction or b"0")


def _stat_unchanged(path: Path, recorded: dict[bytes, bytes], mode: bytes,
                    track_executable: bool) -> bool:
    """Whether `path` still has the modification and change times, size, inode and mode the index
    recorded. Takes the file, its recorded fields, the recorded mode and whether the executable
    bit counts. Returns False when unsure."""
    try:
        info = os.lstat(path)
        mtime = _nanoseconds(recorded[b"mtime"])
        if (mode == _SYMLINK) != stat.S_ISLNK(info.st_mode):
            return False
        if track_executable and mode != _SYMLINK and (
                bool(info.st_mode & stat.S_IXUSR) != (mode == _EXECUTABLE)):
            return False
        return (info.st_mtime_ns == mtime
                and info.st_ctime_ns == _nanoseconds(recorded[b"ctime"])
                and info.st_size & 0xFFFFFFFF == int(recorded[b"size"])
                and info.st_ino & 0xFFFFFFFF == int(recorded[b"ino"]))
    except (OSError, KeyError, ValueError):
        return False


def _attributes(repo: Path, paths: list[bytes], context,
                operator: list[str]) -> dict[bytes, dict[bytes, bytes]] | None:
    """`{path: {attribute: value}}` of the conversion attributes git applies to each path in
    `repo`. Takes the repository, the paths, the context to ask in and the operator's own
    settings as `-c` arguments. Returns None when git could not say."""
    if not paths:
        return {}
    out = stdout_bytes_fed(repo, [*operator, "check-attr", "-z", "--stdin",
                                  *_CONVERSION_ATTRIBUTES],
                           b"\0".join(paths) + b"\0", context=context)
    if out is None:
        return None
    fields = out.split(b"\0")
    found: dict[bytes, dict[bytes, bytes]] = {p: {} for p in paths}
    for i in range(0, len(fields) - 2, 3):
        found.setdefault(fields[i], {})[fields[i + 1]] = fields[i + 2]
    return found


def _conversion_config(repo: Path) -> list[str]:
    """The `-c` settings that carry the end-of-line configuration and attributes file git uses for
    `repo`, as data: the repository's own value, else the operator's global one. Takes the
    repository. Returns them."""
    operator = operator_config.global_config(repo)
    args = []
    for key in (*_CONVERSION_CONFIG, "core.attributesfile"):
        value = stdout(repo, ["config", "--get", key], context=UNTRUSTED).strip() \
            or operator.get(key, "")
        if value:
            if key == "core.attributesfile":
                value = os.path.expanduser(value)
            args += ["-c", f"{key}={value}"]
    return args


def _converted_as_in(repo: Path, borrowed, paths: list[bytes]) -> bool:
    """Whether a saw-owned repository converts `paths` exactly as `repo` does and none passes
    through a filter. Takes the operator's repository, the saw-owned one and the paths. Returns
    False when git could not say."""
    operator = _conversion_config(repo)
    theirs = _attributes(repo, paths, UNTRUSTED, operator)
    ours = _attributes(borrowed.path, paths, SAW_OWNED, operator)
    if theirs is None or ours is None:
        return False
    for rel in paths:
        attrs = theirs.get(rel, {})
        if attrs.get(b"filter", b"unspecified") not in (b"unspecified", b"unset"):
            return False
        if attrs != ours.get(rel, {}):
            return False
    return True


def _blob_id(data: bytes, object_format: str) -> bytes:
    digest = hashlib.new("sha256" if object_format == "sha256" else "sha1")
    digest.update(b"blob %d\0" % len(data))
    digest.update(data)
    return digest.hexdigest().encode()


def _content_matches(borrowed, worktree: Path, rel: bytes, mode: bytes, oid: bytes,
                     object_format: str, track_executable: bool, conversion: list[str]) -> bool:
    """Whether the file at `rel` holds what the index records, its bytes converted by git's
    built-in rules for that path. Takes the saw-owned repository, the working tree, the path, its
    recorded mode and id, the object format, whether the executable bit counts and the
    operator's end-of-line settings as `-c` arguments."""
    path = worktree / os.fsdecode(rel)
    if _has_link_above(worktree, rel):
        return False
    try:
        info = os.lstat(path)
        if mode == _SYMLINK:
            return stat.S_ISLNK(info.st_mode) and _blob_id(os.fsencode(os.readlink(path)),
                                                          object_format) == oid
        if not stat.S_ISREG(info.st_mode):
            return False
        if track_executable and bool(info.st_mode & stat.S_IXUSR) != (mode == _EXECUTABLE):
            return False
        data = path.read_bytes()
    except OSError:
        return False
    hashed = stdout_bytes_fed(borrowed.path, [*conversion, "hash-object",
                                              f"--path={os.fsdecode(rel)}", "--stdin"], data,
                              context=SAW_OWNED)
    return hashed is not None and hashed.strip() == oid


def _submodule_dirty(worktree: Path, rel: bytes, oid: bytes, depth: int) -> bool:
    """Whether the submodule checked out at `rel` holds anything the recorded commit does not.
    Takes the working tree, the path, the recorded commit and the nesting depth. An uninitialised
    submodule is clean."""
    path = worktree / os.fsdecode(rel)
    if not os.path.lexists(path / ".git"):
        return False
    if depth >= _SUBMODULE_DEPTH:
        return True
    head = stdout(path, ["rev-parse", "--verify", "--quiet", "HEAD"], context=UNTRUSTED).strip()
    return head.encode() != oid or is_dirty(path, _depth=depth + 1)


def uncommitted_paths(worktree: str | Path, *, _depth: int = 0) -> list[bytes] | None:
    """Every path `worktree` holds differently from its HEAD: a staged change, a conflict, a
    tracked file whose content or mode differs from the index, a submodule off its recorded
    commit or with work of its own, and each untracked file that is not ignored. A changed file
    the operator's attributes send through a filter is listed. Takes the working tree. Returns
    the paths, or None when git could not say."""
    worktree = Path(worktree)
    try:
        head = stdout(worktree, ["rev-parse", "--verify", "--quiet", "HEAD"],
                      context=UNTRUSTED).strip()
        committed = _tree_entries(worktree, head) if head else {}
        indexed = _index_entries(worktree)
    except (TreeStateUnknown, ValueError):
        return None
    changed: set[bytes] = {rel for rel in set(committed) | set(indexed)
                           if rel not in indexed or indexed[rel][2] != b"0"
                           or committed.get(rel) != indexed[rel][:2]}
    tracked = {rel: (mode, oid) for rel, (mode, oid, stage) in indexed.items() if stage == b"0"}
    for rel, (mode, oid) in tracked.items():
        if mode == _GITLINK and _submodule_dirty(worktree, rel, oid, _depth):
            changed.add(rel)
    stats = _recorded_stats(worktree)
    if stats is None:
        return None
    track_executable = stdout(worktree, ["config", "--get", "--type=bool", "core.filemode"],
                              context=UNTRUSTED).strip() != "false"
    stale = [rel for rel, (mode, _oid) in tracked.items() if mode != _GITLINK
             and not _stat_unchanged(worktree / os.fsdecode(rel), stats.get(rel, {}), mode,
                                     track_executable)]
    compare = []
    for rel in stale:
        recorded = stats.get(rel, {}).get(b"size", b"0")
        try:
            resized = recorded != b"0" and os.lstat(
                worktree / os.fsdecode(rel)).st_size & 0xFFFFFFFF != int(recorded)
        except (OSError, ValueError):
            resized = True
        (changed.add(rel) if resized else compare.append(rel))
    if compare:
        object_format = stdout(worktree, ["rev-parse", "--show-object-format"],
                               context=UNTRUSTED).strip() or "sha1"
        conversion = _conversion_config(worktree)
        with borrow(worktree) as borrowed:
            if not _converted_as_in(worktree, borrowed, compare):
                changed.update(compare)
            else:
                with borrowed.attributes_then(_NO_FILTER):
                    for rel in compare:
                        mode, oid = tracked[rel]
                        if not _content_matches(borrowed, worktree, rel, mode, oid,
                                                object_format, track_executable, conversion):
                            changed.add(rel)
    own = stdout(worktree, ["config", "--get", "core.excludesFile"], context=UNTRUSTED).strip()
    excludes = None if own else operator_config.global_excludes_file(
        operator_config.global_config(worktree))
    listing = (["-c", f"core.excludesFile={excludes}"] if excludes is not None else []) + [
        "ls-files", "-z", "--others", "--exclude-standard"]
    untracked = stdout_bytes(worktree, listing, context=UNTRUSTED)
    if untracked is None:
        return None
    changed.update(p for p in untracked.split(b"\0") if p)
    return sorted(changed)


@dataclass(frozen=True)
class ChangesInTheWay:
    """The uncommitted changes a checkout holds on the paths a move to another commit rewrites.

    `carryable` are changes a move can leave as they are on disk; `already` are changes that
    already hold what the target records; `blocking` are what no move can keep: a merge, rebase,
    cherry-pick or revert in progress, a conflict anywhere, a changed submodule on a rewritten
    path, and a rewritten path reached through a link."""

    carryable: tuple[str, ...] = ()
    already: tuple[str, ...] = ()
    blocking: tuple[str, ...] = ()


_OPERATIONS = ("MERGE_HEAD", "CHERRY_PICK_HEAD", "REVERT_HEAD", "rebase-merge", "rebase-apply")


def operations_in_progress(worktree: Path) -> list[str] | None:
    """The git operations `worktree` is in the middle of. Takes the working tree. Returns their
    names, or None when git could not say where it keeps them."""
    args = ["rev-parse"] + [part for name in _OPERATIONS for part in ("--git-path", name)]
    listed = stdout(worktree, args, context=UNTRUSTED).splitlines()
    if len(listed) != len(_OPERATIONS):
        return None
    found = []
    for name, where in zip(_OPERATIONS, listed):
        path = Path(where) if os.path.isabs(where) else worktree / where
        if os.path.lexists(path):
            found.append(name)
    return found


def changes_in_the_way(worktree: str | Path, commit: str) -> ChangesInTheWay | None:
    """The uncommitted changes in `worktree` that a move to `commit` would overwrite: each path
    the move rewrites whose state on disk is not what `commit` records there, or whose staged
    entry differs from both HEAD and `commit`. A change on a path the move leaves alone is not in
    the way. Takes the working tree and the commit. Returns them, or None when the checkout cannot
    be read."""
    worktree = Path(worktree)
    operations = operations_in_progress(worktree)
    changed = uncommitted_paths(worktree)
    if changed is None or operations is None:
        return None
    try:
        head = stdout(worktree, ["rev-parse", "--verify", "--quiet", "HEAD"],
                      context=UNTRUSTED).strip()
        committed = _tree_entries(worktree, head) if head else {}
        target = _tree_entries(worktree, commit)
        indexed = _index_entries(worktree)
    except (TreeStateUnknown, ValueError):
        return None
    across = set(committed) | set(target)
    rewritten = {rel for rel in across if committed.get(rel) != target.get(rel)}
    blocking = [rel for rel, entry in indexed.items() if entry[2] != b"0"]
    blocking += [rel for rel in rewritten if _has_link_above(worktree, rel)]
    blocking += [name.encode() for name in operations]
    carryable: list[bytes] = []
    already: list[bytes] = []
    present = []
    for rel in changed:
        if rel in blocking or rel not in rewritten:
            continue
        staged = indexed.get(rel)
        if staged is not None and staged[:2] not in (committed.get(rel), target.get(rel)):
            carryable.append(rel)
        elif rel not in target:
            if os.path.lexists(worktree / os.fsdecode(rel)):
                carryable.append(rel)
            else:
                already.append(rel)
        elif target[rel][0] == _GITLINK:
            blocking.append(rel)
        else:
            present.append(rel)
    if present:
        object_format = stdout(worktree, ["rev-parse", "--show-object-format"],
                               context=UNTRUSTED).strip() or "sha1"
        track_executable = stdout(worktree, ["config", "--get", "--type=bool", "core.filemode"],
                                  context=UNTRUSTED).strip() != "false"
        conversion = _conversion_config(worktree)
        with borrow(worktree) as borrowed:
            if not _converted_as_in(worktree, borrowed, present):
                carryable.extend(present)
            else:
                with borrowed.attributes_then(_NO_FILTER):
                    for rel in present:
                        matches = _content_matches(borrowed, worktree, rel, *target[rel],
                                                   object_format, track_executable, conversion)
                        (already if matches else carryable).append(rel)
    return ChangesInTheWay(tuple(sorted(os.fsdecode(r) for r in carryable)),
                           tuple(sorted(os.fsdecode(r) for r in already)),
                           tuple(sorted({os.fsdecode(r) for r in blocking})))


def is_dirty(worktree: str | Path, *, _depth: int = 0) -> bool:
    """Whether `worktree` holds anything its HEAD does not (see `uncommitted_paths`). Takes the
    working tree. A checkout that cannot be read is dirty."""
    found = uncommitted_paths(worktree, _depth=_depth)
    return found is None or bool(found)


def _has_link_above(worktree: Path, rel: bytes) -> bool:
    here = worktree
    for part in os.fsdecode(rel).split("/")[:-1]:
        here = here / part
        if os.path.islink(here):
            return True
    return False


def _write_paths(repo: Path, worktree: Path, commit: str, entries, paths: list[bytes]) -> bool:
    """Write what `commit` records at `paths` into `worktree`, converted by git's built-in
    end-of-line and ident rules, and delete every path in `paths` it does not record; a directory
    holding anything is left in place, as git leaves it. Returns whether every one was written."""
    deleted = [p for p in paths if p not in entries]
    written = [p for p in paths if p in entries and entries[p][0] != _GITLINK]
    for rel in deleted:
        if _has_link_above(worktree, rel):
            return False
        target = worktree / os.fsdecode(rel)
        try:
            if target.is_dir() and not target.is_symlink():
                if not any(target.iterdir()):
                    target.rmdir()
                continue
            if os.path.lexists(target):
                target.unlink()
        except OSError:
            return False
        parent = target.parent
        while parent != worktree and parent.is_dir() and not any(parent.iterdir()):
            parent.rmdir()
            parent = parent.parent
    if not written:
        return True
    with borrow(repo) as borrowed, borrowed.attributes_then(_NO_FILTER):
        index = scratch.new_file("an index to write a checkout from")
        try:
            index.unlink()
            env = {"GIT_INDEX_FILE": str(index)}
            loaded = borrowed.run(["read-tree", commit], env=env)
            if loaded is None or loaded.returncode != 0:
                return False
            done = stdout_bytes_fed(borrowed.path, [*_conversion_config(worktree), "--work-tree",
                                                    str(worktree), "checkout-index", "-f", "-z",
                                                    "--stdin"],
                                    b"\0".join(written) + b"\0", env=env, context=SAW_OWNED)
            return done is not None
        finally:
            scratch.release_path(index)


def rewrite_index(worktree: str | Path, feed: bytes) -> bool:
    """Apply `update-index --index-info` lines to the index of the checkout at `worktree`: on a
    private copy first, then swapped in while git's own `index.lock` is held. Takes the checkout
    and the NUL-separated lines. Returns whether the index now holds them; on False it is
    untouched."""
    gitdir = stdout(worktree, ["rev-parse", "--path-format=absolute", "--git-dir"],
                    context=UNTRUSTED).strip()
    if not gitdir:
        return False
    index, lock = Path(gitdir) / "index", Path(gitdir) / "index.lock"
    try:
        fd = os.open(lock, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o644)
        os.close(fd)
    except OSError:
        return False
    held = True
    private = scratch.new_file("the index a run rewrites")
    try:
        shutil.copyfile(index, private)
        if stdout_bytes_fed(worktree, ["update-index", "-z", "--index-info"], feed,
                            env={"GIT_INDEX_FILE": str(private)}, context=UNTRUSTED) is None:
            return False
        shutil.copyfile(private, lock)
        os.replace(lock, index)
        held = False
        return True
    except OSError:
        return False
    finally:
        if held:
            try:
                os.unlink(lock)
            except OSError:
                pass
        scratch.release_path(private)


def _unstaged(entry, recorded) -> bool:
    """Whether an index entry holds what HEAD records at its path, the operator having staged
    nothing there. Takes the index entry (or None) and HEAD's entry (or None)."""
    return (entry[:2] if entry is not None else None) == recorded


class PreparedMove:
    """A checkout about to follow its branch: its index already rewritten on a private copy and
    its `index.lock` held, so nothing else writes the index between the ref move and the swap.

    `keep` names paths left as they are on disk; each keeps what was staged there, or follows the
    branch when nothing was. `restage` gives, for kept paths, the index entries to put back
    exactly (None for no entry). `kept_entries` records what was staged at each kept path before
    the move."""

    def __init__(self, repo: Path, holder: Checkout, old: str, new: str,
                 keep: frozenset[bytes] = frozenset(), restage: dict | None = None):
        self.repo, self.holder, self.old, self.new = repo, holder, old, new
        self.keep = keep
        self.restage = restage
        self.kept_entries: dict = {}
        self.lock = holder.gitdir / "index.lock"
        self.staged = scratch.new_file("the index a checkout moves to")
        self.paths: list[bytes] = []
        self.target: dict = {}
        self.held = False

    def prepare(self) -> bool:
        """Rewrite a copy of the index to `new` and take the index lock. Returns whether both
        happened; on False nothing is held, and False when a path the move rewrites passes
        through a filter."""
        try:
            before = _tree_entries(self.holder.worktree, self.old)
            self.target = _tree_entries(self.holder.worktree, self.new)
        except (TreeStateUnknown, ValueError):
            return False
        self.paths = sorted(p for p in set(before) | set(self.target)
                            if before.get(p) != self.target.get(p))
        files = [p for p in self.paths
                 if any(side.get(p, (_GITLINK,))[0] != _GITLINK for side in (before, self.target))]
        if files:
            with borrow(self.repo) as borrowed:
                converts_alike = _converted_as_in(self.holder.worktree, borrowed, files)
            if not converts_alike:
                return False
        zero = b"0" * len(self.new)
        try:
            staged = _index_entries(self.holder.worktree) if self.keep else {}
        except (TreeStateUnknown, ValueError):
            return False
        self.kept_entries = {p: staged.get(p) for p in self.paths if p in self.keep}
        lines = []
        for p in self.paths:
            if p in self.keep and self.restage is not None and p in self.restage:
                entry = self.restage[p]
                lines.append(b"%s %s\t%s\0" % (entry[0], entry[1], p) if entry is not None
                             else b"0 %s\t%s\0" % (zero, p))
            elif p not in self.keep or _unstaged(staged.get(p), before.get(p)):
                lines.append(b"%s %s\t%s\0" % (self.target[p][0], self.target[p][1], p)
                             if p in self.target else b"0 %s\t%s\0" % (zero, p))
        feed = b"".join(lines)
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
            if not _write_paths(self.repo, self.holder.worktree, self.new, self.target,
                                [p for p in self.paths if p not in self.keep]):
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
            return _write_paths(self.repo, self.holder.worktree, self.old, before,
                                [p for p in self.paths if p not in self.keep])
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
