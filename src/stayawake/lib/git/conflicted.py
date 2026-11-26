#!/usr/bin/env python3
"""A merge or rebase saw ran in its holding copy that stopped for conflicts: what it left there, and
the files that carry it into the open folder's git directory."""
from __future__ import annotations

import hashlib
import os
import shutil
import stat
from dataclasses import dataclass, field
from pathlib import Path

from stayawake.lib.git.run import SAW_OWNED, UNTRUSTED, run, stdout, stdout_bytes, stdout_bytes_fed
from stayawake.utils import atomicwrite, pathsafe, scratch

MERGE = "merge"
REBASE = "rebase"
CANNOT_CARRY = "the update stops for conflicts that cannot be brought into the folder"
FINISH_COMMAND = {MERGE: "git commit", REBASE: "git rebase --continue"}

_IN_PROGRESS = ("MERGE_HEAD", "rebase-merge", "rebase-apply")
_REBASE_STATE = "rebase-merge"
_FILE_MODES = (b"100644", b"100755")
_LARGEST_STATE_FILE = 64 << 20
_HEX = frozenset(b"0123456789abcdef")

_ONE_COMMIT = "one-commit"
_TEXT = "text"
_TODO = "todo"
_COUNT = "count"
_FLAG = "flag"
_COMMIT_LINES = "commit-lines"
_BRANCH = "branch"
_MERGE_MODE = "merge-mode"
_SIGNING = "signing"

_MERGE_FILES = {"MERGE_HEAD": _ONE_COMMIT, "MERGE_MSG": _TEXT, "MERGE_MODE": _MERGE_MODE,
                "ORIG_HEAD": _ONE_COMMIT}
_REBASE_ROOT_FILES = {"REBASE_HEAD": _ONE_COMMIT, "ORIG_HEAD": _ONE_COMMIT, "MERGE_MSG": _TEXT}
_REBASE_STATE_FILES = {
    "head-name": _BRANCH, "onto": _ONE_COMMIT, "orig-head": _ONE_COMMIT, "stopped-sha": _ONE_COMMIT,
    "git-rebase-todo": _TODO, "git-rebase-todo.backup": _TODO, "done": _TODO,
    "end": _COUNT, "msgnum": _COUNT, "message": _TEXT, "author-script": _TEXT, "patch": _TEXT,
    "interactive": _FLAG, "drop_redundant_commits": _FLAG, "no-reschedule-failed-exec": _FLAG,
    "rewritten-list": _COMMIT_LINES, "rewritten-pending": _COMMIT_LINES, "gpg_sign_opt": _SIGNING,
}
_REBASE_STATE_NEEDED = ("head-name", "onto", "orig-head", "git-rebase-todo", "done", "end", "msgnum")


@dataclass(frozen=True)
class Stopped:
    """A merge or rebase stopped for conflicts in the holding copy: the operation, the commit
    the update brings, the tree the open folder's files take, the commit the holding copy's HEAD is
    on, each conflicted index entry as (path, mode, object, stage), each file git keeps for the
    operation as (place, sha256 of its bytes), and the commits a rebase has yet to replay. `files`
    holds those files' bytes, by their place in a git directory."""

    operation: str
    incoming: str
    landed: str
    head: str
    stages: tuple[tuple[str, str, str, str], ...]
    file_digests: tuple[tuple[str, str], ...]
    picks: tuple[str, ...] = ()
    files: dict = field(default_factory=dict, compare=False)

    @property
    def conflicts(self) -> tuple[str, ...]:
        """Name the paths left to resolve. Returns them sorted."""
        return tuple(sorted({path for path, _, _, _ in self.stages}))

    def entries_by_path(self) -> dict[bytes, tuple[tuple[bytes, bytes, bytes], ...]]:
        """Group the conflicted index entries by path. Returns each path's (mode, object, stage)
        entries."""
        grouped: dict[bytes, list[tuple[bytes, bytes, bytes]]] = {}
        for path, mode, oid, stage in self.stages:
            grouped.setdefault(os.fsencode(path), []).append((mode.encode(), oid.encode(), stage.encode()))
        return {path: tuple(entries) for path, entries in grouped.items()}

    def record(self) -> dict:
        """Write what identifies this stop as JSON-ready values. Returns them."""
        return {"operation": self.operation, "incoming": self.incoming, "landed": self.landed,
                "head": self.head, "stages": [list(entry) for entry in self.stages],
                "file_digests": [list(entry) for entry in self.file_digests], "picks": list(self.picks)}

    @classmethod
    def from_record(cls, record: dict) -> "Stopped":
        """Read a stop back from what `record` wrote. Takes the record. Returns the stop. Raises
        KeyError or TypeError for anything else."""
        return cls(record["operation"], record["incoming"], record["landed"], record["head"],
                   tuple(tuple(entry) for entry in record["stages"]),
                   tuple(tuple(entry) for entry in record["file_digests"]), tuple(record["picks"]))


def stopped_for_conflicts(work: Path, holding: Path) -> bool:
    """Tell whether a merge or rebase in the holding copy stopped for conflicts. Takes the holding
    work tree and its git directory. Returns the answer."""
    if not any(os.path.lexists(holding / name) for name in _IN_PROGRESS):
        return False
    return bool(unmerged_entries(work))


def read(work: Path, holding: Path, base: str) -> "Stopped | str":
    """Read what a merge or rebase that stopped for conflicts left in the holding copy, and write
    the tree the open folder's files take. Takes the holding work tree, its git directory and the
    commit the open folder is on. Returns the stop, or a sentence when it cannot be carried."""
    operation = MERGE if os.path.lexists(holding / "MERGE_HEAD") else (
        REBASE if os.path.lexists(holding / _REBASE_STATE) else "")
    stages = unmerged_entries(work)
    if not operation or not stages:
        return CANNOT_CARRY
    if any(mode not in _FILE_MODES for entries in stages.values() for mode, _, _ in entries):
        return CANNOT_CARRY
    files = operation_files(holding, operation)
    if files is None:
        return CANNOT_CARRY
    incoming = _commit_in(files["MERGE_HEAD" if operation == MERGE else f"{_REBASE_STATE}/onto"])
    if _commit_in(files["ORIG_HEAD"]) != base:
        return CANNOT_CARRY
    if operation == REBASE and (_commit_in(files[f"{_REBASE_STATE}/orig-head"]) != base
                                or _commit_in(files["REBASE_HEAD"])
                                != _commit_in(files.get(f"{_REBASE_STATE}/stopped-sha", b""))):
        return CANNOT_CARRY
    head = stdout(work, ["rev-parse", "--verify", "--quiet", "HEAD"], context=SAW_OWNED).strip()
    landed = _landed_tree(work, holding, stages)
    if not head or not landed:
        return CANNOT_CARRY
    entries = tuple(sorted((os.fsdecode(path), mode.decode(), oid.decode(), stage.decode())
                           for path, listed in stages.items() for mode, oid, stage in listed))
    digests = tuple(sorted((place, hashlib.sha256(data).hexdigest()) for place, data in files.items()))
    picks = picks_in(files.get(f"{_REBASE_STATE}/git-rebase-todo", b""))
    return Stopped(operation, incoming, landed, head, entries, digests, picks, files)


def only_picks(todo: bytes) -> bool:
    """Tell whether a rebase todo holds nothing but picks. Takes its bytes. Returns the answer."""
    return _in_form(_TODO, todo)


def picks_in(todo: bytes) -> tuple[str, ...]:
    """Read the commits a rebase todo picks, in order. Takes the todo's bytes. Returns their ids."""
    return tuple(line.split(b" ")[1].decode() for line in todo.splitlines() if _is_pick(line))


def incoming_commits(holding: Path) -> tuple[str, ...]:
    """Read the commits a merge or rebase in progress in the holding copy brings. Takes the holding
    git directory. Returns their ids, or none when they cannot be read."""
    for place in ("MERGE_HEAD", f"{_REBASE_STATE}/onto", "rebase-apply/onto"):
        data = pathsafe.read_regular_no_follow(holding / place, _LARGEST_STATE_FILE)
        if data is None:
            continue
        named = tuple(line.decode() for line in data.split())
        return named if named and all(_is_object_id(line.encode()) for line in named) else ()
    return ()


def operation_in(holding: Path) -> str:
    """Name the operation in progress in the holding copy. Takes its git directory. Returns merge
    when a merge is under way, else rebase."""
    return MERGE if os.path.lexists(holding / "MERGE_HEAD") else REBASE


def unmerged_entries(work: Path) -> dict[bytes, tuple[tuple[bytes, bytes, bytes], ...]] | None:
    """Read the conflicted entries of the holding copy's index. Takes the holding work tree. Returns
    each conflicted path's (mode, object, stage) entries, or None when the index cannot be read."""
    listed = stdout_bytes(work, ["ls-files", "-s", "-u", "-z"], context=SAW_OWNED)
    if listed is None:
        return None
    found: dict[bytes, list[tuple[bytes, bytes, bytes]]] = {}
    for record in listed.split(b"\0"):
        if not record:
            continue
        described, _, path = record.partition(b"\t")
        parts = described.split(b" ")
        if len(parts) != 3 or not path:
            return None
        found.setdefault(path, []).append((parts[0], parts[1], parts[2]))
    return {path: tuple(entries) for path, entries in found.items()}


def versions_brought(work: Path, base: str, incoming: tuple[str, ...], head: str,
                     picks: tuple[str, ...] = ()) -> tuple[tuple[str, tuple[str, ...]], ...] | None:
    """List the other versions of files a stopped update brings: each incoming commit's version of
    each path it changes from the commit it shares with the open folder, the holding copy's HEAD's
    version of each path a rebase changed by moving HEAD, and each commit a rebase has yet to
    replay with the paths it changes. Takes the holding work tree, the open folder's commit, the
    incoming commits, the holding copy's HEAD and the commits left to replay. Returns (commit,
    paths) pairs, or None when they cannot be listed."""
    versions = []
    for commit in incoming:
        parted = stdout(work, ["merge-base", base, commit], context=SAW_OWNED).strip()
        if parted:
            names = _names(work, ["diff", "--name-only", "-z", parted, commit])
        else:
            names = _names(work, ["ls-tree", "-r", "-z", "--name-only", commit])
        if names is None:
            return None
        versions.append((commit, names))
    if head not in (base, *incoming):
        moved = _names(work, ["diff", "--name-only", "-z", base, head])
        if moved is None:
            return None
        versions.append((head, moved))
    for pick in picks:
        changed = changed_by(work, pick)
        if changed is None:
            return None
        versions.append((pick, changed))
    return tuple(versions)


def changed_by(repo: Path, commit: str) -> tuple[str, ...] | None:
    """List the paths a commit changes from its first parent, or every path of a commit with none.
    Takes a repository holding the commit and the commit. Returns the paths, or None when git could
    not list them."""
    parent = stdout(repo, ["rev-parse", "--verify", "--quiet", f"{commit}^"], context=UNTRUSTED).strip()
    args = ["diff", "--name-only", "-z", parent, commit] if parent else ["ls-tree", "-r", "-z", "--name-only", commit]
    listed = stdout_bytes(repo, args, context=UNTRUSTED)
    return None if listed is None else tuple(os.fsdecode(raw) for raw in listed.split(b"\0") if raw)


def commits_named(files: dict[str, bytes]) -> set[str]:
    """Collect every commit the operation's files name. Takes the files. Returns the commit ids."""
    named: set[str] = set()
    for place, data in files.items():
        form = _form_of(place)
        if form == _ONE_COMMIT:
            named.add(_commit_in(data))
        elif form == _TODO:
            named.update(line.split(b" ")[1].decode() for line in data.splitlines()
                         if line.startswith(b"pick "))
        elif form == _COMMIT_LINES:
            named.update(word.decode() for line in data.splitlines() for word in line.split())
    return named


def branch_named(files: dict[str, bytes]) -> str:
    """Read the branch a rebase replays. Takes the operation's files. Returns its ref, `detached
    HEAD`, or "" for a merge."""
    return files.get(f"{_REBASE_STATE}/head-name", b"").decode().strip()


def all_commits(repo: Path, ids: set[str]) -> bool:
    """Tell whether each id names a commit the open folder holds. Takes the open folder and the
    ids. Returns the answer."""
    if not ids:
        return True
    feed = ("\n".join(sorted(ids)) + "\n").encode()
    listed = stdout_bytes_fed(repo, ["cat-file", "--batch-check=%(objectname) %(objecttype)"], feed,
                              context=UNTRUSTED)
    if listed is None:
        return False
    lines = listed.decode(errors="replace").splitlines()
    return len(lines) == len(ids) and all(line.endswith(" commit") for line in lines)


class Placed:
    """The operation's files written into the open folder's git directory, and what each name
    held before."""

    def __init__(self, gitdir: Path, previous: dict[str, bytes | None], made_state: bool):
        self.gitdir, self.previous, self.made_state = gitdir, previous, made_state

    def take_back(self) -> bool:
        """Restore each name's earlier contents and remove each name that did not exist. Returns
        whether every one is restored."""
        whole = True
        for place, data in self.previous.items():
            target = self.gitdir / place
            if data is not None:
                whole = atomicwrite.replace(target, data, mode=atomicwrite.AS_A_PLAIN_WRITE) and whole
                continue
            try:
                if os.path.lexists(target):
                    target.unlink()
            except OSError:
                whole = False
        if self.made_state:
            shutil.rmtree(self.gitdir / _REBASE_STATE, ignore_errors=True)
            whole = whole and not os.path.lexists(self.gitdir / _REBASE_STATE)
        return whole


def place(gitdir: Path, files: dict[str, bytes]) -> Placed | None:
    """Write the files a merge or rebase in progress keeps into the open folder's git directory.
    Takes the git directory and the files by their place in it. Returns what was written, or None
    when one could not be, with every name put back."""
    if os.path.lexists(gitdir / _REBASE_STATE) or os.path.lexists(gitdir / "MERGE_HEAD"):
        return None
    made_state = any(name.startswith(f"{_REBASE_STATE}/") for name in files)
    previous: dict[str, bytes | None] = {}
    for name in files:
        if "/" not in name and os.path.lexists(gitdir / name):
            earlier = pathsafe.read_regular_no_follow(gitdir / name, _LARGEST_STATE_FILE)
            if earlier is None:
                return None
            previous[name] = earlier
        else:
            previous[name] = None
    placed = Placed(gitdir, previous, made_state)
    try:
        if made_state:
            atomicwrite.make_folder(gitdir / _REBASE_STATE)
    except OSError:
        placed.take_back()
        return None
    for name, data in files.items():
        if not atomicwrite.replace(gitdir / name, data, mode=atomicwrite.AS_A_PLAIN_WRITE):
            placed.take_back()
            return None
    return placed


def operation_files(holding: Path, operation: str) -> dict[str, bytes] | None:
    """Read the files git keeps for a merge or rebase in progress in the holding copy, each checked
    against the form git writes it in. Takes the holding git directory and the operation. Returns
    them by their place in a git directory, or None when one is missing or not in that form."""
    if operation == MERGE:
        names = list(_MERGE_FILES)
    else:
        try:
            listed = sorted(entry.name for entry in os.scandir(holding / _REBASE_STATE))
        except OSError:
            return None
        if not set(listed) <= set(_REBASE_STATE_FILES) or not set(_REBASE_STATE_NEEDED) <= set(listed):
            return None
        names = list(_REBASE_ROOT_FILES) + [f"{_REBASE_STATE}/{name}" for name in listed]
    files: dict[str, bytes] = {}
    for name in names:
        data = pathsafe.read_regular_no_follow(holding / name, _LARGEST_STATE_FILE)
        if data is None or not _in_form(_form_of(name), data):
            return None
        files[name] = data
    return files


def _form_of(place: str) -> str:
    """Return the form git writes the file at `place` in. Takes its place in a git directory."""
    if place.startswith(f"{_REBASE_STATE}/"):
        return _REBASE_STATE_FILES[place.split("/", 1)[1]]
    return {**_MERGE_FILES, **_REBASE_ROOT_FILES}[place]


def _in_form(form: str, data: bytes) -> bool:
    """Tell whether a file's bytes are in the form git writes it in. Takes the form and the bytes.
    Returns the answer."""
    if form == _TEXT:
        return True
    if form == _FLAG:
        return data == b""
    if form == _ONE_COMMIT:
        return data.endswith(b"\n") and _is_object_id(data[:-1])
    if form == _COUNT:
        return data.endswith(b"\n") and data[:-1].isdigit()
    if form == _MERGE_MODE:
        return data in (b"", b"no-ff")
    if form == _SIGNING:
        return data.startswith(b"-S") and not any(byte in b" \t\r\n" for byte in data)
    if form == _BRANCH:
        name = data[:-1] if data.endswith(b"\n") else b""
        return name == b"detached HEAD" or (name.startswith(b"refs/heads/") and data.count(b"\n") == 1
                                            and not any(byte in b" \t\r~^:?*[\\" for byte in name))
    lines = data.splitlines()
    if form == _COMMIT_LINES:
        return all(line.split() and all(_is_object_id(word) for word in line.split()) for line in lines)
    return all(not line or line.startswith(b"#") or _is_pick(line) for line in lines)


def _is_pick(line: bytes) -> bool:
    """Tell whether a todo line picks one commit. Takes the line. Returns the answer."""
    words = line.split(b" ", 2)
    return len(words) >= 2 and words[0] == b"pick" and _is_object_id(words[1])


def _is_object_id(word: bytes) -> bool:
    """Tell whether `word` is a full object id. Takes the bytes. Returns the answer."""
    return len(word) in (40, 64) and set(word) <= _HEX


def _commit_in(data: bytes) -> str:
    """Read the one commit id a file names. Takes its bytes. Returns the id, or ""."""
    return data.strip().decode() if _is_object_id(data.strip()) else ""


def _names(work: Path, args: list[str]) -> tuple[str, ...] | None:
    """List the paths a NUL-separated git listing names. Takes the holding work tree and the
    arguments. Returns the paths, or None when git could not list them."""
    listed = stdout_bytes(work, args, context=SAW_OWNED)
    if listed is None:
        return None
    return tuple(os.fsdecode(raw) for raw in listed.split(b"\0") if raw)


def _landed_tree(work: Path, holding: Path, stages: dict) -> str:
    """Write the tree the open folder's files take: the holding index, with each conflicted path
    holding the bytes on disk in the holding work tree, conflict markers included. Takes the
    holding work tree, its git directory and the conflicted entries. Returns the tree id, or "" when
    it could not be written."""
    private = scratch.new_file("the index a stopped update leaves in the folder")
    try:
        shutil.copyfile(holding / "index", private)
        env = {"GIT_INDEX_FILE": str(private)}
        zero = b"0" * len(next(iter(stages.values()))[0][1])
        feed = []
        for path, entries in sorted(stages.items()):
            feed.append(b"0 %s\t%s\0" % (zero, path))
            on_disk = work / os.fsdecode(path)
            try:
                found = os.lstat(on_disk)
            except FileNotFoundError:
                continue
            if not stat.S_ISREG(found.st_mode):
                return ""
            hashed = run(work, ["hash-object", "-w", "--no-filters", "--", os.fsdecode(path)],
                         context=SAW_OWNED)
            if hashed is None or hashed.returncode != 0 or not hashed.stdout.strip():
                return ""
            by_stage = {stage: mode for mode, _, stage in entries}
            mode = by_stage.get(b"2") or by_stage.get(b"3") or by_stage.get(b"1")
            feed.append(b"%s %s\t%s\0" % (mode, hashed.stdout.strip().encode(), path))
        if stdout_bytes_fed(work, ["update-index", "-z", "--index-info"], b"".join(feed), env=env,
                            context=SAW_OWNED) is None:
            return ""
        written = run(work, ["write-tree"], env=env, context=SAW_OWNED)
        return written.stdout.strip() if written is not None and written.returncode == 0 else ""
    except OSError:
        return ""
    finally:
        scratch.release_path(private)
