#!/usr/bin/env python3
"""Put the operator's uncommitted work on a local branch of its own, once it is clean."""
from __future__ import annotations

import os
import stat
import time
from dataclasses import dataclass, field
from pathlib import Path

from stayawake.lib.git.run import run, run_ok, stdout, stdout_bytes_fed
from stayawake.lib.git.write.working_tree import uncommitted_paths
from stayawake.utils import scratch

BRANCH_PREFIX = "saw/uncommitted-"
MAX_SAVED_BYTES = 2_000_000
_BATCH = 200
MESSAGE = ("saw: the uncommitted working tree, after the cleanup\n\n"
           "What the working tree held that was not committed, as it stands once the payload has "
           "been removed. This branch is local and is never pushed.\n")


@dataclass(frozen=True)
class Preserved:
    """What a run put aside.

    `branch` is empty when nothing was, `reason` names what stopped it, and `blocked` is True only
    when saw could not do what it should have rather than there being nothing to do.
    """

    branch: str = ""
    files: int = 0
    reason: str = ""
    blocked: bool = False
    withheld: int = 0
    unsaved: int = 0
    unread: int = 0

    def note(self) -> str:
        """Describe what was put aside, for the operator. Returns "" when nothing was."""
        if self.reason:
            return f"could not put your uncommitted work on a branch: {self.reason}"
        if not self.branch:
            return ""
        return (f"{self.files} uncommitted file(s) saved on the local branch "
                f"{self.branch} — it is never pushed") + self._withheld_note("; ")

    def _withheld_note(self, lead: str = "") -> str:
        """The counts that stayed out of the branch. Takes the text to lead with."""
        parts = []
        if self.withheld:
            parts.append(f"{self.withheld} file(s) saw named were kept out of it")
        if self.unsaved:
            parts.append(f"{self.unsaved} could not be put on the branch and stay on disk only")
        if self.unread:
            parts.append(f"{self.unread} in directories saw does not read were left off it "
                         "and stay on disk only")
        return f"{lead}{'; '.join(parts)}" if parts else ""


class WorkingTreeUnlisted(OSError):
    """git could not list the working tree, so nothing can be said about what it holds."""


def can_hold(repo: str | Path) -> str:
    """Whether a run could put this working tree on a branch. Takes the repository. Returns "" when
    it could, and otherwise the reason it could not."""
    if uncommitted_paths(repo) is None:
        return "git could not list the working tree"
    if not stdout(repo, ["rev-parse", "HEAD"]).strip():
        return "this repository has no commit to branch from"
    return ""


def uncommitted(repo: str | Path) -> list[str]:
    """What the working tree holds that is not committed.

    Takes the repository. Returns the paths as git stores them, both ends of a rename among them;
    an ignored path is not. Raises `WorkingTreeUnlisted` when git could not answer.
    """
    found = uncommitted_paths(repo)
    if found is None:
        raise WorkingTreeUnlisted("git could not list the working tree")
    return [os.fsdecode(path) for path in found]


@dataclass
class Snapshot:
    """The working tree as it stood, held in this run's own index until it is committed."""

    repo: str | Path
    head: str = ""
    index: Path | None = None
    staged: list[str] = field(default_factory=list)
    unsaved: list[str] = field(default_factory=list)
    withheld: list[str] = field(default_factory=list)
    reason: str = ""
    blocked: bool = False

    @property
    def env(self) -> dict:
        """The environment naming this snapshot's index."""
        return {"GIT_INDEX_FILE": str(self.index / "index")}

    def release(self) -> None:
        """Give up the index this snapshot was held in."""
        if self.index is not None:
            scratch.release_path(self.index)
            self.index = None


def capture(repo: str | Path, only: list[str] | None = None,
            skip: list[str] | None = None, confirms=None,
            limit: int = MAX_SAVED_BYTES) -> Snapshot:
    """Hold the working tree as it stands, in this run's own index.

    Takes the repository, optionally the only paths to hold, the paths to leave out, and
    `confirms(bytes, path, is_symlink) -> bool` and the largest file to save. Returns the snapshot; `reason`
    names what stopped it. A path left out, and a file whose bytes `confirms`, is never written
    into git. The caller releases
    it, and `branch()` turns it into a local branch.
    """
    entries = uncommitted(repo)
    if only is not None:
        wanted = set(only)
        entries = [p for p in entries if p in wanted]
    if skip:
        away = set(skip)
        entries = [p for p in entries if p not in away]
    head = stdout(repo, ["rev-parse", "HEAD"]).strip()
    if not head:
        return Snapshot(repo=repo, reason="this repository has no commit to branch from")
    index = scratch.new_dir("the uncommitted-work branch")
    snapshot = Snapshot(repo=repo, head=head, index=index)
    if not run_ok(repo, ["read-tree", head], env=snapshot.env):
        snapshot.reason, snapshot.blocked = "the current commit could not be read", True
        return snapshot
    snapshot.unsaved, snapshot.withheld = _stage(repo, entries, snapshot.env, confirms, limit)
    if entries and len(snapshot.unsaved) == len(entries):
        snapshot.reason, snapshot.blocked = "the working tree could not be staged", True
        return snapshot
    snapshot.staged = [p for p in entries if p not in set(snapshot.unsaved)
                       and p not in set(snapshot.withheld) and _on_disk(Path(repo) / p)]
    return snapshot


def branch(snapshot: Snapshot, condemned: list[str] | None = None,
           cleaned: list[str] | None = None, unread: int = 0, confirms=None) -> Preserved:
    """Commit a snapshot to a local branch, leaving HEAD, the index and the files alone.

    Takes the snapshot, the paths the scan named, the named paths this run cleaned in place, and
    how many paths were left off because the scan does not read them, and the check a file's
    bytes pass before they are written. Returns what was put aside.
    A cleaned path goes on the branch as it now stands; every other named path leaves the index
    first, so the branch carries none of them. The count is of the operator's own files.
    """
    unsaved = len(snapshot.unsaved)
    if snapshot.reason:
        return Preserved(reason=snapshot.reason, blocked=snapshot.blocked, unsaved=unsaved,
                         unread=unread)
    repo, env = snapshot.repo, snapshot.env
    rewritten = sorted(set(cleaned or ()) & set(condemned or ()))
    refused, held_back = _stage(repo, rewritten, env, confirms)
    unstaged = set(refused) | set(held_back)
    named = sorted(set(condemned or ()) - (set(rewritten) - unstaged))
    dropped = _drop(repo, named, env)
    if dropped is not None:
        dropped += len(set(snapshot.withheld) - set(named))
    if dropped is None:
        return Preserved(reason="a path the scan named could not be kept out", blocked=True,
                         unsaved=unsaved, unread=unread)
    kept = [p for p in snapshot.staged if p not in set(named)]
    if not kept:
        return Preserved(withheld=dropped, unsaved=unsaved, unread=unread)
    res = run(repo, ["write-tree"], env=env)
    if res is None or res.returncode != 0:
        return Preserved(reason="the working tree could not be written", blocked=True,
                         withheld=dropped, unsaved=unsaved, unread=unread)
    tree = (res.stdout or "").strip()
    changed = stdout(repo, ["diff-tree", "--name-only", "-r", "-z", snapshot.head, tree])
    theirs = set(changed.split("\0")) - {""} - set(named) - (set(rewritten) - set(snapshot.staged))
    files = len(theirs)
    if not files:
        return Preserved(withheld=dropped, unsaved=unsaved, unread=unread)
    res = run(repo, ["commit-tree", tree, "-p", snapshot.head, "-m", MESSAGE])
    if res is None or res.returncode != 0:
        return Preserved(reason=f"the branch could not be committed ({_why(res)})", blocked=True,
                         withheld=dropped, unsaved=unsaved, unread=unread)
    name = _free_name(repo)
    if not run_ok(repo, ["update-ref", f"refs/heads/{name}", (res.stdout or "").strip()]):
        return Preserved(reason="the branch could not be created", blocked=True,
                         withheld=dropped, unsaved=unsaved, unread=unread)
    return Preserved(branch=name, files=files, withheld=dropped, unsaved=unsaved,
                     unread=unread)


def preserve(repo: str | Path, remembered: list[str] | None = None, *,
             condemned: list[str] | None = None, removed: list[str] | None = None,
             cleaned: list[str] | None = None, unread: list[str] | None = None,
             confirms=None, limit: int = MAX_SAVED_BYTES) -> Preserved:
    """Put the working tree on a local branch of its own, leaving the repository as it was.

    Takes the repository, optionally the paths to consider, the paths the scan named, the paths
    this run removed, the named paths it cleaned in place, the paths the scan does not read, and
    `confirms(bytes, path, is_symlink) -> bool` and the largest file to save. Returns what was put aside;
    neither a removed nor an unread path, nor a file whose bytes `confirms`, is read into git.
    """
    left_off = set(unread or ()) - set(condemned or ())
    snapshot = capture(repo, remembered, skip=[*(removed or ()), *left_off], confirms=confirms,
                       limit=limit)
    try:
        return branch(snapshot, condemned, cleaned, len(left_off), confirms)
    finally:
        snapshot.release()


def _on_disk(path: Path) -> bool:
    """Whether a path is still there to be saved. Takes the path. Returns the answer."""
    try:
        return path.exists() or path.is_symlink()
    except OSError:
        return False


def _free_name(repo: str | Path) -> str:
    """A branch name no ref holds yet. Takes the repository. Returns the name."""
    stamp = time.strftime("%Y-%m-%d-%H%M%S")
    for suffix in ("", *(f"-{n}" for n in range(2, 100))):
        name = f"{BRANCH_PREFIX}{stamp}{suffix}"
        if not run_ok(repo, ["show-ref", "--verify", "--quiet", f"refs/heads/{name}"]):
            return name
    return f"{BRANCH_PREFIX}{stamp}-{os.getpid()}"


def _entry(path: Path, limit: int = MAX_SAVED_BYTES) -> tuple[str, bytes] | None:
    """The mode git records for a file and the bytes it stores. Takes the file and the largest
    file to read. Returns None when it is not a regular file or a link, is larger than `limit`,
    or cannot be read."""
    try:
        info = os.lstat(path)
        if stat.S_ISLNK(info.st_mode):
            return "120000", os.fsencode(os.readlink(path))
        if not stat.S_ISREG(info.st_mode) or info.st_size > limit:
            return None
        with open(path, "rb") as fh:
            return ("100755" if info.st_mode & stat.S_IXUSR else "100644"), fh.read()
    except OSError:
        return None


def _no_object(repo: str | Path) -> bytes:
    """The all-zero object id of `repo`'s hash, which removes an index entry. Takes the
    repository. Returns it."""
    return b"0" * (len(stdout(repo, ["rev-parse", "HEAD"]).strip()) or 40)


def _stage(repo: str | Path, paths: list[str], env: dict, confirms=None,
           limit: int = MAX_SAVED_BYTES) -> tuple[list[str], list[str]]:
    """Stage the working tree into this run's own index, as the bytes on disk.

    Takes the repository, the paths, the environment naming that index,
    `confirms(bytes, path, is_symlink) -> bool` and the largest file to read. Returns the paths that could not
    be staged, and the paths held
    back because their bytes confirm, which are never written into git. A path no longer on disk
    leaves the index.
    """
    refused: list[str] = []
    withheld: list[str] = []
    lines: list[bytes] = []
    zero = _no_object(repo)
    for path in paths:
        target = Path(repo) / path
        if not (os.path.lexists(target)):
            lines.append(b"0 %s\t%s" % (zero, os.fsencode(path)))
            continue
        found = _entry(target, limit)
        if found is None:
            refused.append(path)
            continue
        if confirms is not None and confirms(found[1], path, found[0] == "120000"):
            withheld.append(path)
            continue
        mode, data = found
        oid = stdout_bytes_fed(repo, ["hash-object", "-w", "--no-filters", "--stdin"], data)
        if oid is None or not oid.strip():
            refused.append(path)
            continue
        lines.append(b"%s %s\t%s" % (mode.encode(), oid.strip(), os.fsencode(path)))
    for start in range(0, len(lines), _BATCH):
        feed = b"\0".join(lines[start:start + _BATCH]) + b"\0"
        if stdout_bytes_fed(repo, ["update-index", "-z", "--index-info"], feed, env=env) is None:
            return list(paths), withheld
    return refused, withheld


def _drop(repo: str | Path, paths: list[str], env: dict) -> int | None:
    """Take paths out of this run's own index, leaving the files on disk.

    Takes the repository, the paths and the environment naming that index. Returns how many the
    index held, or None when git failed.
    """
    gone = 0
    zero = _no_object(repo)
    for start in range(0, len(paths), _BATCH):
        batch = paths[start:start + _BATCH]
        held = stdout_bytes_fed(repo, ["ls-files", "-z", "--", *batch], b"", env=env)
        if held is None:
            return None
        present = [p for p in held.split(b"\0") if p]
        gone += len(present)
        if not present:
            continue
        feed = b"\0".join(b"0 %s\t%s" % (zero, p) for p in present) + b"\0"
        if stdout_bytes_fed(repo, ["update-index", "-z", "--index-info"], feed, env=env) is None:
            return None
    return gone


def _why(res) -> str:
    """The reason a git command gave. Takes its result. Returns a short line."""
    if res is None:
        return "git could not run"
    return ((res.stderr or "").strip().splitlines() or ["no reason given"])[0][:120]
