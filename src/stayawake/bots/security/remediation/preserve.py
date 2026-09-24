#!/usr/bin/env python3
"""Put the operator's uncommitted work on a local branch of its own, once it is clean."""
from __future__ import annotations

import os
import time
from dataclasses import dataclass, field
from pathlib import Path

from stayawake.lib.git.run import run, run_ok, stdout
from stayawake.utils import scratch

BRANCH_PREFIX = "saw/uncommitted-"
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

    def note(self) -> str:
        """Describe what was put aside, for the operator. Returns "" when nothing was."""
        if self.reason:
            return f"could not put your uncommitted work on a branch: {self.reason}"
        if not self.branch:
            return self._withheld_note()
        return (f"{self.files} uncommitted file(s) saved on the local branch "
                f"{self.branch} — it is never pushed") + self._withheld_note("; ")

    def _withheld_note(self, lead: str = "") -> str:
        """The counts that stayed out of the branch. Takes the text to lead with."""
        parts = []
        if self.withheld:
            parts.append(f"{self.withheld} file(s) saw named were kept out of it")
        if self.unsaved:
            parts.append(f"{self.unsaved} could not be put on the branch and stay on disk only")
        return f"{lead}{'; '.join(parts)}" if parts else ""


def uncommitted(repo: str | Path) -> list[str]:
    """What the working tree holds that is not committed.

    Takes the repository. Returns the paths as git stores them rather than as it prints them, both
    ends of a rename among them; an ignored path is not.
    """
    out = stdout(repo, ["status", "--porcelain", "-z", "--untracked-files=all"])
    fields = out.split("\0")
    found: list[str] = []
    index = 0
    while index < len(fields):
        record = fields[index]
        index += 1
        if len(record) < 4:
            continue
        found.append(record[3:])
        if ("R" in record[:2] or "C" in record[:2]) and index < len(fields):
            found.append(fields[index])
            index += 1
    return found


@dataclass
class Snapshot:
    """The working tree as it stood, held in this run's own index until it is committed."""

    repo: str | Path
    head: str = ""
    index: Path | None = None
    staged: list[str] = field(default_factory=list)
    unsaved: list[str] = field(default_factory=list)
    reason: str = ""
    blocked: bool = False

    @property
    def env(self) -> dict:
        """The environment naming this snapshot's index."""
        return dict(os.environ, GIT_INDEX_FILE=str(self.index / "index"))

    def release(self) -> None:
        """Give up the index this snapshot was held in."""
        if self.index is not None:
            scratch.release_path(self.index)
            self.index = None


def capture(repo: str | Path, only: list[str] | None = None,
            skip: list[str] | None = None) -> Snapshot:
    """Hold the working tree as it stands, without writing anything to the repository.

    Takes the repository, optionally the only paths to hold, and the paths to leave out. Returns
    the snapshot; `reason` names what stopped it. A path left out is never read into git at all.
    The caller releases it, and `branch()` turns it into a local branch.
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
    snapshot.unsaved = _stage(repo, entries, snapshot.env)
    if entries and len(snapshot.unsaved) == len(entries):
        snapshot.reason, snapshot.blocked = "the working tree could not be staged", True
        return snapshot
    snapshot.staged = [p for p in entries if p not in set(snapshot.unsaved)]
    return snapshot


def branch(snapshot: Snapshot, condemned: list[str] | None = None) -> Preserved:
    """Commit a snapshot to a local branch, leaving HEAD, the index and the files alone.

    Takes the snapshot and the paths the scan named. Returns what was put aside. A named path
    leaves the index first, so the branch carries none of them.
    """
    unsaved = len(snapshot.unsaved)
    if snapshot.reason:
        return Preserved(reason=snapshot.reason, blocked=snapshot.blocked, unsaved=unsaved)
    repo, env = snapshot.repo, snapshot.env
    named = sorted(set(condemned or ()))
    dropped = _drop(repo, named, env)
    if dropped is None:
        return Preserved(reason="a path the scan named could not be kept out", blocked=True,
                         unsaved=unsaved)
    kept = [p for p in snapshot.staged if p not in set(named)]
    if not kept:
        return Preserved(withheld=dropped, unsaved=unsaved)
    res = run(repo, ["write-tree"], env=env)
    if res is None or res.returncode != 0:
        return Preserved(reason="the working tree could not be written", blocked=True,
                         withheld=dropped, unsaved=unsaved)
    tree = (res.stdout or "").strip()
    res = run(repo, ["commit-tree", tree, "-p", snapshot.head, "-m", MESSAGE])
    if res is None or res.returncode != 0:
        return Preserved(reason=f"the branch could not be committed ({_why(res)})", blocked=True,
                         withheld=dropped, unsaved=unsaved)
    name = _free_name(repo)
    if not run_ok(repo, ["update-ref", f"refs/heads/{name}", (res.stdout or "").strip()]):
        return Preserved(reason="the branch could not be created", blocked=True,
                         withheld=dropped, unsaved=unsaved)
    return Preserved(branch=name, files=len(kept), withheld=dropped, unsaved=unsaved)


def preserve(repo: str | Path, remembered: list[str] | None = None, *,
             condemned: list[str] | None = None) -> Preserved:
    """Put the working tree on a local branch of its own, leaving the repository as it was.

    Takes the repository, optionally the paths to consider and the paths the scan named. Returns
    what was put aside. A path left out stays where it is on disk.
    """
    snapshot = capture(repo, remembered)
    try:
        return branch(snapshot, condemned)
    finally:
        snapshot.release()


def _free_name(repo: str | Path) -> str:
    """A branch name no ref holds yet. Takes the repository. Returns the name."""
    stamp = time.strftime("%Y-%m-%d-%H%M%S")
    for suffix in ("", *(f"-{n}" for n in range(2, 100))):
        name = f"{BRANCH_PREFIX}{stamp}{suffix}"
        if not run_ok(repo, ["show-ref", "--verify", "--quiet", f"refs/heads/{name}"]):
            return name
    return f"{BRANCH_PREFIX}{stamp}-{os.getpid()}"


def _stage(repo: str | Path, paths: list[str], env: dict) -> list[str]:
    """Stage the working tree into this run's own index.

    Takes the repository, the paths to stage and the environment naming that index. Returns the
    paths that did not stage; a batch that git refuses is retried one path at a time, so one of
    them cannot cost the rest.
    """
    refused: list[str] = []
    for start in range(0, len(paths), _BATCH):
        batch = paths[start:start + _BATCH]
        if run_ok(repo, ["add", "-A", "--", *batch], env=env):
            continue
        for path in batch:
            if not run_ok(repo, ["add", "-A", "--", path], env=env):
                refused.append(path)
    return refused


def _drop(repo: str | Path, paths: list[str], env: dict) -> int | None:
    """Take paths out of this run's own index, leaving the files on disk.

    Takes the repository, the paths and the environment naming that index. Returns how many the
    index held, or None when a batch failed.
    """
    gone = 0
    for start in range(0, len(paths), _BATCH):
        batch = paths[start:start + _BATCH]
        res = run(repo, ["rm", "--cached", "-r", "-f", "--ignore-unmatch", "--", *batch], env=env)
        if res is None or res.returncode != 0:
            return None
        gone += sum(1 for line in (res.stdout or "").splitlines() if line.startswith("rm "))
    return gone


def _why(res) -> str:
    """The reason a git command gave. Takes its result. Returns a short line."""
    if res is None:
        return "git could not run"
    return ((res.stderr or "").strip().splitlines() or ["no reason given"])[0][:120]
