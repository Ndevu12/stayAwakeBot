#!/usr/bin/env python3
"""Put the operator's uncommitted work on a local branch of its own, once it is clean."""
from __future__ import annotations

import os
import time
from dataclasses import dataclass
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
    """What a run put aside. `branch` is empty when nothing was, and `reason` names what stopped it."""

    branch: str = ""
    files: int = 0
    reason: str = ""
    withheld: int = 0

    def note(self) -> str:
        """Describe what was put aside, for the operator. Returns "" when nothing was."""
        if self.reason:
            return f"could not put your uncommitted work on a branch: {self.reason}"
        if not self.branch:
            return self._withheld_note()
        return (f"{self.files} uncommitted file(s) saved on the local branch "
                f"{self.branch} — it is never pushed") + self._withheld_note("; ")

    def _withheld_note(self, lead: str = "") -> str:
        """The count that stayed out of git. Takes the text to lead with. Returns "" when none did."""
        if not self.withheld:
            return ""
        return f"{lead}{self.withheld} file(s) were left on disk and not copied into git"


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


def preserve(repo: str | Path, remembered: list[str] | None = None, *,
             condemned: list[str] | None = None) -> Preserved:
    """Commit the working tree to a local branch, leaving HEAD, the index and the files alone.

    Takes the repository and, optionally, the paths to consider and the paths the scan named.
    Returns what was put aside — an empty `Preserved` when nothing is still uncommitted, or one
    carrying `reason` when it could not be done. A path the scan named stays on disk and out of
    the branch.
    """
    entries = uncommitted(repo)
    if remembered is not None:
        wanted = set(remembered)
        entries = [p for p in entries if p in wanted]
    named = set(condemned or ())
    changed, withheld = [], 0
    for path in entries:
        if path in named:
            withheld += 1
            continue
        changed.append(path)
    if not changed and not named:
        return Preserved(withheld=withheld)
    head = stdout(repo, ["rev-parse", "HEAD"]).strip()
    if not head:
        return Preserved(reason="this repository has no commit to branch from", withheld=withheld)
    index_dir = scratch.new_dir("the uncommitted-work branch")
    env = dict(os.environ, GIT_INDEX_FILE=str(index_dir / "index"))
    try:
        if not run_ok(repo, ["read-tree", head], env=env):
            return Preserved(reason="the current commit could not be read", withheld=withheld)
        if not _stage(repo, changed, env):
            return Preserved(reason="the working tree could not be staged", withheld=withheld)
        dropped = _drop(repo, sorted(named), env)
        if dropped is None:
            return Preserved(reason="a path the scan named could not be kept out", withheld=withheld)
        withheld += dropped
        if not changed and not dropped:
            return Preserved(withheld=withheld)
        res = run(repo, ["write-tree"], env=env)
        if res is None or res.returncode != 0:
            return Preserved(reason="the working tree could not be written", withheld=withheld)
        tree = (res.stdout or "").strip()
        res = run(repo, ["commit-tree", tree, "-p", head, "-m", MESSAGE])
        if res is None or res.returncode != 0:
            return Preserved(reason=f"the branch could not be committed ({_why(res)})", withheld=withheld)
        commit = (res.stdout or "").strip()
        branch = f"{BRANCH_PREFIX}{time.strftime('%Y-%m-%d-%H%M%S')}"
        if not run_ok(repo, ["update-ref", f"refs/heads/{branch}", commit]):
            return Preserved(reason="the branch could not be created", withheld=withheld)
        return Preserved(branch=branch, files=len(changed), withheld=withheld)
    finally:
        scratch.release_path(index_dir)


def _stage(repo: str | Path, paths: list[str], env: dict) -> bool:
    """Stage the working tree into this run's own index.

    Takes the repository, the paths to stage and the environment naming that index. Returns whether
    every batch staged.
    """
    for start in range(0, len(paths), _BATCH):
        batch = paths[start:start + _BATCH]
        if not run_ok(repo, ["add", "-A", "--", *batch], env=env):
            return False
    return True


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
