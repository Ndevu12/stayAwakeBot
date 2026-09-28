#!/usr/bin/env python3
"""A checkout saw builds a fix in: a repository saw owns, reading the operator's objects through
`alternates`, with the base commit's raw bytes on disk and the operator's branches, remote
branches and tags copied in as refs so a scan of it sees the history a scan of theirs would.

Nothing runs in the operator's repository but reads and `update-ref`: the branch is set there
when the checkout is made and moved when a commit lands (`land`), after the commit's objects
have been handed over (`transfer.adopt_objects`).
"""
from __future__ import annotations

import contextlib
import shutil
import threading
from dataclasses import dataclass, field
from pathlib import Path

from stayawake.lib.git import owned
from stayawake.lib.git.borrowed import borrow
from stayawake.lib.git.run import SAW_OWNED, run_ok
from stayawake.lib.git.write.branch import refs_under, set_branch, update_refs
from stayawake.lib.git.write.checkouts import checked_out_at
from stayawake.lib.git.write.transfer import adopt_objects, resolved

_RAW_BYTES_ATTRIBUTES = "* -text -eol -filter -ident -working-tree-encoding\n"
_MIRRORED_REFS = ("refs/heads", "refs/remotes", "refs/tags")


@dataclass
class SawCheckout:
    """A live fix checkout: where it is, whose repository it stands for, and its branch."""
    path: Path
    operator_repo: Path
    gitdir: Path
    branch: str
    landed: str
    _closing: contextlib.ExitStack = field(repr=False, default_factory=contextlib.ExitStack)


_held: dict[Path, SawCheckout] = {}
_lock = threading.Lock()


def held_checkout(path: str | Path) -> SawCheckout | None:
    """The live checkout at `path`, or None when saw made none there."""
    with _lock:
        return _held.get(Path(path).resolve())


def _build(repo: Path, path: Path, branch: str, base: str, stack: contextlib.ExitStack) -> Path | None:
    borrowed = stack.enter_context(borrow(repo))
    gitdir = borrowed.path
    (gitdir / "info").mkdir(exist_ok=True)
    (gitdir / "info" / "attributes").write_text(_RAW_BYTES_ATTRIBUTES, encoding="utf-8")
    mirrored = refs_under(repo, *_MIRRORED_REFS)
    mirrored.pop(f"refs/heads/{branch}", None)
    if not update_refs(gitdir, [(ref, oid, "") for ref, oid in mirrored.items()],
                       context=SAW_OWNED):
        return None
    steps = (["update-ref", f"refs/heads/{branch}", base],
             ["symbolic-ref", "HEAD", f"refs/heads/{branch}"],
             ["config", "core.bare", "false"],
             ["config", "core.worktree", str(path)])
    if not all(run_ok(gitdir, step, context=SAW_OWNED) for step in steps):
        return None
    path.mkdir(parents=True, exist_ok=True)
    (path / ".git").write_text(f"gitdir: {gitdir}\n", encoding="utf-8")
    owned.own(path)
    stack.callback(owned.disown, path)
    if not run_ok(path, ["read-tree", "-u", "--reset", base], context=SAW_OWNED):
        return None
    return gitdir


def add_worktree(repo: str | Path, path: str | Path, branch: str, baseref: str) -> bool:
    """Make a fix checkout of `baseref` at `path` on `branch`, and set `branch` in `repo` to it.
    Takes the operator repository, an empty directory, the branch and the ref to start from.
    Refuses a branch one of the operator's own checkouts has checked out. Returns whether the
    checkout is ready."""
    repo, path = Path(repo), Path(path).resolve()
    with _lock:
        stale = _held.pop(path, None)
    if stale is not None:
        stale._closing.close()
    base = resolved(repo, baseref)
    if not base:
        return False
    try:
        if checked_out_at(repo, branch) is not None:
            return False
    except OSError:
        return False
    stack = contextlib.ExitStack()
    try:
        gitdir = _build(repo, path, branch, base, stack)
    except OSError:
        gitdir = None
    if gitdir is None or not set_branch(repo, branch, base):
        stack.close()
        return False
    with _lock:
        _held[path] = SawCheckout(path, repo, gitdir, branch, base, stack)
    return True


def land(path: str | Path) -> str:
    """Hand the checkout's current commit to the operator repository and move its branch there.
    Returns "" once the branch points at it, else why not."""
    checkout = held_checkout(path)
    if checkout is None:
        return f"{path} is not a checkout saw made"
    tip = resolved(checkout.gitdir, "HEAD", context=SAW_OWNED)
    if not tip:
        return "the fix commit could not be read"
    if tip == checkout.landed:
        return ""
    try:
        if checked_out_at(checkout.operator_repo, checkout.branch) is not None:
            return f"'{checkout.branch}' is checked out in the repository"
    except OSError as exc:
        return str(exc)
    failure = adopt_objects(checkout.operator_repo, checkout.gitdir, [tip], [checkout.landed])
    if failure:
        return failure
    if not update_refs(checkout.operator_repo,
                       [(f"refs/heads/{checkout.branch}", tip, checkout.landed)]):
        return f"'{checkout.branch}' moved in the repository while the fix was built"
    checkout.landed = tip
    return ""


def remove_worktree(repo: str | Path, path: str | Path) -> bool:
    """Tear down the fix checkout at `path`, leaving its branch in `repo`. Returns whether it is
    gone."""
    resolved_path = Path(path).resolve()
    with _lock:
        checkout = _held.pop(resolved_path, None)
    if checkout is not None:
        checkout._closing.close()
    shutil.rmtree(resolved_path, ignore_errors=True)
    return not resolved_path.exists()


def release_worktree(repo: str | Path):
    """Build the teardown for a fix checkout of this repo. Takes the repo. Returns a callable that
    takes the path and returns "" when the checkout is gone, else why it is not."""
    def teardown(path: Path) -> str:
        remove_worktree(repo, path)
        return "" if not Path(path).exists() else f"the fix checkout at {path} could not be removed"
    return teardown
