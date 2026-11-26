#!/usr/bin/env python3
"""Carry an update that stopped for conflicts in saw's holding copy into the open folder, and put the
open folder back on a tree saw let in.

The open folder is not written until `apply`. The git saw runs here uses the contexts that keep a
repository's hooks, filters and configuration from deciding what runs.
"""
from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from stayawake.lib.git import conflicted, holding_directory, owned, subcommand_options
from stayawake.lib.git.query import files_brought
from stayawake.lib.git.run import SAW_OWNED, UNTRUSTED, run_ok, stdout
from stayawake.lib.git.typed_command import TypedCommand
from stayawake.lib.git.write.branch import update_refs
from stayawake.lib.git.write.checkouts import Checkout
from stayawake.lib.git.write.transfer import adopt_objects, missing_objects
from stayawake.lib.git.write.working_tree import PreparedMove, changes_in_the_way, uncommitted_paths
from stayawake.utils import pathsafe


WRITE_LEFT_PART_WAY = ("the update could not be written into the open folder, and the folder may have "
                       "changed; check it with git status")
PUT_BACK_LEFT_PART_WAY = "the folder could not be put back, and it may have changed; check it with git status"
UNCARRIED_CONFLICTS = "uncarried-conflicts"


@dataclass(frozen=True)
class Arrived:
    """What a command produced outside the open folder. `written` holds the sha256 each file it
    writes into the folder must hold, by path. `versions` names other versions of files the update
    brings, as (commit, paths), and `stopped` the merge or rebase that stopped for conflicts, when
    it did. `bring_in` is the git subcommand and commit that bring in exactly the checked commit,
    for a pull that stopped for conflicts that cannot be carried."""

    root: Path
    paths: tuple[str, ...]
    mode: str
    commit: str
    base: str
    head: str
    refs: tuple[tuple[str, str, str], ...]
    written: tuple[tuple[str, str], ...] = ()
    versions: tuple[tuple[str, tuple[str, ...]], ...] = ()
    stopped: "conflicted.Stopped | None" = None
    bring_in: tuple[str, ...] = ()


def continues_a_rebase(command: TypedCommand) -> bool:
    """Tell whether a git command continues or skips ahead in a rebase in progress. Takes the
    command. Returns the answer."""
    return command.sub == "rebase" and bool(
        {"--continue", "--skip"} & set(subcommand_options.read("rebase", list(command.rest)).names()))


def rebase_left(repo: Path) -> "tuple[str, tuple[str, ...], bool] | str | None":
    """Read what a rebase in progress in `repo` has left to do. Takes the open folder. Returns the
    commit it replays onto, the commits it has left and whether its todo holds nothing but picks;
    None when no rebase is in progress, or a sentence when its state cannot be read."""
    gitdir = _git_dir(Path(repo))
    if gitdir is None:
        return "the open folder is not a git checkout"
    if os.path.lexists(gitdir / "rebase-apply"):
        return "the rest of this rebase cannot be checked"
    if not os.path.lexists(gitdir / "rebase-merge"):
        return None
    onto = pathsafe.read_regular_no_follow(gitdir / "rebase-merge" / "onto", 4096)
    todo = pathsafe.read_regular_no_follow(gitdir / "rebase-merge" / "git-rebase-todo", 64 << 20)
    if onto is None or todo is None:
        return "the rest of this rebase cannot be checked"
    return onto.decode(errors="replace").strip(), conflicted.picks_in(todo), conflicted.only_picks(todo)


def claim(into: Path) -> None:
    """Mark the holding repository and its work tree as ones this process may write. Takes the
    holding directory. Returns nothing."""
    for made in (Path(into) / holding_directory.REPOSITORY, Path(into) / holding_directory.WORK_TREE):
        if made.is_dir():
            owned.own(made)


def apply(repo: Path, into: Path, arrived: Arrived) -> str:
    """Carry an update that stopped for conflicts into `repo`. Takes the open folder, the holding
    directory and what prepare stored. Returns "" when the folder holds it, else a sentence that
    also names a folder that may have changed."""
    repo = Path(repo).resolve()
    claim(into)
    if arrived.mode != "conflicts":
        return conflicted.CANNOT_CARRY
    return _apply_conflicts(repo, Path(into) / holding_directory.REPOSITORY, arrived)


def arrived_with_conflicts(work: Path, holding: Path, base: str, kind: str) -> "Arrived | str":
    """Describe what a merge or rebase stopped for conflicts in the holding copy brings. Takes the
    holding work tree, its git directory, the open folder's commit and the command's kind. Returns
    what arrived: the conflicts to carry into the folder, or an update to check that stays out of
    it. Returns a sentence when neither can be described."""
    stopped = conflicted.read(work, holding, base)
    if isinstance(stopped, str):
        return _arrived_uncarried(work, holding, base, kind)
    changed = files_brought(work, base, stopped.landed, context=SAW_OWNED)
    names = None if changed is None else tuple(dict.fromkeys((*changed, *stopped.conflicts)))
    versions = conflicted.versions_brought(work, base, (stopped.incoming,), stopped.head, stopped.picks)
    if names is None or versions is None:
        return "the files the update brings could not be listed"
    return Arrived(work, names, "conflicts", stopped.incoming, base, _head_text(holding), (),
                   versions=versions, stopped=stopped)


def _arrived_uncarried(work: Path, holding: Path, base: str, kind: str) -> "Arrived | str":
    """Describe a stop whose conflicts cannot be carried into the folder: an update to check that
    stays out of it. Takes the holding work tree, its git directory, the open folder's commit and
    the command's kind. Returns what arrived, or a sentence when its incoming commits cannot be
    read."""
    incoming = conflicted.incoming_commits(holding)
    head = stdout(work, ["rev-parse", "--verify", "--quiet", "HEAD"], context=SAW_OWNED).strip()
    versions = conflicted.versions_brought(work, base, incoming, head) if incoming and head else None
    if versions is None:
        return conflicted.CANNOT_CARRY
    bring_in = (conflicted.operation_in(holding), incoming[0]) if kind == "pull" else ()
    return Arrived(work, (), UNCARRIED_CONFLICTS, incoming[0], base, _head_text(holding), (), versions=versions,
                   bring_in=bring_in)


def _apply_conflicts(repo: Path, bare: Path, arrived: Arrived) -> str:
    """Carry a merge or rebase that stopped for conflicts into `repo`: the checked files, the
    conflicted index entries and the operation's state. Takes the open folder, the holding
    repository and what prepare stored. Returns "" when the folder holds it,
    else a sentence that also names a folder that may have changed."""
    stopped = conflicted.read(arrived.root, bare, arrived.base)
    if isinstance(stopped, str) or stopped != arrived.stopped:
        return "the holding directory no longer holds the checked update. Run the command again"
    if stdout(repo, ["rev-parse", "--verify", "--quiet", "HEAD"], context=UNTRUSTED).strip() != arrived.base:
        return "the open folder changed while the update was checked"
    gitdir = _git_dir(repo)
    if gitdir is None:
        return "the open folder is not a git checkout"
    head = _head_text(repo)
    if stopped.operation == conflicted.REBASE and conflicted.branch_named(stopped.files) != (
            head.removeprefix("ref: ").strip() if head.startswith("ref: ") else "detached HEAD"):
        return "the open folder changed while the update was checked"
    why = adopt_objects(repo, bare, [stopped.incoming, stopped.landed, stopped.head], [arrived.base])
    if why:
        return f"the update could not be copied into the open folder: {why}"
    if not conflicted.all_commits(repo, conflicted.commits_named(stopped.files) | {stopped.head}):
        return "the update could not be copied into the open folder"
    stages = stopped.entries_by_path()
    if missing_objects(repo, [oid.decode() for entries in stages.values() for _, oid, _ in entries]) != []:
        return "the update could not be copied into the open folder"
    way = changes_in_the_way(repo, stopped.landed)
    before = uncommitted_paths(repo)
    if way is None or before is None:
        return "the folder was not changed: its uncommitted work could not be read"
    if way.blocking or way.carryable or set(before) & set(stages):
        return "uncommitted work would be overwritten, so the folder was not changed"
    move = PreparedMove(repo, Checkout(repo, gitdir), arrived.base, stopped.landed,
                        conflict_stages=stages)
    if not move.prepare():
        move.release()
        return "the update could not be written into the open folder"
    placed = conflicted.place(gitdir, stopped.files)
    if placed is None:
        move.release()
        return "the update could not be written into the open folder"
    expected = {os.fsencode(rel): digest for rel, digest in arrived.written}
    if move.apply(expected) and (stopped.operation == conflicted.MERGE or _write_head(gitdir, stopped.head)):
        move.release()
        return ""
    move.release()
    if placed.take_back() and move.undo(before):
        return "the update could not be written into the open folder"
    return WRITE_LEFT_PART_WAY


def restore(repo: Path, commit: str) -> str:
    """Put the open folder back on `commit`, a tree saw let in, keeping uncommitted work. Takes the
    open folder and the commit, which must already be in the repository. Returns "" when the folder
    is on it, else a sentence that also names a folder that may have changed. The current branch is
    moved to the commit and HEAD stays attached."""
    repo = Path(repo).resolve()
    gitdir = _git_dir(repo)
    if gitdir is None:
        return "the open folder is not a git checkout"
    if not run_ok(repo, ["cat-file", "-e", f"{commit}^{{commit}}"], context=UNTRUSTED):
        return "saw does not have the tree to put back"
    base = stdout(repo, ["rev-parse", "--verify", "--quiet", "HEAD"], context=UNTRUSTED).strip()
    if not base:
        return "the open folder has no commit to put back from"
    way = changes_in_the_way(repo, commit)
    if way is None:
        return "saw could not tell whether uncommitted work could be kept"
    if way.blocking:
        return "uncommitted work would be overwritten, so the folder was not changed"
    head = _head_text(repo)
    branch = head[len("ref: "):].strip() if head.startswith("ref: ") else None
    keep = frozenset(path.encode() for path in way.carryable)
    before = uncommitted_paths(repo)
    if before is None:
        return "the folder was not changed: its uncommitted work could not be read"
    move = PreparedMove(repo, Checkout(repo, gitdir), base, commit, keep=keep)
    if not move.prepare():
        move.release()
        return "the folder could not be put back"
    if branch and not update_refs(repo, [(branch, commit, base)]):
        move.release()
        return "the open folder changed while saw was putting it back"
    if not (move.apply() and _write_head(gitdir, head if branch else commit)):
        move.release()
        if branch:
            update_refs(repo, [(branch, base, commit)])
        if move.undo(before):
            return "the folder could not be put back"
        return PUT_BACK_LEFT_PART_WAY
    move.release()
    return ""


def _head_text(repo: Path) -> str:
    gitdir = _git_dir(repo)
    return _read(gitdir / "HEAD").strip() if gitdir else ""


def _git_dir(repo: Path) -> "Path | None":
    named = stdout(repo, ["rev-parse", "--path-format=absolute", "--git-dir"], context=UNTRUSTED).strip()
    if not named:
        named = stdout(repo, ["rev-parse", "--path-format=absolute", "--git-dir"], context=SAW_OWNED).strip()
    if not named or "\n" in named:
        return None
    path = Path(named)
    return path if path.is_dir() else None


def _write_head(gitdir: Path, text: str) -> bool:
    if _read(gitdir / "HEAD").strip() == text.strip():
        return True
    temporary = gitdir / "HEAD.saw"
    try:
        temporary.write_text(text if text.endswith("\n") else text + "\n", encoding="utf-8")
        os.replace(temporary, gitdir / "HEAD")
    except OSError:
        return False
    return True


def _read(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except OSError:
        return ""
