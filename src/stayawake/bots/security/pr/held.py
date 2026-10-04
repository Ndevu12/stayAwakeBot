#!/usr/bin/env python3
"""What the history still stores at the paths a run cleared from the checkout.
"""
from __future__ import annotations

from pathlib import Path
from typing import Mapping

from stayawake.bots.security.pr.fix_verdict import History, HistoryHold, Remedy
from stayawake.bots.security.remediation import live
from stayawake.lib.git.run import run


class _Unanswered(Exception):
    """git could not answer a question the verdict depends on."""


def history_holds(repo: Path, paths, baseref: str, signatures, allowlist, opts, *,
                  fix_branch: str = "") -> History:
    """Find the places that still store confirmed content at the paths. Takes the repository, the
    cleared paths, the ref the fix is prepared against, the by-matcher signatures, the allowlist,
    the scan options and the branch the fix is prepared on. Returns the `History`, each hold with
    its remedy, and `unread` set when git could not answer."""
    paths = sorted(set(paths))
    if not paths:
        return History()
    return _holds(repo, paths, baseref, live.StoredContent(repo, signatures, allowlist, opts),
                  fix_branch)


class _ExactVersions:
    """A judge of stored entries that confirms only the versions named for each path."""

    def __init__(self, versions: Mapping[str, set[str]]):
        self._versions = versions

    def confirms(self, path: str, entry: tuple[str, str]) -> bool:
        """Takes the path and its `(mode, object)` entry. Returns whether it is a named version."""
        return entry[1] in self._versions.get(path, ())


def versions_held(repo: Path, versions: Mapping[str, set[str]], baseref: str, *,
                  fix_branch: str = "") -> History:
    """Find the places that still store one of the named versions of each path. Takes the
    repository, each path mapped to its version ids, the ref the fix is prepared against and the
    branch the fix is prepared on. Returns the `History`."""
    paths = sorted(p for p, ids in versions.items() if ids)
    if not paths:
        return History()
    return _holds(repo, paths, baseref, _ExactVersions(versions), fix_branch)


def _holds(repo: Path, paths: list[str], baseref: str, stored, fix_branch: str) -> History:
    """Find the places that still store what a judge confirms at the paths. Takes the repository,
    the paths, the ref the fix is prepared against, the judge and the branch the fix is prepared on.
    Returns the `History`."""
    try:
        holds = _at_head(repo, paths, baseref, stored)
        holds += _on_branches(repo, paths, baseref, stored, fix_branch)
        holds += _in_stash(repo, paths, stored)
    except _Unanswered as exc:
        return History(unread=str(exc))
    return History(holds=tuple(holds))


def _git(repo: Path, args: list[str]):
    res = run(repo, args)
    if res is None:
        raise _Unanswered("git could not run")
    return res


def _held_at(repo: Path, treeish: str, paths: list[str], stored) -> tuple[str, ...]:
    key = live.path_key(repo)
    found = live.entries(repo, ["ls-tree", "-r", "-z", "--full-tree", treeish],
                         live.literal_pathspecs(), staged=False, key=key)
    if found is None:
        raise _Unanswered(f"git could not list {treeish}")
    held = []
    for path in paths:
        verdicts = [stored.confirms(path, entry) for entry in found.get(key(path), ())]
        if any(v is None for v in verdicts):
            raise _Unanswered(f"could not read {path} at {treeish}")
        if any(verdicts):
            held.append(path)
    return tuple(held)


def _reached_by(repo: Path, commit: str, ref: str) -> bool:
    res = _git(repo, ["merge-base", "--is-ancestor", commit, ref])
    if res.returncode not in (0, 1):
        raise _Unanswered(f"could not tell whether {ref} reaches {commit}")
    return res.returncode == 0


def _remedy(repo: Path, commit: str, baseref: str) -> Remedy:
    return Remedy.FIX_PR if _reached_by(repo, commit, baseref) else Remedy.AMEND


def _on_a_remote(repo: Path, commit: str) -> bool:
    res = run(repo, ["for-each-ref", "--contains", commit, "--format=%(refname)", "refs/remotes"])
    return res is not None and res.returncode == 0 and bool((res.stdout or "").strip())


def _current_branch(repo: Path) -> str:
    res = _git(repo, ["symbolic-ref", "-q", "HEAD"])
    return (res.stdout or "").strip() if res.returncode == 0 else ""


def _at_head(repo: Path, paths, baseref: str, stored) -> list[HistoryHold]:
    head = _git(repo, ["rev-parse", "--verify", "-q", "HEAD^{commit}"])
    if head.returncode != 0:
        return []
    commit = (head.stdout or "").strip()
    held = _held_at(repo, commit, paths, stored)
    if not held:
        return []
    remedy = _remedy(repo, commit, baseref)
    name = _current_branch(repo).removeprefix("refs/heads/") or "HEAD"
    return [HistoryHold("head", name, held, remedy,
                        on_remote=remedy is Remedy.AMEND and _on_a_remote(repo, commit))]


def _on_branches(repo: Path, paths, baseref: str, stored, fix_branch: str) -> list[HistoryHold]:
    listing = _git(repo, ["for-each-ref", "--format=%(refname)%00%(objectname)", "refs/heads"])
    if listing.returncode != 0:
        raise _Unanswered("could not list the branches")
    current = _current_branch(repo)
    holds = []
    for line in (listing.stdout or "").splitlines():
        ref, _, commit = line.partition("\0")
        if not commit or ref in (current, f"refs/heads/{fix_branch}"):
            continue
        held = _held_at(repo, commit, paths, stored)
        if held:
            holds.append(HistoryHold("branch", ref.removeprefix("refs/heads/"), held,
                                     _remedy(repo, commit, baseref)))
    return holds


def _in_stash(repo: Path, paths, stored) -> list[HistoryHold]:
    has = _git(repo, ["rev-parse", "--verify", "-q", "refs/stash"])
    if has.returncode != 0:
        return []
    listing = _git(repo, ["log", "-g", "--format=%H", "refs/stash", "--"])
    if listing.returncode != 0:
        raise _Unanswered("could not list the stash")
    holds = []
    for index, commit in enumerate((listing.stdout or "").split()):
        held: set[str] = set()
        for part in (commit, f"{commit}^2", f"{commit}^3"):
            if part != commit and _git(repo, ["rev-parse", "--verify", "-q",
                                              f"{part}^{{commit}}"]).returncode != 0:
                continue
            held.update(_held_at(repo, part, paths, stored))
        if held:
            holds.append(HistoryHold("stash", f"stash@{{{index}}}", tuple(sorted(held)),
                                     Remedy.NAMED_ONLY))
    return holds
