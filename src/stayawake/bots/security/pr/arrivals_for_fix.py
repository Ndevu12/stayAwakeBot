#!/usr/bin/env python3
"""The files added in the same commit as a confirmed payload, which `saw fix` names and leaves."""
from __future__ import annotations

from pathlib import Path

from stayawake.bots.security.pr import arrival_questions
from stayawake.bots.security.pr.fix_verdict import Arrivals
from stayawake.bots.security.remediation import delivery, live
from stayawake.lib import git as gitutil



def _confirmed_versions(repo: Path, path: str, stored) -> set[str]:
    """Walk a path's history and collect the commits whose version of it is confirmed. Takes the
    repo, the path and the stored-content judge. Returns those commits. Raises `Unread` when git
    could not walk or read it, or the history is too long to walk."""
    changed = delivery.history_of(repo, path, all_branches=True)
    if changed is None:
        raise gitutil.Unread(f"every copy of {path}")
    found = set()
    for sha in changed:
        answered, entry = gitutil.entry_at(repo, sha, path)
        verdict = stored.confirms(path, entry) if answered and entry is not None else False
        if not answered or verdict is None:
            raise gitutil.Unread(f"every copy of {path}")
        if verdict:
            found.add(sha)
    return found


def _swept_merges(repo: Path, findings, unread: list[str]) -> tuple[dict, set[str], set[str]]:
    """Find the merges `saw fix amend` takes a payload out of, and what it takes or asks about on
    its own. Takes the repo, the findings, and where to name what git could not read. Returns each
    merge it sweeps mapped to the payload paths, the paths it takes or asks about, and the merges it
    leaves to its own questions."""
    deliveries: dict[str, tuple[str, ...]] = {}
    handled: set[str] = set()
    own_questions: set[str] = set()
    for finding, anchors in delivery.confirmed_commits(findings):
        reported = getattr(finding, "commit_sha", "") or ""
        related = tuple(getattr(finding, "related_paths", ()) or ())
        sha = gitutil.stdout(repo, ["rev-parse", "--verify", "--quiet",
                                    f"{reported}^{{commit}}"]).strip()
        if not sha:
            unread.append(reported[:12])
            continue
        try:
            taken = delivery.swept_by(repo, sha, related, anchors)
        except gitutil.Unread as missed:
            unread.append(missed.subject)
            continue
        if taken:
            deliveries[sha] = tuple(taken)
            handled.update(taken)
        else:
            own_questions.add(sha)
            handled.update(related)
    return deliveries, handled, own_questions


def arrivals_beside(repo: Path, paths, findings, signatures, allowlist, opts) -> Arrivals:
    """Find, changing nothing, the files added in the same commit as a confirmed payload at the
    paths. Takes the repository, the confirmed paths, the scan's findings, and the signatures,
    allowlist and scan options. Returns the `Arrivals`."""
    paths = sorted(set(paths))
    if not paths:
        return Arrivals()
    unread: list[str] = []
    deliveries, handled, own_questions = _swept_merges(repo, findings, unread)
    stored = live.StoredContent(repo, signatures, allowlist, opts)
    for path in paths:
        try:
            found = delivery.first_carriers(repo, {path: _confirmed_versions(repo, path, stored)})
        except gitutil.Unread as missed:
            unread.append(missed.subject)
            continue
        for sha, carried in found.items():
            deliveries[sha] = tuple(dict.fromkeys(deliveries.get(sha, ()) + carried))
    for sha in own_questions:
        deliveries.pop(sha, None)
    excluded = set(paths) | handled | {getattr(f, "path", "") or "" for f in findings}
    put = arrival_questions.from_history(repo, deliveries, delivery.brought_by_each(repo, deliveries),
                                excluded, set())
    whole = gitutil.holds_its_history(repo)
    return Arrivals(
        files=tuple(f.path for question in put.asked for f in question.files),
        first_commits=tuple(put.first_commits) if whole else (),
        unread=tuple([*unread, *put.unread, *([] if whole else put.first_commits)]))
