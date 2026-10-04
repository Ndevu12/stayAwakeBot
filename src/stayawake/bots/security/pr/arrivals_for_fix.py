#!/usr/bin/env python3
"""The files added in the same commit as a confirmed payload, which `saw fix` names and leaves."""
from __future__ import annotations

from pathlib import Path

from stayawake.bots.security.pr import arrival_questions, arrival_record
from stayawake.bots.security.pr.fix_verdict import Arrivals
from stayawake.bots.security.remediation import delivery, live
from stayawake.lib import git as gitutil


def _confirmed_versions(repo: Path, path: str, stored) -> list[str]:
    """Walk a path's history and collect the commits whose version of it is confirmed. Takes the
    repo, the path and the stored-content judge. Returns those commits. Raises `Unread` when git
    could not walk or read it, or the history is too long to walk."""
    def confirmed(sha: str, at: str) -> bool:
        answered, entry = gitutil.entry_at(repo, sha, at)
        verdict = stored.confirms(at, entry) if answered and entry is not None else False
        if not answered or verdict is None:
            raise gitutil.Unread(f"every copy of {at}")
        return verdict

    found = delivery.commits_carrying(repo, path, confirmed)
    if found is None:
        raise gitutil.Unread(f"every copy of {path}")
    return found


def _recorded(repo: Path) -> tuple[list, list[str]]:
    """Read the deliveries earlier `saw fix amend` runs left undecided for this repository. Takes
    the repo. Returns the recorded questions, and the records that could not be read."""
    slug = gitutil.origin_slug(repo)
    if not slug:
        return [], []
    records, unreadable = arrival_record.read_all(slug)
    return [q for record in records for q in record.deliveries], unreadable


def _from_this_run(repo: Path, paths: list[str], findings, stored, seen: set, excluded: set[str],
                   unread: list[str]):
    """Build the questions for the deliveries of the confirmed payloads at the paths. Takes the
    repo, the paths, the scan's findings, the stored-content judge, the files already put, the
    paths to leave out and where to name what git could not read, each of which it adds to.
    Returns the `Questions`."""
    sweeps = delivery.sweep_merges(repo, findings)
    unread.extend([*sweeps.unresolved, *sweeps.unread])
    deliveries = dict(sweeps.swept)
    carriers: dict[str, list[str]] = {}
    for path in paths:
        try:
            carriers[path] = _confirmed_versions(repo, path, stored)
        except gitutil.Unread as missed:
            unread.append(missed.subject)
    delivery.add_first_carriers(repo, carriers, deliveries, unread)
    for sha in sweeps.left_to_ask:
        deliveries.pop(sha, None)
    excluded.update(p for paths in [*sweeps.swept.values(), *sweeps.left_to_ask.values()]
                    for p in paths)
    return arrival_questions.from_history(repo, deliveries, delivery.brought_by_each(repo, deliveries),
                                          excluded, seen)


def arrivals_beside(repo: Path, paths, findings, signatures, allowlist, opts) -> Arrivals:
    """Find, changing nothing, the files added in the same commit as a confirmed payload at the
    paths, and those an earlier `saw fix amend` left undecided. Takes the repository, the confirmed
    paths, the scan's findings, and the signatures, allowlist and scan options. Returns the
    `Arrivals`."""
    paths = sorted(set(paths))
    unread: list[str] = []
    seen: set[tuple[str, str]] = set()
    excluded = set(paths) | {getattr(f, "path", "") or "" for f in findings}
    put = arrival_questions.Questions()
    if paths:
        put = _from_this_run(repo, paths, findings, live.StoredContent(repo, signatures, allowlist, opts),
                             seen, excluded, unread)
    recorded, unreadable = _recorded(repo)
    left = arrival_questions.from_records(recorded, excluded, seen, lambda forms, path, blob: True)
    whole = gitutil.holds_its_history(repo) if put.first_commits else True
    return Arrivals(
        files=tuple(f.path for question in [*put.asked, *left] for f in question.files),
        first_commits=tuple(put.first_commits) if whole else (),
        unread=tuple([*unread, *put.unread, *([] if whole else put.first_commits)]),
        unread_records=tuple(unreadable))
