#!/usr/bin/env python3
"""The files added in the same commit as a confirmed payload, which `saw fix` names, or puts to the
operator when one can be asked."""
from __future__ import annotations

from pathlib import Path

from stayawake.bots.security.pr import arrival_questions, arrival_record, held
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


def _from_this_run(repo: Path, paths: list[str], findings, stored, seen: set, excluded: set[str],
                   unread: list[str]):
    """Build the questions for the deliveries of the confirmed payloads at the paths. Takes the
    repo, the paths, the scan's findings, the stored-content judge, the files already put, the
    paths to leave out and where to name what git could not read, each of which it adds to.
    Returns the `Questions`."""
    sweeps = delivery.sweep_merges(repo, findings)
    unread.extend(detail for _kind, detail in sweeps.failed)
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


def _decided_and_recorded(slug: str):
    """Read what earlier runs decided and left undecided for one repository. Takes its slug, or ""
    when it has none. Returns the decisions, the records, and the stores that could not be read."""
    if not slug:
        return [], [], []
    decided, read = arrival_record.read_decisions(slug)
    records, unreadable = arrival_record.read_all(slug)
    if not read:
        unreadable = [*unreadable, str(arrival_record.state_dir(slug) / arrival_record.DECIDED_NAME)]
    return decided, records, unreadable


def arrivals_beside(repo: Path, paths, findings, signatures, allowlist, opts, *, resolver=None,
                    baseref: str = "", fix_branch: str = "") -> Arrivals:
    """Find the files added in the same commit as a confirmed payload at the paths and those an
    earlier `saw fix amend` left undecided, and, with a resolver, put them to the operator and keep
    the answers. Takes the repository, the confirmed paths, the scan's findings, the signatures,
    allowlist and scan options, the resolver, or None when nobody can be asked, the ref the fix is
    prepared against and the branch it is prepared on. Returns the `Arrivals`."""
    paths = sorted(set(paths))
    unread: list[str] = []
    slug = gitutil.origin_slug(repo)
    decided, records, unreadable = _decided_and_recorded(slug)
    pairs = frozenset((d.path, d.blob) for d in decided)
    keeps = frozenset((d.path, d.blob) for d in decided
                      if d.decision == arrival_record.KEEP_DECISION)
    seen: set[tuple[str, str]] = set()
    excluded = set(paths) | {getattr(f, "path", "") or "" for f in findings}
    put = arrival_questions.Questions()
    if paths:
        put = _from_this_run(repo, paths, findings, live.StoredContent(repo, signatures, allowlist, opts),
                             seen, excluded, unread)
    recorded = [q for record in records for q in record.deliveries]
    every = [*put.asked,
             *arrival_questions.from_records(recorded, excluded, seen, lambda forms, path, blob: True)]
    candidates = arrival_questions.files_of(every)
    undecided = arrival_questions.without(every, pairs)
    taken = [(d.path, d.blob) for d in decided if d.decision == arrival_record.TAKE_OUT_DECISION
             and (d.path, d.blob) in candidates]
    saved = True
    if resolver is not None and undecided:
        asked_now = arrival_questions.ASKED_PER_RUN
        settled = arrival_questions.ask(
            arrival_questions.with_mentions(repo, undecided[:asked_now]) + undecided[asked_now:],
            resolver)
        answered = arrival_questions.decisions(settled)
        saved = not answered or (bool(slug) and arrival_record.add_decisions(slug, answered))
        if saved and answered:
            now = keeps | {(d.path, d.blob) for d in answered
                           if d.decision == arrival_record.KEEP_DECISION}
            for record in records:
                arrival_record.keep_only(record, arrival_questions.still_to_ask(
                    record.deliveries, arrival_questions.Settled(), lambda forms, path, blob: True,
                    now))
        taken += [(f.path, f.blob) for f in settled.take_out]
        undecided = settled.undecided
    versions: dict[str, set[str]] = {}
    for path, blob in taken:
        versions.setdefault(path, set()).add(blob)
    stored = held.versions_held(repo, versions, baseref, fix_branch=fix_branch)
    whole = gitutil.holds_its_history(repo) if put.first_commits else True
    return Arrivals(
        files=tuple(f.path for question in undecided for f in question.files),
        first_commits=tuple(put.first_commits) if whole else (),
        unread=tuple([*unread, *put.unread, *([] if whole else put.first_commits),
                      *([stored.unread] if stored.unread else [])]),
        unread_records=tuple(unreadable),
        take_out=tuple(sorted(set(taken))),
        taken_out_held=stored.holds,
        not_saved=not saved)
