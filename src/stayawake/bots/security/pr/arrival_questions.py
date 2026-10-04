#!/usr/bin/env python3
"""Put the files a delivery commit added beside a removed payload to the operator, one question per
delivery."""
from __future__ import annotations

from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Callable, Mapping

from stayawake.bots.security.pr.resolve import (KEEP, TAKE_OUT, ArrivedFile, DeliveryAnswer,
                                                DeliveryQuestion)
from stayawake.bots.security.pr import arrival_record
from stayawake.bots.security.remediation import delivery
from stayawake.bots.security.remediation.delivery import Brought
from stayawake.lib import git as gitutil

ASKED_PER_RUN = 10


@dataclass
class Questions:
    """The questions a run has to put, and the deliveries it can only name."""

    asked: list[DeliveryQuestion] = field(default_factory=list)
    first_commits: list[str] = field(default_factory=list)
    unread: list[str] = field(default_factory=list)


@dataclass
class Settled:
    """What became of the files put to the operator.

    `take_out` are the files to remove as they were added; `kept` are the files the operator kept;
    `delivered_in` maps each of both, as `(path, blob)`, to every id of the commit that added it;
    `undecided` the questions nobody answered.
    """

    take_out: list[ArrivedFile] = field(default_factory=list)
    kept: list[ArrivedFile] = field(default_factory=list)
    undecided: list[DeliveryQuestion] = field(default_factory=list)
    delivered_in: dict[tuple[str, str], tuple[str, ...]] = field(default_factory=dict)


def _with_files(question: DeliveryQuestion, files) -> DeliveryQuestion:
    """Copy a question with other files. Takes the question and the files. Returns the copy."""
    return replace(question, files=tuple(files))


def from_history(repo: Path, deliveries: Mapping[str, tuple[str, ...]],
                 brought: Mapping[str, Brought | None], excluded: set[str],
                 seen: set[tuple[str, str]]) -> Questions:
    """Build one question per delivery from the files it added that nothing else handles. Takes the
    repo, each delivery mapped to the payload paths saw removes from it, what each brought (None
    where git could not read it), the paths to leave out, and the files already put, which it adds
    to. Returns the `Questions`."""
    out = Questions()
    for commit, removing in deliveries.items():
        found = brought.get(commit)
        if found is None:
            out.unread.append(commit[:12])
            continue
        fresh = [ArrivedFile(path, blob) for path, blob in found.added
                 if path not in excluded and (path, blob) not in seen]
        if found.parentless:
            if fresh:
                out.first_commits.append(commit[:12])
            continue
        if not fresh:
            continue
        seen.update((f.path, f.blob) for f in fresh)
        meta = gitutil.commit_meta(repo, commit)
        out.asked.append(DeliveryQuestion(
            commit, meta.get("date", ""), meta.get("subject", ""), tuple(sorted(removing)),
            tuple(fresh), tuple(p for p in found.changed if p not in excluded)))
    return out


def from_records(recorded, excluded: set[str], seen: set[tuple[str, str]],
                 held: Callable[[tuple[str, ...], str, str], bool]) -> list[DeliveryQuestion]:
    """Build the questions an earlier run recorded and nobody answered. Takes the recorded
    questions, the paths to leave out, the files already put, which it adds to, and
    `held(forms, path, blob)`, which says whether history after that delivery still holds that file.
    Returns the questions with a file still to ask."""
    out = []
    for question in recorded:
        fresh = [f for f in question.files if f.path not in excluded
                 and (f.path, f.blob) not in seen and held(question.forms, f.path, f.blob)]
        if fresh:
            seen.update((f.path, f.blob) for f in fresh)
            out.append(_with_files(question, fresh))
    return out


def ask(questions, resolver, limit: int = ASKED_PER_RUN) -> Settled:
    """Put each question to the operator, at most `limit` of them. Takes the questions, the
    resolver, or None when nobody can be asked, and the limit. Returns what was `Settled`; a file
    chosen at a path already chosen at another blob is left undecided."""
    settled = Settled()
    taken: dict[str, str] = {}
    for at, question in enumerate(questions):
        answer = None
        if resolver is not None and at < limit:
            try:
                answer = resolver(question)
            except Exception:
                answer = None
        if not isinstance(answer, DeliveryAnswer) or answer.action not in (TAKE_OUT, KEEP):
            settled.undecided.append(question)
            continue
        chosen = set(answer.chosen) if answer.action == TAKE_OUT else set()
        clashing = []
        for f in question.files:
            if f.path not in chosen:
                settled.kept.append(f)
                settled.delivered_in[(f.path, f.blob)] = question.forms
            elif taken.setdefault(f.path, f.blob) != f.blob:
                clashing.append(f)
            else:
                settled.take_out.append(f)
                settled.delivered_in[(f.path, f.blob)] = question.forms
        if clashing:
            settled.undecided.append(_with_files(question, clashing))
    return settled


def decisions(settled: Settled) -> list[arrival_record.Decision]:
    """List what the operator answered, as decisions kept between runs. Takes what was settled.
    Returns the decisions."""
    return ([arrival_record.Decision(f.path, f.blob, settled.delivered_in[(f.path, f.blob)],
                                     arrival_record.KEEP_DECISION) for f in settled.kept]
            + [arrival_record.Decision(f.path, f.blob, settled.delivered_in[(f.path, f.blob)],
                                       arrival_record.TAKE_OUT_DECISION)
               for f in settled.take_out])


def with_mentions(repo: Path, questions) -> list[DeliveryQuestion]:
    """Add to each question how many other files of the project mention each of its files, outside
    the files of the same delivery. Takes the repo and the questions. Returns the questions with
    `named_by` filled, or unchanged when the project could not be read in full."""
    naming = delivery.files_naming(repo, [f.path for q in questions for f in q.files])
    if naming is None:
        return list(questions)
    out = []
    for question in questions:
        own = {*(f.path for f in question.files), *question.removing, *question.changed}
        counts = {f.path: len(naming[f.path] - own) for f in question.files if f.path in naming}
        out.append(replace(question, named_by=tuple(sorted(counts.items()))))
    return out


def without(questions, pairs) -> list[DeliveryQuestion]:
    """Leave files out of questions. Takes the questions and the `(path, blob)` pairs to leave out.
    Returns the questions with a file left, each with only those files."""
    out = []
    for question in questions:
        files = [f for f in question.files if (f.path, f.blob) not in pairs]
        if files:
            out.append(_with_files(question, files))
    return out


def files_of(questions) -> set[tuple[str, str]]:
    """List the files the questions put. Takes the questions. Returns their `(path, blob)` pairs."""
    return {(f.path, f.blob) for question in questions for f in question.files}


def remapped_decisions(decided, mapping: Mapping[str, str]) -> list[arrival_record.Decision]:
    """Add the ids a history rewrite gave each decision's delivery commit. Takes the decisions and
    the rewrite's map from old commit ids to new. Returns the decisions, each with its new ids
    added."""
    return [replace(d, forms=tuple(dict.fromkeys([*d.forms, *(mapping[c] for c in d.forms
                                                              if c in mapping)])))
            for d in decided]


def remapped(recorded, mapping: Mapping[str, str]) -> list[DeliveryQuestion]:
    """Add the ids a history rewrite gave each delivery commit. Takes the questions and the rewrite's
    map from old commit ids to new. Returns the questions, each with its new ids added."""
    out = []
    for question in recorded:
        new = [mapping[c] for c in question.forms if c in mapping and mapping[c] not in question.forms]
        out.append(replace(question, known_as=tuple(dict.fromkeys([*question.known_as, *new]))))
    return out


def still_to_ask(recorded, settled: Settled,
                 held: Callable[[tuple[str, ...], str, str], bool],
                 kept_before=frozenset()) -> list[DeliveryQuestion]:
    """Find what an earlier run's record must keep after this run. Takes the recorded questions,
    what this run settled, `held(forms, path, blob)`, and the `(path, blob)` pairs kept in earlier
    runs. Returns each question with only the files history after that delivery still holds that
    the operator has not kept."""
    kept = set(settled.kept) | {ArrivedFile(path, blob) for path, blob in kept_before}
    out = []
    for question in recorded:
        files = [f for f in question.files if f not in kept and held(question.forms, f.path, f.blob)]
        out.append(_with_files(question, files))
    return out
