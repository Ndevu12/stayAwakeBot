#!/usr/bin/env python3
"""The files added beside a removed payload that nobody decided, kept in saw's own state between
`saw fix amend` runs."""
from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from stayawake.bots.security.pr.resolve import ArrivedFile, DeliveryQuestion
from stayawake.utils import atomicwrite, env

RECORD_NAME = "arrivals.json"
_FORMAT = 1
_MAX_RECORD_BYTES = 8 * 1024 * 1024
_HEX = frozenset("0123456789abcdef")


@dataclass(frozen=True)
class Record:
    """One record file and the deliveries it holds."""

    source: Path
    deliveries: tuple[DeliveryQuestion, ...]


def state_dir(slug: str) -> Path:
    """Find saw's own folder for one repository's amend runs. Takes the repository's slug. Returns
    the folder."""
    safe = "".join(c if c.isalnum() or c in "-._" else "-" for c in slug) or "repository"
    return Path(env.xdg_state_home()) / "saw" / "amend" / safe


def _is_object_id(value) -> bool:
    return isinstance(value, str) and len(value) in (40, 64) and set(value) <= _HEX


def _strings(value) -> bool:
    return isinstance(value, list) and all(isinstance(item, str) for item in value)


def _delivery(raw) -> DeliveryQuestion | None:
    """Read one recorded delivery. Takes its stored form. Returns the question, or None when the
    form is not one this module writes."""
    if not isinstance(raw, dict) or not _is_object_id(raw.get("commit")):
        return None
    date, subject, removing, files = (raw.get("date"), raw.get("subject"), raw.get("removing"),
                                      raw.get("files"))
    known_as = raw.get("known_as", [])
    if not (isinstance(date, str) and isinstance(subject, str) and _strings(removing)
            and isinstance(files, list) and isinstance(known_as, list)
            and all(_is_object_id(c) for c in known_as)):
        return None
    arrived = []
    for item in files:
        if (not isinstance(item, dict) or not isinstance(item.get("path"), str)
                or not item["path"] or not _is_object_id(item.get("blob"))):
            return None
        arrived.append(ArrivedFile(item["path"], item["blob"]))
    return DeliveryQuestion(raw["commit"], date, subject, tuple(removing), tuple(arrived),
                            recorded=True, known_as=tuple(known_as))


def _read(source: Path) -> tuple[DeliveryQuestion, ...] | None:
    """Read one record file. Takes its path. Returns its deliveries, or None when it could not be
    read or is not in the form this module writes."""
    try:
        if source.stat().st_size > _MAX_RECORD_BYTES:
            return None
        raw = json.loads(source.read_text(encoding="utf-8"))
    except (OSError, ValueError, RecursionError):
        return None
    if not isinstance(raw, dict) or raw.get("format") != _FORMAT:
        return None
    listed = raw.get("deliveries")
    if not isinstance(listed, list):
        return None
    out = []
    for item in listed:
        read = _delivery(item)
        if read is None:
            return None
        out.append(read)
    return tuple(out)


def read_all(slug: str) -> tuple[list[Record], list[str]]:
    """Read every record kept for one repository. Takes its slug. Returns the records, and the paths
    of those that could not be read."""
    root = state_dir(slug)
    try:
        sources = sorted(root.glob(f"*/{RECORD_NAME}"))
    except OSError:
        return [], [str(root)]
    records, unreadable = [], []
    for source in sources:
        read = _read(source)
        if read is None:
            unreadable.append(str(source))
        else:
            records.append(Record(source, read))
    return records, unreadable


def _stored(question: DeliveryQuestion) -> dict:
    return {"commit": question.commit, "date": question.date, "subject": question.subject,
            "removing": list(question.removing),
            "files": [{"path": f.path, "blob": f.blob} for f in question.files],
            "known_as": list(question.known_as)}


def _replace(target: Path, deliveries) -> bool:
    """Write a record file in one step. Takes its path and the deliveries. Returns whether it was
    written."""
    body = json.dumps({"format": _FORMAT, "deliveries": [_stored(q) for q in deliveries]},
                      indent=1, sort_keys=True)
    return atomicwrite.replace(target, body)


def _merged(earlier, later) -> list[DeliveryQuestion]:
    """Combine two delivery lists, each file of each commit once. Takes both. Returns the list."""
    out: dict[str, DeliveryQuestion] = {}
    for question in [*earlier, *later]:
        known = out.get(question.commit)
        if known is None:
            out[question.commit] = question
            continue
        files = tuple(dict.fromkeys([*known.files, *question.files]))
        known_as = tuple(dict.fromkeys([*known.known_as, *question.known_as]))
        out[question.commit] = DeliveryQuestion(known.commit, known.date, known.subject,
                                                known.removing, files, recorded=True,
                                                known_as=known_as)
    return list(out.values())


def write(folder: Path, deliveries) -> Path | None:
    """Add deliveries to the record kept in one run's folder. Takes the folder and the deliveries.
    Returns the record's path, or None when it could not be written."""
    target = folder / RECORD_NAME
    earlier: tuple[DeliveryQuestion, ...] = ()
    try:
        present = target.exists()
    except OSError:
        return None
    if present:
        read = _read(target)
        if read is None:
            return None
        earlier = read
    return target if _replace(target, _merged(earlier, deliveries)) else None


def keep_only(record: Record, deliveries) -> bool:
    """Replace what a record holds, removing the record when nothing is left. Takes the record and
    the deliveries still to ask. Returns whether that was done."""
    remaining = [q for q in deliveries if q.files]
    if remaining:
        return _replace(record.source, remaining)
    try:
        record.source.unlink()
    except FileNotFoundError:
        pass
    except OSError:
        return False
    return True
