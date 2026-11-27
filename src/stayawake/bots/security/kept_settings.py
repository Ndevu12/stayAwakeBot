#!/usr/bin/env python3
"""The git settings the operator kept for each repository: the fingerprint of the programs its own
settings start, recorded when a person answers yes, and the one a person answered no to. The git
stand-in reads the record, runs git in a repository with its own settings only while they still match
the kept ones, and does not ask again about settings a person answered no to. The record is one of
saw's records, never kept inside a repository."""
from __future__ import annotations

import json
from pathlib import Path

from stayawake.bots.security import records
from stayawake.lib.git import runs_directly, settings_fingerprint
from stayawake.lib.git.settings_fingerprint import Fingerprint

VERSION = 1
RECORD_TABLE = "kept_settings_record"
RECORD_LIMIT = 1 << 20
KEPT = "repositories"
DECLINED = "declined"


def record_path() -> Path:
    """Return the path of the record, named in the table the git stand-in reads too."""
    return records.path(*runs_directly.tables()[RECORD_TABLE])


def _read() -> dict[str, dict[str, str]]:
    """Read the record. Returns the kept and the declined digests, each by repository."""
    try:
        data = json.loads(records.read_text(record_path())[:RECORD_LIMIT])
    except (OSError, ValueError):
        data = {}
    found: dict[str, dict[str, str]] = {}
    for table in (KEPT, DECLINED):
        listed = data.get(table) if isinstance(data, dict) else None
        found[table] = ({repository: digest for repository, digest in listed.items()
                         if isinstance(repository, str) and isinstance(digest, str)}
                        if isinstance(listed, dict) else {})
    return found


def _write(recorded: dict[str, dict[str, str]]) -> bool:
    """Write the record. Takes the kept and the declined digests, each by repository. Returns
    whether it was written."""
    where = record_path()
    try:
        records.make_folder(where.parent)
    except OSError:
        return False
    text = json.dumps({"version": VERSION, **recorded}, indent=2, sort_keys=True) + "\n"
    return records.replace(where, text)


def kept_digest(repository: str) -> str | None:
    """Return the digest kept for a repository. Takes its key. Returns it, or None."""
    return _read()[KEPT].get(repository)


def is_kept(found: Fingerprint) -> bool:
    """Say whether the operator kept exactly these settings. Takes the fingerprint."""
    return kept_digest(found.repository) == found.digest()


def is_declined(found: Fingerprint) -> bool:
    """Say whether a person answered no to exactly these settings. Takes the fingerprint."""
    return _read()[DECLINED].get(found.repository) == found.digest()


def keep(found: Fingerprint) -> bool:
    """Record that the operator keeps these settings. Takes the fingerprint. Returns whether the
    record was written."""
    recorded = _read()
    recorded[KEPT][found.repository] = found.digest()
    recorded[DECLINED].pop(found.repository, None)
    return _write(recorded)


def decline(found: Fingerprint) -> bool:
    """Record that a person answered no to these settings. Takes the fingerprint. Returns whether
    the record was written."""
    recorded = _read()
    recorded[DECLINED][found.repository] = found.digest()
    return _write(recorded)


def forget(repository: str) -> bool:
    """Stop keeping a repository's settings. Takes its key. Returns whether any were kept."""
    recorded = _read()
    if recorded[KEPT].pop(repository, None) is None:
        return False
    return _write(recorded)


def kept_before(folder: str | Path) -> Fingerprint | None:
    """Read the fingerprint of a folder's repository when the operator kept exactly it. Takes the
    folder. Returns it, or None."""
    found = settings_fingerprint.fingerprint(folder)
    return found if isinstance(found, Fingerprint) and not found.empty and is_kept(found) else None


def keep_after_a_governed_change(folder: str | Path, before: Fingerprint | None) -> bool:
    """Record the settings a folder has after saw wrote a checked update into it, when the operator
    kept the settings it had before. An update that changes a hook, a hook manager's file or a file
    a hook names is held for a person's review when it arrives. Takes the folder and its kept
    fingerprint before the update. Returns whether the record changed."""
    if before is None:
        return False
    after = settings_fingerprint.fingerprint(folder)
    if not isinstance(after, Fingerprint) or after.repository != before.repository:
        return False
    if after.digest() == before.digest():
        return False
    return forget(before.repository) if after.empty else keep(after)
