#!/usr/bin/env python3
"""The git settings the operator kept for each repository: the fingerprint of the programs its own
settings start, recorded when a person answers yes. The git stand-in reads the record and runs git in
a repository with its own settings only while they still match it. The record is one of saw's
records, never kept inside a repository."""
from __future__ import annotations

import json
from pathlib import Path

from stayawake.bots.security import records
from stayawake.lib.git import runs_directly, settings_fingerprint
from stayawake.lib.git.settings_fingerprint import Fingerprint

VERSION = 1
RECORD_TABLE = "kept_settings_record"
RECORD_LIMIT = 1 << 20


def record_path() -> Path:
    """Return the path of the record, named in the table the git stand-in reads too."""
    return records.path(*runs_directly.tables()[RECORD_TABLE])


def _read() -> dict[str, str]:
    """Read every kept fingerprint. Returns each repository's digest, or an empty mapping."""
    try:
        data = json.loads(records.read_text(record_path())[:RECORD_LIMIT])
    except (OSError, ValueError):
        return {}
    kept = data.get("repositories") if isinstance(data, dict) else None
    if not isinstance(kept, dict):
        return {}
    return {repository: digest for repository, digest in kept.items()
            if isinstance(repository, str) and isinstance(digest, str)}


def _write(kept: dict[str, str]) -> bool:
    """Write every kept fingerprint. Takes each repository's digest. Returns whether it was
    written."""
    where = record_path()
    try:
        records.make_folder(where.parent)
    except OSError:
        return False
    text = json.dumps({"version": VERSION, "repositories": kept}, indent=2, sort_keys=True) + "\n"
    return records.replace(where, text)


def kept_digest(repository: str) -> str | None:
    """Return the digest kept for a repository. Takes its key. Returns it, or None."""
    return _read().get(repository)


def is_kept(found: Fingerprint) -> bool:
    """Say whether the operator kept exactly these settings. Takes the fingerprint."""
    return kept_digest(found.repository) == found.digest()


def keep(found: Fingerprint) -> bool:
    """Record that the operator keeps these settings. Takes the fingerprint. Returns whether the
    record was written."""
    kept = _read()
    kept[found.repository] = found.digest()
    return _write(kept)


def forget(repository: str) -> bool:
    """Stop keeping a repository's settings. Takes its key. Returns whether any were kept."""
    kept = _read()
    if kept.pop(repository, None) is None:
        return False
    return _write(kept)


def kept_before(folder: str | Path) -> Fingerprint | None:
    """Read the fingerprint of a folder's repository when the operator kept exactly it. Takes the
    folder. Returns it, or None."""
    found = settings_fingerprint.fingerprint(folder)
    return found if isinstance(found, Fingerprint) and not found.empty and is_kept(found) else None


def keep_after_a_governed_change(folder: str | Path, before: Fingerprint | None) -> bool:
    """Record the settings a folder has after saw wrote a checked update into it, when the operator
    kept the settings it had before. Takes the folder and its kept fingerprint before the update.
    Returns whether the record changed."""
    if before is None:
        return False
    after = settings_fingerprint.fingerprint(folder)
    if not isinstance(after, Fingerprint) or after.repository != before.repository:
        return False
    if after.digest() == before.digest():
        return False
    return forget(before.repository) if after.empty else keep(after)
