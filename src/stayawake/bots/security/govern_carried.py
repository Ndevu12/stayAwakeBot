#!/usr/bin/env python3
"""What saw carried into an open folder that git has yet to finish: a rebase stopped for conflicts,
with the commit it replays onto and the commits it checked that the rebase has yet to replay."""
from __future__ import annotations

import json
from pathlib import Path

from stayawake.bots.security import govern_status
from stayawake.utils import atomicwrite


def _record_path(repo: str | Path) -> Path:
    """Name the file that holds a folder's record. Takes the open folder. Returns the path."""
    return govern_status.status_dir().parent / "carried" / f"{govern_status.folder_key(repo)}.json"


def remember(repo: str | Path, onto: str, picks: tuple[str, ...]) -> bool:
    """Record a rebase saw carried into `repo`. Takes the open folder, the commit it replays onto and
    the commits left to replay. Returns whether the record was written."""
    where = _record_path(repo)
    try:
        atomicwrite.make_folder(where.parent)
    except OSError:
        return False
    return atomicwrite.replace(where, json.dumps({"onto": onto, "picks": list(picks)}))


def carried_onto(repo: str | Path) -> str | None:
    """Read the commit the rebase saw last carried into `repo` replays onto. Takes the open folder.
    Returns it, or None for a folder saw carried no rebase into."""
    try:
        onto = json.loads(_record_path(repo).read_text(encoding="utf-8"))["onto"]
    except (OSError, ValueError, KeyError, TypeError):
        return None
    return onto if isinstance(onto, str) else None


def carried(repo: str | Path, onto: str, picks: tuple[str, ...]) -> bool:
    """Tell whether a rebase in progress in `repo` is one saw carried, with nothing left to replay
    beyond what saw checked. Takes the open folder, the commit the rebase replays onto and the
    commits it has left. Returns the answer."""
    try:
        record = json.loads(_record_path(repo).read_text(encoding="utf-8"))
        checked = tuple(record["picks"])
        return record["onto"] == onto and len(picks) <= len(checked) and checked[len(checked) - len(picks):] == picks
    except (OSError, ValueError, KeyError, TypeError):
        return False
