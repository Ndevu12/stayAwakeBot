#!/usr/bin/env python3
"""The command of an update `saw govern` held where no one could be asked, kept per repository until
`saw govern let-in` runs it again in a terminal."""
from __future__ import annotations

import json
import os
from pathlib import Path

from stayawake.bots.security import govern_command, govern_held, govern_status
from stayawake.bots.security.govern import TOOLS
from stayawake.lib.git import holding_directory
from stayawake.utils import atomicwrite, env, pathsafe
from stayawake.utils.timeutil import now_iso

VERSION = 1
_MOST_BYTES = 64 << 10


def store() -> Path:
    """Return the folder the held commands are kept in, one file per repository."""
    return Path(env.xdg_state_home()) / "saw" / "govern" / "held"


def repository_of(folder: str) -> str:
    """Find the top of the working tree a folder is in. Takes the folder. Returns it resolved, or the
    folder itself resolved when it is in no working tree."""
    top = govern_command.top_of_working_tree(Path(folder))
    return os.path.realpath(top if top is not None else folder)


def _record_path(repository: str) -> Path:
    return store() / f"{govern_status.folder_key(repository)}.json"


def let_in_command(repository: str) -> list[str]:
    """Build the command that lets in the update held for a repository, naming the repository when
    this process runs outside it. Takes the repository's top folder. Returns the command."""
    here = repository_of(os.getcwd())
    return ["saw", "govern", "let-in"] + ([] if here == repository else ["--repo", repository])


def keep_for_let_in(repo: str, command: list[str], answer: dict) -> None:
    """Keep the command of an update saw held and offers to let in, replacing the repository's
    earlier one, and add the command that lets it in to the answer's decision. Takes the open folder, the
    command line with the tool first and prepare's answer. Returns nothing, leaving the answer as
    it was when the update is not held for a let-in or the command cannot be kept."""
    decision = answer.get("decision")
    if not (isinstance(decision, dict) and govern_held.LET_IN in (decision.get("choices") or [])):
        return
    if holding_directory.in_a_repository(store()):
        return
    repository = repository_of(repo)
    body = {"version": VERSION, "repository": repository, "ran_in": os.path.realpath(os.getcwd()),
            "command": list(command), "at": now_iso()}
    try:
        store().mkdir(parents=True, exist_ok=True, mode=0o700)
        kept = atomicwrite.replace(_record_path(repository), json.dumps(body))
    except OSError:
        return
    if kept:
        decision["let_in_later"] = let_in_command(repository)


def read(folder: str) -> dict | None:
    """Read the command kept for the repository a folder is in. Takes any folder inside it. Returns
    the record, or None when there is none or it cannot be used."""
    if holding_directory.in_a_repository(store()):
        return None
    repository = repository_of(folder)
    raw = pathsafe.read_regular_no_follow(_record_path(repository), _MOST_BYTES)
    try:
        record = json.loads(raw) if raw is not None else None
    except ValueError:
        return None
    if not (isinstance(record, dict) and record.get("version") == VERSION and record.get("repository") == repository):
        return None
    command, ran_in = record.get("command"), record.get("ran_in")
    if not (isinstance(command, list) and command and all(isinstance(word, str) for word in command)
            and command[0] in TOOLS and isinstance(ran_in, str)):
        return None
    return record


def clear(folder: str, record: dict) -> None:
    """Remove the command kept for the repository a folder is in when it is still the one given.
    Takes any folder inside it and the record that ran. Returns nothing."""
    if read(folder) == record:
        try:
            _record_path(record["repository"]).unlink()
        except OSError:
            pass
