#!/usr/bin/env python3
"""The JSON documents saw prints, and the schema version each one is written in.

A document's name is the command that prints it, its words joined by `-`: `auth-status` is what
`saw auth status --json` prints. A version changes only when a change would break a reader;
adding a field does not change it.
"""
from __future__ import annotations

from typing import Any

SCHEMA_VERSION_OF_EACH_DOCUMENT = {
    "scan": 1,
    "fix": 1,
    "doctor": 1,
    "auth-status": 1,
    "guard-drift": 1,
    "audit": 1,
    "hook-status": 1,
    "capabilities": 1,
}

# `hook install` and `hook repair` print the hook-status document. Their names are not that document.
ALSO_PRINTED_BY = {
    "hook-status": (("hook", "install"), ("hook", "repair")),
}


def versioned(document: str, payload: dict[str, Any]) -> dict[str, Any]:
    """Stamp `payload` with the schema version `document` is written in, as its first key.

    Takes the document's name and its payload. Returns a new dict; `payload` is left as it was."""
    return {"schema_version": SCHEMA_VERSION_OF_EACH_DOCUMENT[document], **payload}


def command_of(document: str) -> list[str]:
    """Name the command words that print `document`. Returns them in order, e.g. `["auth",
    "status"]`."""
    return document.split("-")


def commands_for(document: str) -> list[tuple[str, ...]]:
    """Name every command that prints `document`.

    Takes the document's name. Returns the command its name is, then any other command that
    prints the same document."""
    return [tuple(command_of(document)), *ALSO_PRINTED_BY.get(document, ())]
