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
    "capabilities": 1,
}


def versioned(document: str, payload: dict[str, Any]) -> dict[str, Any]:
    """Stamp `payload` with the schema version `document` is written in, as its first key.

    Takes the document's name and its payload. Returns a new dict; `payload` is left as it was."""
    return {"schema_version": SCHEMA_VERSION_OF_EACH_DOCUMENT[document], **payload}


def command_of(document: str) -> list[str]:
    """Name the command words that print `document`. Returns them in order, e.g. `["auth",
    "status"]`."""
    return document.split("-")
