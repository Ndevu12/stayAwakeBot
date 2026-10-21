#!/usr/bin/env python3
"""The document `saw hook status --json` prints. `saw hook install` and `saw hook repair` print it too."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class Obstacle:
    """One reason saw's hooks may not run. `repair` is empty when the sentence names no command."""

    code: str
    message: str
    repair: str


@dataclass(frozen=True)
class Problem:
    """One problem the status report names. `repair` is empty when the sentence names no command."""

    code: str
    message: str
    repair: str


@dataclass(frozen=True)
class Posture:
    """Whether scan-on-clone is in place, and what would stop it."""

    installed: bool
    events: tuple[str, ...]
    via: tuple[str, ...]
    disabled_by_env: bool
    problems: tuple[Problem, ...]


def problem(code: str, message: str, repair: str) -> Problem:
    """Name one problem.

    Takes its stable code, the sentence the report shows, and the command that addresses it.
    Returns the problem. `repair` is empty when the sentence names no command."""
    return Problem(code, message, repair)


def as_dict(posture: Posture, changed: list[str] | None = None) -> dict[str, Any]:
    """Turn a posture into the document body, without a schema version.

    Takes the posture and, when a command changed something, the sentences that say what.
    Returns the body. `changed` is left out when it is None."""
    body: dict[str, Any] = {
        "installed": posture.installed,
        "events": list(posture.events),
        "via": list(posture.via),
        "disabled_by_env": posture.disabled_by_env,
        "problems": [{"code": item.code, "message": item.message, "repair": item.repair}
                     for item in posture.problems],
    }
    if changed is not None:
        body["changed"] = list(changed)
    return body
