#!/usr/bin/env python3
"""Whether this machine is still checking itself, whether it stopped without being told to, and
what its watcher found that is not dealt with."""
from __future__ import annotations

import time

from stayawake.bots.security import schedule, watchack, watchrecord, watchstate

from .models import HygieneIssue

STOPPED_ID = "self-check-stopped"
CAME_BACK_ID = "self-check-code-came-back"
NOT_STOPPED_ID = "self-check-code-not-stopped"

_DOCS = ("https://github.com/Ndevu12/stayAwakeBot/blob/main/docs/how-to/audit-a-machine.md"
         "#what-a-clean-audit-does-and-does-not-mean")
_FOUND = {
    watchstate.CAME_BACK: (CAME_BACK_ID, "Code this machine stopped before came back",
                           "It is running again and has not been dealt with.",
                           watchstate.DEAL_WITH_IT),
    watchstate.NOT_STOPPED: (NOT_STOPPED_ID, "Code running on this machine could not be stopped",
                             "The watcher found it and could not end it.", "Run `saw harden`."),
}


def check_self_check(placed=schedule.was_placed, verdict=schedule.verdict,
                     running=schedule.is_running, supported=schedule.supported,
                     record=watchrecord.load, clock=time.time,
                     placed_since=schedule.placed_since,
                     acknowledged=watchack.load_acknowledgement) -> list[HygieneIssue]:
    """Report a check this machine was set to make and is no longer making, and what its watcher
    found that is not dealt with. Takes the collaborators that read the schedule, the watcher's
    record and `saw harden`'s acknowledgement. Returns the issues; a check that cannot be read
    raises, so the audit reports it as not completed."""
    if not supported():
        return []
    state = verdict() if placed() else None
    held = state == schedule.PRISTINE and running()
    kept = watchack.settled(record(), acknowledged())
    matters = watchstate.still_open(kept, now=clock(), placed=held, placed_since=placed_since())
    issues = _schedule_issues(state) if state is not None and not held else []
    if any(m.kind == watchstate.NOT_CHECKING for m in matters):
        issues.append(_issue(STOPPED_ID, "This machine stopped checking itself",
                             "It is set to check itself and has not done so recently.",
                             "Run `saw watch stop`, then `saw watch`."))
    issues += [_issue(*_FOUND[m.kind]) for m in matters if m.kind in _FOUND]
    return issues


def _schedule_issues(state: str) -> list[HygieneIssue]:
    """Report a scheduled check that is not held. Takes what the scheduled item is to saw. Returns
    the issue."""
    if state == schedule.PRISTINE:
        return [_issue(STOPPED_ID, "This machine stopped checking itself",
                       "It is set to check itself and is not doing so.", "Run `saw watch`.")]
    return [_issue(STOPPED_ID, "What was checking this machine is gone",
                   "It was set to check itself; what does that is no longer there.",
                   "Run `saw watch`.")]


def _issue(issue_id: str, title: str, detail: str, remediation: str) -> HygieneIssue:
    """Build one warning of this check. Takes its id, title, detail and remediation. Returns it."""
    return HygieneIssue(id=issue_id, severity="warning", title=title, detail=detail,
                        remediation=remediation, reference=_DOCS)
