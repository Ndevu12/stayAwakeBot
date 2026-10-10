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
    kinds = {m.kind for m in matters}
    if watchstate.NOT_CHECKING in kinds:
        issues.append(HygieneIssue(
            id=STOPPED_ID, severity="warning", title="This machine stopped checking itself",
            detail="It is set to check itself and has not done so recently.",
            remediation="Run `saw watch stop`, then `saw watch`.", reference=_DOCS))
    if watchstate.CAME_BACK in kinds:
        issues.append(HygieneIssue(
            id=CAME_BACK_ID, severity="warning", title="Code this machine stopped before came back",
            detail="It is running again and has not been dealt with.",
            remediation="Run `saw harden`, then `saw audit` to find what brings it back.",
            reference=_DOCS))
    if watchstate.NOT_STOPPED in kinds:
        issues.append(HygieneIssue(
            id=NOT_STOPPED_ID, severity="warning",
            title="Code running on this machine could not be stopped",
            detail="The watcher found it and could not end it.", remediation="Run `saw harden`.",
            reference=_DOCS))
    return issues


def _schedule_issues(state: str) -> list[HygieneIssue]:
    """Report a scheduled check that is not held. Takes what the scheduled item is to saw. Returns
    the issue."""
    if state == schedule.PRISTINE:
        return [HygieneIssue(id=STOPPED_ID, severity="warning",
                             title="This machine stopped checking itself",
                             detail="It is set to check itself and is not doing so.",
                             remediation="Run `saw watch`.", reference=_DOCS)]
    return [HygieneIssue(id=STOPPED_ID, severity="warning",
                         title="What was checking this machine is gone",
                         detail="It was set to check itself; what does that is no longer there.",
                         remediation="Run `saw watch`.", reference=_DOCS)]
