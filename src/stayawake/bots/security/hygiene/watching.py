#!/usr/bin/env python3
"""Whether this machine is still checking itself, and whether it stopped without being told to."""
from __future__ import annotations

from stayawake.bots.security import schedule

from .models import HygieneIssue

STOPPED_ID = "self-check-stopped"

_DOCS = ("https://github.com/Ndevu12/stayAwakeBot/blob/main/docs/how-to/audit-a-machine.md"
         "#what-a-clean-audit-does-and-does-not-mean")


def check_self_check(placed=schedule.was_placed, verdict=schedule.verdict,
                     running=schedule.is_running,
                     supported=schedule.supported) -> list[HygieneIssue]:
    """Report a check this machine was set to make and is no longer making."""
    if not supported() or not placed():
        return []
    try:
        state = verdict()
        loaded = running()
    except Exception:
        return []
    if state == schedule.PRISTINE and loaded:
        return []
    if state == schedule.PRISTINE:
        return [HygieneIssue(
            id=STOPPED_ID, severity="warning",
            title="This machine stopped checking itself",
            detail="It is set to check itself and is not doing so.",
            remediation="Run `saw watch`.", reference=_DOCS)]
    return [HygieneIssue(
        id=STOPPED_ID, severity="warning",
        title="What was checking this machine is gone",
        detail="It was set to check itself; what does that is no longer there.",
        remediation="Run `saw watch`.", reference=_DOCS)]
