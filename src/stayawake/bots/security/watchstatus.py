#!/usr/bin/env python3
"""What saw says about the watcher where the user reads it: `saw watch status`, and the line every
other command prints while something is open."""
from __future__ import annotations

import time

from stayawake.bots.security import schedule, watchack, watchrecord, watchstate
from stayawake.utils import exitcodes

_CHECKING = "This machine is checking itself."
_FROM_LOGIN = "This machine will check itself from your next login. Run `saw watch` to start it now."
_NOT_CHECKING = "This machine is not checking itself. Run `saw watch`."
_WAS_CHANGED = "What checks this machine was changed. Run `saw watch` to put it back."
_CANNOT_TELL = "Whether this machine checks itself could not be established."
_STALLED = ("This machine is set to check itself but has not done so recently. Run `saw watch stop`, "
            "then `saw watch`.")


def status_of(*, supported=schedule.supported, verdict=schedule.verdict,
              running=schedule.is_running, record=None, clock=time.time,
              placed_since=schedule.placed_since, acknowledged=None) -> tuple[int, str]:
    """Say where the watcher stands. Takes the collaborators that read the schedule, the watcher's
    record and `saw harden`'s acknowledgement. Returns the exit code and the lines an operator
    reads: whether the machine checks itself, everything still open, and what happened since the
    last report."""
    code, line = _schedule_status(supported, verdict, running)
    kept = _settled_record(record, acknowledged)
    matters = watchstate.still_open(kept, now=clock(), placed=code == exitcodes.CLEAN,
                                    placed_since=placed_since())
    stalled = any(m.kind == watchstate.NOT_CHECKING for m in matters)
    lines = [_STALLED] if stalled else [line]
    lines += [m.line for m in matters if m.kind != watchstate.NOT_CHECKING]
    said = watchstate.what_happened(kept.get("since", {}))
    if said:
        lines.append(" ".join([watchstate.since_heading(kept)] + said))
    if any(m.urgent for m in matters):
        code = max(code, exitcodes.FINDINGS)
    return code, "\n".join(lines)


def foreground_notice(*, record=None, placed=schedule.was_placed, clock=time.time,
                      placed_since=schedule.placed_since, acknowledged=None) -> str:
    """Build the line every other command prints. Takes the collaborators that read the record,
    the placement and `saw harden`'s acknowledgement. Returns every urgent matter still open as one
    line, or "" when none is; never fails."""
    try:
        kept = _settled_record(record, acknowledged)
        matters = watchstate.still_open(kept, now=clock(), placed=placed(),
                                        placed_since=placed_since())
        return " ".join(m.line for m in matters if m.urgent)
    except Exception:
        return ""


def _settled_record(record, acknowledged) -> dict:
    """Read the watcher's record with `saw harden`'s acknowledgement applied. Takes the two
    readers, or None for the real ones. Returns the record."""
    return watchack.settled((record or watchrecord.load)(),
                            (acknowledged or watchack.load_acknowledgement)())


def _schedule_status(supported, verdict, running) -> tuple[int, str]:
    """Read whether the scheduled check is in place and held. Takes the schedule's collaborators.
    Returns the exit code and one line."""
    if not supported():
        return exitcodes.INCOMPLETE, _CANNOT_TELL
    try:
        state = verdict()
    except Exception:
        return exitcodes.INCOMPLETE, _CANNOT_TELL
    if state == schedule.ABSENT:
        return exitcodes.FINDINGS, _NOT_CHECKING
    if state != schedule.PRISTINE:
        return exitcodes.FINDINGS, _WAS_CHANGED
    return (exitcodes.CLEAN, _CHECKING) if running() else (exitcodes.FINDINGS, _FROM_LOGIN)
