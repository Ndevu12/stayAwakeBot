#!/usr/bin/env python3
"""What saw says about the watcher where the user reads it: `saw watch status`, the document
`saw watch status --json` prints, and the line every other command prints while something is open."""
from __future__ import annotations

import time
from dataclasses import dataclass

from stayawake.bots.security import schedule, watchack, watchrecord, watchstate
from stayawake.utils import exitcodes
from stayawake.utils.json_documents import versioned

_CHECKING = "`saw watch` is in place."
_FROM_LOGIN = "`saw watch` will be in place from your next login. Run `saw watch` to start it now."
_NOT_CHECKING = "`saw watch` is not in place. Run `saw watch`."
_WAS_CHANGED = "`saw watch` had been changed on this machine. Run `saw watch` to put it back."
_CANNOT_TELL = "Whether `saw watch` is in place could not be established."
_STALLED = ("`saw watch` is in place but has not run recently. Run `saw watch stop`, then "
            "`saw watch`.")

IN_PLACE, FROM_NEXT_LOGIN, NOT_IN_PLACE, CHANGED, COULD_NOT_TELL = (
    "in-place", "from-next-login", "not-in-place", "changed", "could-not-tell")


@dataclass(frozen=True)
class Standing:
    """Where the watcher stands, as facts the sentences and the JSON document both read from."""
    code: int
    schedule: str
    schedule_line: str
    matters: list
    since_heading: str
    since_lines: list


def status_of(*, supported=schedule.supported, verdict=schedule.verdict,
              running=schedule.is_running, record=None, clock=time.time,
              placed_since=schedule.placed_since, acknowledged=None) -> tuple[int, str]:
    """Say where the watcher stands. Takes the collaborators that read the schedule, the watcher's
    record and `saw harden`'s acknowledgement. Returns the exit code and the lines an operator
    reads: whether `saw watch` is in place, everything still open, and what happened since the
    last report."""
    s = _standing(supported, verdict, running, record, clock, placed_since, acknowledged)
    stalled = any(m.kind == watchstate.NOT_CHECKING for m in s.matters)
    lines = [_STALLED] if stalled else [s.schedule_line]
    lines += [m.line for m in s.matters if m.kind != watchstate.NOT_CHECKING]
    if s.since_lines:
        lines.append(" ".join([s.since_heading] + s.since_lines))
    return s.code, "\n".join(lines)


def status_document(*, supported=schedule.supported, verdict=schedule.verdict,
                    running=schedule.is_running, record=None, clock=time.time,
                    placed_since=schedule.placed_since, acknowledged=None) -> tuple[int, dict]:
    """Build the `watch-status` document. Takes the same collaborators as `status_of`. Returns the
    exit code and the document: the schedule, every matter still open, and what happened since the
    last report, with no paths and no process numbers. Exit codes match `status_of`."""
    s = _standing(supported, verdict, running, record, clock, placed_since, acknowledged)
    body: dict = {
        "schedule": s.schedule,
        "matters": [{"kind": m.kind, "line": m.line, "urgent": m.urgent} for m in s.matters],
    }
    if s.since_lines:
        body["since"] = {"heading": s.since_heading, "lines": list(s.since_lines)}
    return s.code, versioned("watch-status", body)


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


def _standing(supported, verdict, running, record, clock, placed_since, acknowledged) -> Standing:
    """Read where the watcher stands. Takes the schedule's collaborators, the record reader and
    `saw harden`'s acknowledgement. Returns the facts."""
    kind, code, line = _schedule_status(supported, verdict, running)
    kept = _settled_record(record, acknowledged)
    matters = watchstate.still_open(kept, now=clock(), placed=code == exitcodes.CLEAN,
                                    placed_since=placed_since())
    said = watchstate.what_happened(kept.get("since", {}))
    if any(m.urgent for m in matters):
        code = max(code, exitcodes.FINDINGS)
    return Standing(code, kind, line, matters, watchstate.since_heading(kept), said)


def _settled_record(record, acknowledged) -> dict:
    """Read the watcher's record with `saw harden`'s acknowledgement applied. Takes the two
    readers, or None for the real ones. Returns the record."""
    return watchack.settled((record or watchrecord.load)(),
                            (acknowledged or watchack.load_acknowledgement)())


def _schedule_status(supported, verdict, running) -> tuple[str, int, str]:
    """Read whether the scheduled check is in place and held. Takes the schedule's collaborators.
    Returns the schedule state, the exit code and one line."""
    if not supported():
        return COULD_NOT_TELL, exitcodes.INCOMPLETE, _CANNOT_TELL
    try:
        state = verdict()
    except Exception:
        return COULD_NOT_TELL, exitcodes.INCOMPLETE, _CANNOT_TELL
    if state == schedule.ABSENT:
        return NOT_IN_PLACE, exitcodes.FINDINGS, _NOT_CHECKING
    if state != schedule.PRISTINE:
        return CHANGED, exitcodes.FINDINGS, _WAS_CHANGED
    if running():
        return IN_PLACE, exitcodes.CLEAN, _CHECKING
    return FROM_NEXT_LOGIN, exitcodes.FINDINGS, _FROM_LOGIN
