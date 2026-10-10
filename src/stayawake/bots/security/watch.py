#!/usr/bin/env python3
"""One unattended pass: end the code this machine has identified, and remember the rest.

Narrower than `saw harden` on purpose: it ends only what the corpus identified and never asks for
privilege. What it declines is left for harden, which runs with an operator present.
"""
from __future__ import annotations

import time

from stayawake.bots.security import liveledger, schedule, watchrecord
from stayawake.bots.security.harden.live import end_live_code
from stayawake.bots.security.livecode import fingerprint, live_code_processes
from stayawake.utils import elevate, exitcodes
from stayawake.utils.procsnap import snapshot


BETWEEN_PASSES = 30

_ENDED = "Code running on this machine was stopped."
_RETURNED = "It has been stopped here before and is running again. Take this machine off the network."
_LEFT = "Something running here could not be stopped. Run `saw harden`."
_UNNAMED = "Something is running that this machine cannot identify."
_QUIET = "Nothing on this machine is running code it should not."
_NOT_READ = "Running processes could not be examined, so nothing here covers one."
_PASS_FAILED = "This machine could not check itself. Run `saw watch status`."
_NOT_TOLD = "What this machine found could not be recorded or announced. Run `saw watch status`."
_STALLED = "This machine is set to check itself but has not done so recently. Run `saw watch`."
_CAME_BACK = ("Code stopped here before came back and has not been dealt with. Take this machine "
              "off the network, then run `saw harden`.")
_SCHEDULED = "This machine will keep checking itself from now on."
_AT_LOGIN = "This machine will keep checking itself from your next login."
_ALREADY = "This machine was already checking itself."
_PUT_BACK = "The check this machine runs by itself had been changed. It has been put back."
_NOT_SCHEDULED = "This machine could not be asked to keep checking itself."
_UNSCHEDULED = "This machine will no longer check itself."
_WAS_NOT = "This machine was not checking itself."
_NOT_OURS = "Something else is there under that name. It has been left alone."
_CHECKING = "This machine is checking itself."
_FROM_LOGIN = "This machine will check itself from your next login. Run `saw watch` to start it now."
_NOT_CHECKING = "This machine is not checking itself. Run `saw watch`."
_WAS_CHANGED = "What checks this machine was changed. Run `saw watch` to put it back."
_CANNOT_TELL = "Whether this machine checks itself could not be established."


def _never_asks(pids, *, signatures):
    """Refuse privilege rather than seek it. Returns the refusal and nothing ended."""
    return elevate.CANNOT_ASK, []


ENDED, RETURNED, LEFT, UNNAMED, QUIET = "ended", "returned", "left", "unnamed", "quiet"
NOT_READ, PASS_FAILED = "not-read", "pass-failed"
SENTENCE_FOR = {ENDED: _ENDED, RETURNED: _RETURNED, LEFT: _LEFT, UNNAMED: _UNNAMED, QUIET: _QUIET,
                NOT_READ: _NOT_READ, PASS_FAILED: _PASS_FAILED}


def watch_once(**collaborators) -> tuple[int, str]:
    """Make one pass. Takes the collaborators `examine` takes. Returns the exit code and the lines
    an operator would read."""
    code, kinds = examine(**collaborators)
    return code, "\n".join(SENTENCE_FOR[kind] for kind in kinds)


def examine(*, find=None, stop=end_live_code, load=liveledger.load,
            save=liveledger.save, now=None, look=snapshot) -> tuple[int, tuple[str, ...]]:
    """Make one pass. Takes the collaborators that read the processes, end them and keep the
    ledger. Returns the exit code and what the pass found, as event kinds; a process table that
    could not be read is a pass that could not complete."""
    snap = look()
    if not snap.supported or not snap.processes:
        return exitcodes.INCOMPLETE, (NOT_READ,)
    again = find or live_code_processes
    before = load()
    seen = find() if find is not None else live_code_processes(snap)
    identified = [item for item in seen if item.confirmed]

    ending = None
    if identified:
        ending = stop(find=lambda: [i for i in again() if i.confirmed], elevated=_never_asks)

    ended_keys = set()
    if ending is not None and ending.ended:
        ended_keys = {fingerprint(item.code) for item in identified}
    save(liveledger.record(before, seen, ended_keys=ended_keys, now=now))

    returning = any(before.returning(fingerprint(item.code)) for item in identified)
    unfinished = ending is not None and not ending.finished

    kinds = []
    if ending is not None:
        kinds.append(ENDED)
        if returning:
            kinds.append(RETURNED)
        if unfinished:
            kinds.append(LEFT)
    if len(seen) > len(identified):
        kinds.append(UNNAMED)
    if not kinds:
        kinds.append(QUIET)

    if unfinished:
        return exitcodes.INCOMPLETE, tuple(kinds)
    if identified:
        return exitcodes.FINDINGS, tuple(kinds)
    return exitcodes.CLEAN, tuple(kinds)


def keep_going(*, once=examine, sleep=time.sleep, between=BETWEEN_PASSES, passes=None,
               report=print, tell=None) -> int:
    """Keep making the pass until stopped. Takes the pass, the pause between passes, an optional
    bound on how many passes to make, where a pass's lines are printed, and an optional `tell`
    called with each pass's event kinds. Returns the code of the last pass that ran."""
    code = exitcodes.CLEAN
    made = 0
    while passes is None or made < passes:
        try:
            code, kinds = once()
        except Exception:
            code, kinds = exitcodes.INCOMPLETE, (PASS_FAILED,)
        if code != exitcodes.CLEAN:
            report("\n".join(SENTENCE_FOR[kind] for kind in kinds))
        if tell is not None:
            try:
                tell(kinds)
            except Exception:
                report(_NOT_TOLD)
        made += 1
        if passes is None or made < passes:
            sleep(between)
    return code


def schedule_it(*, settle=schedule.settle) -> tuple[int, str]:
    """Ask this machine to keep making the pass. Returns the exit code and one line."""
    out = settle()
    if out.problem:
        return exitcodes.INCOMPLETE, _NOT_SCHEDULED
    if out.state == schedule.REPLACED:
        return exitcodes.CLEAN, _PUT_BACK
    if not out.changed:
        return exitcodes.CLEAN, _ALREADY
    return exitcodes.CLEAN, _SCHEDULED if out.active else _AT_LOGIN


def status_of(*, supported=schedule.supported, verdict=schedule.verdict,
              running=schedule.is_running, record=None, clock=time.time) -> tuple[int, str]:
    """Say whether this machine is checking itself. Takes the collaborators that read the schedule
    and the watcher's record. Returns the exit code and the lines an operator reads."""
    code, line = _schedule_status(supported, verdict, running)
    kept = (record or watchrecord.load)()
    if code == exitcodes.CLEAN and kept and watchrecord.stale(kept, clock()):
        code, line = exitcodes.FINDINGS, _STALLED
    if kept.get("unacknowledged"):
        line += "\n" + _CAME_BACK
    return code, line


def foreground_notice(*, record=None, placed=schedule.was_placed, clock=time.time) -> str:
    """Build the line any foreground command prints about the watcher. Takes the collaborators that
    read the record and the placement. Returns the line, or "" when there is nothing to say."""
    try:
        kept = (record or watchrecord.load)()
        if not kept or not placed():
            return ""
        if kept.get("unacknowledged"):
            return _CAME_BACK
        return _STALLED if watchrecord.stale(kept, clock()) else ""
    except Exception:
        return ""


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


def unschedule_it(*, remove=schedule.take_back) -> tuple[int, str]:
    """Stop this machine making the pass. Removes only what saw placed."""
    state = remove()
    if state == schedule.REMOVED:
        return exitcodes.CLEAN, _UNSCHEDULED
    if state == schedule.NOTHING_TO_REMOVE:
        return exitcodes.CLEAN, _WAS_NOT
    return exitcodes.INCOMPLETE, _NOT_OURS
