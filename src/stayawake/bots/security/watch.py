#!/usr/bin/env python3
"""One unattended pass: end the code this machine has identified, and remember the rest.

Narrower than `saw harden` on purpose: it ends only what the corpus identified and never asks for
privilege. What it declines is left for harden, which runs with an operator present.
"""
from __future__ import annotations

import time

from stayawake.bots.security import liveledger, schedule
from stayawake.bots.security.harden.live import end_live_code
from stayawake.bots.security.livecode import fingerprint, live_code_processes
from stayawake.utils import elevate, exitcodes


BETWEEN_PASSES = 30

_ENDED = "Code running on this machine was stopped."
_RETURNED = "It has been stopped here before and is running again. Take this machine off the network."
_LEFT = "Something running here could not be stopped. Run `saw harden`."
_UNNAMED = "Something is running that this machine cannot identify."
_QUIET = "Nothing on this machine is running code it should not."
_NOT_READ = "Running processes could not be examined, so nothing here covers one."
_SCHEDULED = "This machine will keep checking itself from now on."
_AT_LOGIN = "This machine will keep checking itself from your next login."
_ALREADY = "This machine was already checking itself."
_PUT_BACK = "The check this machine runs by itself had been changed. It has been put back."
_NOT_SCHEDULED = "This machine could not be asked to keep checking itself."
_UNSCHEDULED = "This machine will no longer check itself."
_WAS_NOT = "This machine was not checking itself."
_NOT_OURS = "Something else is there under that name. It has been left alone."


def _never_asks(pids, *, signatures):
    """Refuse privilege rather than seek it. Returns the refusal and nothing ended."""
    return elevate.CANNOT_ASK, []


def watch_once(*, find=live_code_processes, stop=end_live_code, load=liveledger.load,
               save=liveledger.save, now=None) -> tuple[int, str]:
    """Make one pass. Returns the exit code and the line an operator would read."""
    before = load()
    seen = find()
    identified = [item for item in seen if item.confirmed]

    ending = None
    if identified:
        ending = stop(find=lambda: [i for i in find() if i.confirmed], elevated=_never_asks)

    ended_keys = set()
    if ending is not None and ending.ended:
        ended_keys = {fingerprint(item.code) for item in identified}
    save(liveledger.record(before, seen, ended_keys=ended_keys, now=now))

    returning = any(before.returning(fingerprint(item.code)) for item in identified)
    unfinished = ending is not None and not ending.finished

    lines = []
    if ending is not None:
        lines.append(_ENDED)
        if returning:
            lines.append(_RETURNED)
        if unfinished:
            lines.append(_LEFT)
    if len(seen) > len(identified):
        lines.append(_UNNAMED)
    if not lines:
        lines.append(_QUIET)

    if unfinished:
        return exitcodes.INCOMPLETE, "\n".join(lines)
    if identified:
        return exitcodes.FINDINGS, "\n".join(lines)
    return exitcodes.CLEAN, "\n".join(lines)


def keep_going(*, once=watch_once, sleep=time.sleep, between=BETWEEN_PASSES, passes=None,
               report=print) -> int:
    """Keep making the pass until stopped. Returns the code of the last pass that ran.

    Takes an optional bound on how many passes to make; unbounded otherwise.

    TRAP: one bad pass must never end the watch.
    """
    code = exitcodes.CLEAN
    made = 0
    while passes is None or made < passes:
        try:
            code, text = once()
            if code != exitcodes.CLEAN:
                report(text)
        except Exception:
            code = exitcodes.INCOMPLETE
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


def unschedule_it(*, remove=schedule.take_back) -> tuple[int, str]:
    """Stop this machine making the pass. Removes only what saw placed."""
    state = remove()
    if state == schedule.REMOVED:
        return exitcodes.CLEAN, _UNSCHEDULED
    if state == schedule.NOTHING_TO_REMOVE:
        return exitcodes.CLEAN, _WAS_NOT
    return exitcodes.INCOMPLETE, _NOT_OURS
