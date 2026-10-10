#!/usr/bin/env python3
"""One unattended pass: end the code this machine has identified, and remember the rest.

Narrower than `saw harden` on purpose: it ends only what the corpus identified and never asks for
privilege. What it declines is left for harden, which runs with an operator present.
"""
from __future__ import annotations

import time

from stayawake.bots.security import liveledger, schedule
from stayawake.bots.security.watchevents import (
    ENDED, LEFT, NOT_READ, NOT_REMEMBERED, PASS_FAILED, QUIET, RETURNED, SENTENCE_FOR, UNNAMED)
from stayawake.bots.security.harden.live import end_live_code
from stayawake.bots.security.livecode import fingerprint, live_code_processes
from stayawake.utils import elevate, exitcodes
from stayawake.utils.procsnap import snapshot


BETWEEN_PASSES = 30

_NOT_TOLD = "What this machine found could not be recorded or announced. Run `saw watch status`."
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
    try:
        before = load()
    except Exception:
        before = liveledger.Ledger(status=liveledger.CORRUPT)
    seen = find() if find is not None else live_code_processes(snap)
    identified = [item for item in seen if item.confirmed]

    ending = None
    if identified:
        ending = stop(find=lambda: [i for i in again() if i.confirmed], elevated=_never_asks)

    ended_something = ending is not None and ending.ended > 0
    ended_keys = {fingerprint(item.code) for item in identified} if ended_something else set()
    try:
        kept = bool(save(liveledger.record(before, seen, ended_keys=ended_keys, now=now)))
    except Exception:
        kept = False
    remembered = kept and before.status in (liveledger.LOADED, liveledger.ABSENT)

    came_back = any(before.ended_before(fingerprint(item.code)) for item in identified)
    unfinished = ending is not None and not ending.finished

    kinds = []
    if ended_something:
        kinds.append(ENDED)
    if came_back:
        kinds.append(RETURNED)
    if unfinished:
        kinds.append(LEFT)
    if len(seen) > len(identified):
        kinds.append(UNNAMED)
    if not remembered:
        kinds.append(NOT_REMEMBERED)
    if not kinds:
        kinds.append(QUIET)

    if unfinished or not remembered:
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
            _print_safely(report, "\n".join(SENTENCE_FOR[kind] for kind in kinds))
        if tell is not None:
            try:
                tell(kinds)
            except Exception:
                _print_safely(report, _NOT_TOLD)
        made += 1
        if passes is None or made < passes:
            sleep(between)
    return code


def _print_safely(report, text: str) -> None:
    """Print a pass's lines without letting a broken output end the watch. Takes the printer and
    the text."""
    try:
        report(text)
    except Exception:
        pass


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
