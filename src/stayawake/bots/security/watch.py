#!/usr/bin/env python3
"""One unattended pass: end the code this machine has identified, and remember the rest.

Narrower than `saw harden` on purpose. Harden runs with an operator present, so it ends everything
it grades and may ask for privilege to do it. This runs with nobody watching, so it ends only what
the signature corpus identified, never asks for a password, and writes what it saw to the record
instead of raising an alarm about a shape it could not name.
"""
from __future__ import annotations

from stayawake.bots.security import liveledger
from stayawake.bots.security.harden.live import end_live_code
from stayawake.bots.security.livecode import fingerprint, live_code_processes
from stayawake.utils import elevate, exitcodes


_ENDED = "Code running on this machine was stopped."
_RETURNED = "It has been stopped here before and is running again. Take this machine off the network."
_LEFT = "Something running here could not be stopped. Run `saw harden`."
_UNNAMED = "Something is running that this machine cannot identify."
_QUIET = "Nothing on this machine is running code it should not."
_NOT_READ = "Running processes could not be examined, so nothing here covers one."


def _never_asks(pids, *, signatures):
    """Refuse privilege rather than seek it. Returns the refusal and nothing ended.

    Nobody is present to answer a password prompt, and a prompt nobody answers is a run that hangs
    where a scheduled one must not. What this declines is left for a foreground `saw harden`.
    """
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
        # Ended by identity, recorded by content: the ender counts processes, the record counts the
        # code they were running, and one payload is usually several processes.
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
