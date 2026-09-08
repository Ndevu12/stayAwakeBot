#!/usr/bin/env python3
"""Freeze a process, end it, and prove it ended — by identity, never by pid alone.

Every signal here is guarded by the identity the caller read earlier. A pid is a reusable handle:
between reading the process table and acting on it the process can exit and a stranger can inherit
the number, so signalling on a pid alone eventually kills something innocent. Nothing in this module
sends a signal without first confirming the process still has the start time it had.
"""
from __future__ import annotations

import os
import signal
import time

from stayawake.utils.procsnap import GONE, NOT_OURS, RUNNING, UNSUPPORTED, Identity, identify

#: What acting on a process did.
SIGNALLED = "signalled"           # the signal was delivered to the process we meant
ALREADY_GONE = "already-gone"     # it was not executing by the time we reached it
RECYCLED = "recycled"             # the pid is now a different process — refused, never signalled
REFUSED = "refused"               # it is running and not ours; we may not signal it

_SETTLE_SECONDS = 2.0
_POLL_SECONDS = 0.02


def _still(known: Identity) -> tuple[str, Identity | None]:
    """Whether that pid is still the process `known` describes.

    macOS reports a start time in whole seconds, so a pid and a start time alone can be shared by
    two processes started in the same second. The uid is compared as well; the ppid deliberately is
    not, because a process whose parent exits is reparented and would then be refused — which would
    leave an implant running.
    """
    pid = known.pid
    who, state = identify(pid)
    if state == NOT_OURS:
        return REFUSED, None
    if state in (GONE, UNSUPPORTED) or who is None:
        return ALREADY_GONE, None
    if who.zombie:
        return ALREADY_GONE, who          # killed, awaiting reap — it executes nothing
    if (who.start_time, who.uid) != (known.start_time, known.uid):
        return RECYCLED, who
    return RUNNING, who


def _send(known: Identity, sig: int) -> str:
    """Deliver `sig` to the process `known` describes, or say why not."""
    verdict, _who = _still(known)
    if verdict != RUNNING:
        return verdict
    try:
        os.kill(known.pid, sig)
    except ProcessLookupError:
        return ALREADY_GONE
    except PermissionError:
        return REFUSED
    except OSError:
        return REFUSED
    return SIGNALLED


def freeze(known: Identity) -> str:
    """Stop the process running, without ending it.

    SIGSTOP cannot be caught, blocked or ignored, so a handler cannot use its last moment to wipe,
    re-exec or spawn a replacement. A frozen process also cannot fork, which is what makes a
    population of them shrink instead of racing the caller.
    """
    return _send(known, signal.SIGSTOP)


def resume(known: Identity) -> str:
    """Let a frozen process run again — for a caller that froze something and then decided not to
    end it. Without this, a bailed-out run leaves the machine holding stopped processes."""
    return _send(known, signal.SIGCONT)


def end(known: Identity) -> str:
    """End the process. SIGKILL, never SIGTERM: a terminate handler is code the implant chose."""
    return _send(known, signal.SIGKILL)


def has_ended(known: Identity, *, settle: float = _SETTLE_SECONDS,
              sleep=time.sleep, clock=time.monotonic) -> bool:
    """Whether that process is no longer executing. Polled, because SIGKILL is not instantaneous.

    `os.kill(pid, 0)` is the wrong instrument and this is why: a killed process whose parent has not
    reaped it still answers that check, so a caller using it reports a dead implant as alive. The
    identity read answers ESRCH for the same process, and a zombie executes nothing.
    """
    deadline = clock() + settle
    while True:
        verdict, _who = _still(known)
        if verdict in (ALREADY_GONE, RECYCLED):
            return True
        if verdict == REFUSED:
            return False
        if clock() >= deadline:
            return False
        sleep(_POLL_SECONDS)
