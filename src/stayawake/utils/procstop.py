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

from stayawake.utils import elevate
from stayawake.utils.procsnap import (GONE, NOT_OURS, RUNNING, UNSUPPORTED, Identity, identify,
                                      ps_signature)

#: What acting on a process did.
SIGNALLED = "signalled"           # the signal was delivered to the process we meant
ALREADY_GONE = "already-gone"     # it was not executing by the time we reached it
RECYCLED = "recycled"             # the pid is now a different process — refused, never signalled
REFUSED = "refused"               # it is running and not ours; we may not signal it
NEEDS_PRIVILEGE = "needs-privilege"   # ours to end only as root — ask, do not give up on it

_KILL_PATHS = ("/bin/kill", "/usr/bin/kill")

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
        return NEEDS_PRIVILEGE, None
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
        # Not the end of it. This is the one case worth asking about, and saying "refused" here is
        # what left another user's implant running on a machine the operator does own.
        return NEEDS_PRIVILEGE
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
        if verdict in (REFUSED, NEEDS_PRIVILEGE):
            return False
        if clock() >= deadline:
            return False
        sleep(_POLL_SECONDS)


def _kill_binary() -> str | None:
    for candidate in _KILL_PATHS:
        if os.path.exists(candidate):
            return candidate
    return None


def end_as_root(pids: list[int], *, signatures: dict[int, str],
                run_as_root=elevate.run_as_root, signature=ps_signature) -> tuple[str, list[int]]:
    """End processes that are only endable as root, asking for privilege once for all of them.

    The signature each pid had is re-read first and compared: a pid this user cannot read can still
    be recycled, and asking root to kill a stale one is the same mistake with worse consequences.
    Frozen first for the same reason as everywhere else — a spawner that is asked to die politely
    forks before it goes.
    """
    still = [pid for pid in pids if signature(pid) == signatures.get(pid)]
    if not still:
        return elevate.GRANTED, []
    binary = _kill_binary()
    if binary is None:
        return elevate.NOT_AVAILABLE, []
    named = [str(pid) for pid in still]
    outcome, _detail = run_as_root([binary, "-STOP", *named])
    if outcome != elevate.GRANTED:
        return outcome, []
    run_as_root([binary, "-KILL", *named])
    ended = [pid for pid in still if signature(pid) is None]
    return elevate.GRANTED, ended
