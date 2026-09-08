#!/usr/bin/env python3
"""Host-level acting — create denials on this machine. Never touches a project's tree."""
from __future__ import annotations

from stayawake.bots.security import hookscript
from stayawake.bots.security.hygiene.host_artifacts import _global_folders
from stayawake.bots.security.hygiene.models import PROCESSES_NOT_READABLE_ID
from stayawake.bots.security.hygiene.outcome import BLOCKED, run_probe
from stayawake.bots.security.hygiene.process import check_live_processes
from .live import end_live_code
from stayawake.utils import hostdenial, textsafe
from .denial import (ENFORCING, HELD_BY_ANOTHER, IN_A_LIVE_INSTALL, LEFT_OPEN_OVER_CONTENT,
                     NEEDS_ROOT, NOT_HERE_YET, LOCKED_OVER_CONTENT, NOTHING_TO_REMOVE,
                     NOT_WHERE_IT_WAS_NAMED, OCCUPIED, REMOVED, SELF_ENFORCING, UNKNOWN,
                     PathOutcome, apply_one, remove_one)

__all__ = ["run", "apply_one", "PathOutcome", "ENFORCING", "SELF_ENFORCING",
           "NEEDS_ROOT", "IN_A_LIVE_INSTALL", "NOT_HERE_YET", "REMOVED",
           "NOTHING_TO_REMOVE", "LOCKED_OVER_CONTENT", "LEFT_OPEN_OVER_CONTENT",
           "HELD_BY_ANOTHER", "NOT_WHERE_IT_WAS_NAMED", "UNKNOWN", "OCCUPIED",
           "remove_one", "take_back"]


_LIVE = "live-obfuscated-process"

_ENDED_LIVE = "Code that is not on disk was running here. It was captured and ended."
_STILL_LIVE = "Code that is not on disk is still running here, so the control was not applied."
_NOT_OURS_LIVE = "Run again where a password can be answered, or as root."
_STILL_SPAWNING = "They are being started again. Run again once the machine is off the network."
_REFUSED_UNREAD = (
    "Running processes could not be examined, so this control was not applied."
)
_REFUSED_BLOCKED = (
    "Running processes could not be examined, so this control was not applied. "
    "The check stopped on: {reason}"
)
_CAPTURE_EXCERPT = 300
_NOT_HERE = "This control is not implemented on this platform."
_CLAIM = (
    "The observed staging path is denied. A payload that guards the write and uses "
    "the runtime's built-in transport is unaffected."
)
_SOME_ARE_YOURS = (
    "Some of these are held by you rather than by root. An unguarded write to one still fails, "
    "but code running as you can take the lock off first. Run again with sudo to raise them."
)
_NEEDS_ROOT_NOTE = (
    "One or more locations are not yours to write to. Run again with sudo to take those as well."
)
_NOT_EVERYWHERE = (
    "This control is NOT in place. This command deletes nothing, and every location below says "
    "what was done to it — inspect each one yourself and do NOT rotate any credential until you "
    "have."
)
_LEFT_OPEN_NOTE = (
    "Something is sitting in a location that is meant to stay empty. It has been left reachable "
    "rather than locked over, so you can read it — do that before anything else."
)
_DEAD_SAW_NOTE = (
    "The saw that saw's git hooks call is gone or cannot run, so clones are not scanned. "
    "`saw hook repair` points the hooks at this saw."
)
_ALTERED_HOOKS_NOTE = (
    "Where saw's git hooks run, something is not what saw installed. This command does not touch "
    "hooks; `saw hook repair` puts them back and keeps what it moves aside:"
)


_TOOK_BACK = "Every control this tool placed here has been taken back."
_NOT_ALL_BACK = ("Not every control was taken back. This command deletes nothing, and every "
                 "location below says what was done to it.")


def take_back(*, folders=_global_folders, remove=remove_one,
              supported=hostdenial.platform_supported) -> tuple[int, str]:
    """Remove the denials this tool placed. Removed only after a read-back says the path is gone.

    No capture gate here: this opens a location rather than closing one, so it cannot crash a
    process that a payload is holding open — which is the reason applying one waits for capture.

    A location holding content is never settled, locked or open: counting it as one reported a
    machine as back to normal over content nobody had read.
    """
    if not supported():
        return 2, _NOT_HERE
    outcomes = [remove(p) for p in folders()]
    settled = {REMOVED, NOTHING_TO_REMOVE}
    done = bool(outcomes) and all(o.state in settled for o in outcomes)
    lines = [_TOOK_BACK if done else _NOT_ALL_BACK, ""]
    if any(o.state == LEFT_OPEN_OVER_CONTENT for o in outcomes):
        lines.extend([_LEFT_OPEN_NOTE, ""])
    for o in outcomes:
        lines.append(f"  {o.state}: {o.path} — {o.detail}")
    return (0, "\n".join(lines).rstrip()) if done else (3, "\n".join(lines).rstrip())


def _ending_line(ending) -> str:
    """One line for a whole population. What this replaced printed one line per process, and a
    measured run produced 135 of them."""
    if ending.matched == 0:
        return "  it had already exited before this command reached it"
    bits = [f"  {ending.ended} of {ending.matched} ended"]
    if ending.survived:
        bits.append(f"{len(ending.survived)} did not end ({_pids(ending.survived)})")
    if ending.asked_for:
        bits.append(f"{len(ending.asked_for)} needed privilege ({ending.asking or 'not asked'})")
    if ending.refused:
        bits.append(f"{len(ending.refused)} still not ended ({_pids(ending.refused)})")
    if ending.frozen_left:
        bits.append(f"{len(ending.frozen_left)} stopped and contained ({_pids(ending.frozen_left)})"
                    " — release with kill -CONT if one of them is yours")
    if ending.still_holding:
        bits.append(f"{ending.still_holding} still running")
    if ending.captured:
        bits.append(f"captured to {textsafe.plain(ending.captured, limit=4096)}")
    return ", ".join(bits)


def _pids(pids: list[int], shown: int = 8) -> str:
    head = ", ".join(str(p) for p in pids[:shown])
    return head if len(pids) <= shown else f"{head}, and {len(pids) - shown} more"


def run(*, live=check_live_processes, folders=_global_folders,
        apply=apply_one, supported=hostdenial.platform_supported,
        altered=hookscript.altered_hooks, saw_runs=hookscript.recorded_saw_runs,
        stop=end_live_code) -> tuple[int, str]:
    """Apply the denial at every global-resolution entry. Enforcing only after read-back.

    Root is asked of the PATH rather than of the command. Most of these locations belong to the
    operator, so requiring privilege for the whole run withheld a control they could have had from
    every person unwilling to give a security tool root — while the locations that need it are
    named, not silently skipped.

    Every note that applies is printed, not the first that matches: a chain dropped whichever came
    second, and a run can hold both.
    """
    if not supported():
        return 2, _NOT_HERE
    outcome = run_probe("running processes", live)
    if outcome.state == BLOCKED:
        return 1, _REFUSED_BLOCKED.format(reason=textsafe.plain(outcome.reason or "", limit=200))
    issues = list(outcome.issues)
    if any(i.id == PROCESSES_NOT_READABLE_ID for i in issues):
        return 1, _REFUSED_UNREAD
    # Standing down here is what a compromised host used to get: the worse the machine, the less
    # this command did, and the controls it declined are the ones that stop the next re-infection.
    ending = None
    if [i for i in issues if i.id == _LIVE]:
        # This one signals real processes, so a raise inside it is the difference between a report
        # and a traceback. Guarded here rather than by `run_probe`, which returns issues.
        try:
            ending = stop()
        except Exception as exc:                  # never let it take the command down
            return 1, (f"{_STILL_LIVE}\n\n  the attempt stopped on: "
                       f"{textsafe.plain(f'{type(exc).__name__}: {exc}', limit=200)}")
        if not ending.finished:
            lines = [_STILL_LIVE, ""]
            if ending.refused:
                lines += [_NOT_OURS_LIVE, ""]
            if not ending.quiet:
                lines += [_STILL_SPAWNING, ""]
            lines.append(_ending_line(ending))
            return 1, "\n".join(lines)

    outcomes = [apply(p) for p in folders()]
    took = {ENFORCING, SELF_ENFORCING}
    applied = bool(outcomes) and all(o.state in took for o in outcomes)
    headline = _CLAIM if applied else _NOT_EVERYWHERE
    lines = [headline, ""]
    if ending is not None:
        lines.extend([_ENDED_LIVE, _ending_line(ending), ""])
    states = {o.state for o in outcomes}
    for note, fires in ((_SOME_ARE_YOURS, applied and SELF_ENFORCING in states),
                        (_LEFT_OPEN_NOTE, LEFT_OPEN_OVER_CONTENT in states),
                        (_NEEDS_ROOT_NOTE, NEEDS_ROOT in states)):
        if fires:
            lines.extend([note, ""])
    for o in outcomes:
        lines.append(f"  {o.state}: {o.path} — {o.detail}")
    hooks = altered()
    if hooks:
        lines.extend(["", _ALTERED_HOOKS_NOTE] + [f"  {textsafe.plain(str(p), limit=4096)}" for p in hooks])
    if not saw_runs():
        lines.extend(["", _DEAD_SAW_NOTE])
    body = "\n".join(lines).rstrip()
    return (0, body) if applied else (3, body)
