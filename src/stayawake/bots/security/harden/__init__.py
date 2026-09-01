#!/usr/bin/env python3
"""Host-level acting — create denials on this machine. Never touches a project's tree."""
from __future__ import annotations

from stayawake.bots.security.hygiene.host_artifacts import _global_folders
from stayawake.bots.security.hygiene.models import PROCESSES_NOT_READABLE_ID
from stayawake.bots.security.hygiene.process import check_live_processes
from stayawake.utils import hostdenial
from .denial import (ENFORCING, IN_A_LIVE_INSTALL, NEEDS_ROOT, NOT_HERE_YET,
                     NOTHING_TO_REMOVE, OCCUPIED, REMOVED, SELF_ENFORCING, UNKNOWN,
                     PathOutcome, apply_one, remove_one)

__all__ = ["run", "apply_one", "PathOutcome", "ENFORCING", "SELF_ENFORCING",
           "NEEDS_ROOT", "IN_A_LIVE_INSTALL", "NOT_HERE_YET", "REMOVED",
           "NOTHING_TO_REMOVE", "UNKNOWN", "OCCUPIED", "remove_one"]


_LIVE = "live-obfuscated-process"

_REFUSED_LIVE = (
    "A running process still holds code that is not on disk. "
    "Capture it before applying this control."
)
_REFUSED_UNREAD = (
    "Running processes could not be examined, so this control was not applied."
)
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
    "This control is NOT in place. Any location below that it did not take was left exactly as it "
    "stood — this command removes nothing — so inspect each one yourself and do NOT rotate any "
    "credential until you have."
)


_TOOK_BACK = "Every control this tool placed here has been taken back."
_NOT_ALL_BACK = ("Not every control was taken back. Anything below that is still in place was "
                 "left exactly as it stood.")


def take_back(*, folders=_global_folders, remove=remove_one,
              supported=hostdenial.platform_supported) -> tuple[int, str]:
    """Remove the denials this tool placed. Removed only after a read-back says the path is gone.

    No capture gate here: this opens a location rather than closing one, so it cannot crash a
    process that a payload is holding open — which is the reason applying one waits for capture.
    """
    if not supported():
        return 2, _NOT_HERE
    outcomes = [remove(p) for p in folders()]
    settled = {REMOVED, NOTHING_TO_REMOVE}
    done = bool(outcomes) and all(o.state in settled for o in outcomes)
    lines = [_TOOK_BACK if done else _NOT_ALL_BACK, ""]
    for o in outcomes:
        lines.append(f"  {o.state}: {o.path} — {o.detail}")
    return (0, "\n".join(lines).rstrip()) if done else (3, "\n".join(lines).rstrip())


def run(*, live=check_live_processes, folders=_global_folders,
        apply=apply_one, privileged=hostdenial.privileged,
        supported=hostdenial.platform_supported) -> tuple[int, str]:
    """Apply the denial at every global-resolution entry. Enforcing only after read-back.

    Root is asked of the PATH rather than of the command. Most of these locations belong to the
    operator, so requiring privilege for the whole run withheld a control they could have had from
    every person unwilling to give a security tool root — while the locations that need it are
    named, not silently skipped.
    """
    if not supported():
        return 2, _NOT_HERE
    issues = list(live())
    if any(i.id == PROCESSES_NOT_READABLE_ID for i in issues):
        return 1, _REFUSED_UNREAD
    if any(i.id == _LIVE for i in issues):
        return 1, _REFUSED_LIVE

    outcomes = [apply(p) for p in folders()]
    took = {ENFORCING, SELF_ENFORCING}
    applied = bool(outcomes) and all(o.state in took for o in outcomes)
    headline = _CLAIM if applied else _NOT_EVERYWHERE
    lines = [headline, ""]
    if applied and any(o.state == SELF_ENFORCING for o in outcomes):
        lines = [headline, "", _SOME_ARE_YOURS, ""]
    elif any(o.state == NEEDS_ROOT for o in outcomes):
        lines = [headline, "", _NEEDS_ROOT_NOTE, ""]
    for o in outcomes:
        lines.append(f"  {o.state}: {o.path} — {o.detail}")
    body = "\n".join(lines).rstrip()
    return (0, body) if applied else (3, body)
