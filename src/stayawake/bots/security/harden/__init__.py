#!/usr/bin/env python3
"""Host-level acting — create denials on this machine. Never touches a project's tree."""
from __future__ import annotations

from stayawake.bots.security.hygiene.host_artifacts import _global_folders
from stayawake.bots.security.hygiene.models import PROCESSES_NOT_READABLE_ID
from stayawake.bots.security.hygiene.process import check_live_processes
from stayawake.utils import hostdenial
from .denial import ENFORCING, OCCUPIED, UNKNOWN, PathOutcome, apply_one

__all__ = ["run", "apply_one", "PathOutcome", "ENFORCING", "UNKNOWN", "OCCUPIED"]


_LIVE = "live-obfuscated-process"

_REFUSED_LIVE = (
    "A running process still holds code that is not on disk. "
    "Capture it before applying this control."
)
_REFUSED_UNREAD = (
    "Running processes could not be examined, so this control was not applied."
)
_NOT_ROOT = "This command must run as root."
_NOT_HERE = "This control is not implemented on this platform."
_CLAIM = (
    "The observed staging path is denied. A payload that guards the write and uses "
    "the runtime's built-in transport is unaffected."
)


def run(*, live=check_live_processes, folders=_global_folders,
        apply=apply_one, privileged=hostdenial.privileged,
        supported=hostdenial.platform_supported) -> tuple[int, str]:
    """Apply the denial at every global-resolution entry. Enforcing only after read-back."""
    if not supported():
        return 2, _NOT_HERE
    if not privileged():
        return 2, _NOT_ROOT
    issues = list(live())
    if any(i.id == PROCESSES_NOT_READABLE_ID for i in issues):
        return 1, _REFUSED_UNREAD
    if any(i.id == _LIVE for i in issues):
        return 1, _REFUSED_LIVE

    outcomes = [apply(p) for p in folders()]
    lines = [_CLAIM, ""]
    for o in outcomes:
        lines.append(f"  {o.state}: {o.path} — {o.detail}")
    body = "\n".join(lines).rstrip()
    if outcomes and all(o.state == ENFORCING for o in outcomes):
        return 0, body
    return 3, body
