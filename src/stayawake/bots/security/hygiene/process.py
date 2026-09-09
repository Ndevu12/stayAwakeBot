#!/usr/bin/env python3
"""Report the code a running process was handed.

Detection lives in `bots/security/livecode.py`; this renders its result as a `HygieneIssue`.

READ-ONLY. An audit audits and reports; nothing here may signal, stop or end a process, and a test
pins that. Acting on one is a separate command's job, and it is gated on capture."""
from __future__ import annotations

from stayawake.bots.security.livecode import fingerprint, live_code_processes, snapshot as _snapshot
from stayawake.utils.invocation import resolve_invocation
from .models import HygieneIssue, PROCESSES_NOT_READABLE_ID, _WIPER_NOTE


_EXCERPT_CHARS = 240


_PIDS_SHOWN = 8


def _fingerprint(code: str) -> str:
    """The report's phrasing of `code`'s identifier, or an empty string when there is none."""
    short = fingerprint(code)
    return f", fingerprint {short}" if short else ""


def _excerpt(code: str) -> str:
    """Enough of the argument to recognise and keep, bounded. It is attacker-chosen text; the render
    site encodes every field it prints, which is why it is carried rather than summarised away."""
    single = " ".join(code.split())
    return single if len(single) <= _EXCERPT_CHARS else single[:_EXCERPT_CHARS] + " […]"


def live_process_scope_note() -> str:
    """What the process table did not yield — other users' processes, or a platform whose arguments
    cannot be read at all. Disclosure, never a finding: a machine always runs processes this user
    may not read, and gating on that would withhold every verdict on every unprivileged run."""
    return _snapshot().scope_note()


def check_live_processes() -> list[HygieneIssue]:
    """Grade the code each running process was handed.

    Two authorities are reused rather than re-derived. `resolve_invocation` decides which argument
    is code — the same answer the start-up checks use, so the two cannot disagree — and it is what
    keeps this off the whole process table. The obfuscation engine decides what that code is."""
    snapshot = _snapshot()
    if not snapshot.supported or not snapshot.processes:
        # Asked of the reader, not of the platform name: the registry that marks probes unimplemented
        # keys off a different question, and the two answer alike only on the platforms we run.
        return [HygieneIssue(
            id=PROCESSES_NOT_READABLE_ID,
            severity="unknown",
            title="Running processes were not examined",
            detail="Process arguments cannot be read here, so no running process was examined and "
                   "no result covers one.",
            remediation="Inspect what is running yourself, and rotate credentials LAST — "
                        f"{_WIPER_NOTE}.",
        )]
    holding = live_code_processes(snapshot)
    if not holding:
        return []
    # One finding, however many processes.
    first, code, reason = holding[0]
    pids = sorted(p.pid for p, _c, _r in holding)
    where = ", ".join(str(pid) for pid in pids[:_PIDS_SHOWN])
    if len(pids) > _PIDS_SHOWN:
        where += f", and {len(pids) - _PIDS_SHOWN} more"
    count = ("A running process is executing code that is not on disk" if len(pids) == 1 else
             f"{len(pids)} running processes are executing code that is not on disk")
    # TRAP: the payload is never put in `detail`. This reaches the terminal, the JSON, the SARIF
    # and every saved report; the code goes to the capture file instead.
    return [HygieneIssue(
        id="live-obfuscated-process",
        severity="warning",
        title=count,
        detail=f"pid {where} ({resolve_invocation(first.argv).interpreter or first.program}): "
               f"{reason}{_fingerprint(code)}.",
        remediation=f"Rotate credentials LAST — {_WIPER_NOTE}.",
    )]
