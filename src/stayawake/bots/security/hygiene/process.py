#!/usr/bin/env python3
"""Code running right now that never touched the disk.

A loader passed as an interpreter argument leaves nothing to scan: the files are clean and the only
copy is the process. `utils/procsnap` reads the kernel's argv; this decides what it means.

READ-ONLY. An audit audits and reports; nothing here may signal, stop or end a process, and a test
pins that. Acting on one is a separate command's job, and it is gated on capture."""
from __future__ import annotations

from .autorun.grade import resolve_invocation
from .models import HygieneIssue, PROCESSES_NOT_READABLE_ID, _WIPER_NOTE


_EXCERPT_CHARS = 240


def _excerpt(code: str) -> str:
    """Enough of the argument to recognise and keep, bounded. It is attacker-chosen text; the render
    site encodes every field it prints, which is why it is carried rather than summarised away."""
    single = " ".join(code.split())
    return single if len(single) <= _EXCERPT_CHARS else single[:_EXCERPT_CHARS] + " […]"


def _obfuscation_verdict(code: str):
    """The scan side's own judgement, imported locally so a default audit that finds no candidate
    never pays for the engine. `constructs_only` is the calibrated tier for a single argument: an
    argv is one dense line by construction, so the density heuristic below it would be all noise."""
    from stayawake.bots.security.obfuscation.entry import analyze_file
    return analyze_file(code, constructs_only=True)


def _snapshot():
    from stayawake.utils.procsnap import snapshot
    return snapshot()


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
    if not snapshot.supported:
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
    issues: list[HygieneIssue] = []
    for process in snapshot.processes:
        if process.argv_unreadable or not process.argv:
            continue
        invocation = resolve_invocation(process.argv)
        for code in invocation.code_args:
            verdict = _obfuscation_verdict(code)
            if not verdict.obfuscated:
                continue
            issues.append(HygieneIssue(
                id="live-obfuscated-process",
                severity="warning",
                title="A running process was handed obfuscated code",
                detail=f"pid {process.pid} ({invocation.interpreter or process.program}) is "
                       f"executing {verdict.reason}. It is in the process, not on disk: "
                       f"{_excerpt(code)}",
                remediation="Capture it before anything ends it, and rotate credentials LAST — "
                            f"{_WIPER_NOTE}.",
            ))
            break                      # one finding per process; the rest of its argv is the same
    return issues
