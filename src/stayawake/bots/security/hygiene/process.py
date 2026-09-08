#!/usr/bin/env python3
"""Code running right now that never touched the disk.

A loader passed as an interpreter argument leaves nothing to scan: the files are clean and the only
copy is the process. `utils/procsnap` reads the kernel's argv; this decides what it means.

READ-ONLY. An audit audits and reports; nothing here may signal, stop or end a process, and a test
pins that. Acting on one is a separate command's job, and it is gated on capture."""
from __future__ import annotations

import hashlib

from .autorun.grade import resolve_invocation
from .models import HygieneIssue, PROCESSES_NOT_READABLE_ID, _WIPER_NOTE


_EXCERPT_CHARS = 240


_PIDS_SHOWN = 8


def _fingerprint(code: str) -> str:
    """A short hash of the payload, so two runs can be compared without printing any of it."""
    if not code:
        return ""
    return f", fingerprint {hashlib.sha256(code.encode('utf-8', 'replace')).hexdigest()[:12]}"


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


def program_is_gone(pid: int) -> bool:
    """Whether a process is running something that is no longer a file on this disk.

    Imported at the call rather than at the top, for the same reason the snapshot is: an audit that
    never reaches a process should not pay for the reader.
    """
    from stayawake.utils.procsnap import program_is_gone as ask
    return ask(pid)


def live_process_scope_note() -> str:
    """What the process table did not yield — other users' processes, or a platform whose arguments
    cannot be read at all. Disclosure, never a finding: a machine always runs processes this user
    may not read, and gating on that would withhold every verdict on every unprivileged run."""
    return _snapshot().scope_note()


def live_code_processes(snapshot=None) -> list[tuple[object, str, str]]:
    """Every running process holding code an interpreter was handed and the engine calls obfuscated,
    as `(process, code, reason)`.

    One authority. The reporter below and anything that ACTS on these must agree about which
    processes qualify, and they can only be made to agree by asking the same function.
    """
    snap = snapshot if snapshot is not None else _snapshot()
    found: list[tuple[object, str, str]] = []
    if not snap.supported or not snap.processes:
        return found
    for process in snap.processes:
        if process.argv_unreadable or not process.argv:
            continue
        if process.identity is not None and process.identity.zombie:
            continue          # killed and awaiting its parent — it executes nothing
        invocation = resolve_invocation(process.argv)
        graded = None
        for code in invocation.code_args:
            verdict = _obfuscation_verdict(code)
            if verdict.obfuscated:
                graded = (code, verdict.reason)
                break              # one per process; the rest of its argv is the same code
        if graded is None:
            # Code on the command line is one way to run without a file, not the only one. A
            # program that is no longer on disk, or an interpreter handed its program on standard
            # input, is running something nothing here can read — which is not a reason to leave it.
            if invocation.reads_stdin:
                graded = ("", "a program handed to it on standard input")
            elif program_is_gone(process.pid):
                graded = ("", "a program that is no longer on this disk")
        if graded is not None:
            found.append((process, graded[0], graded[1]))
    return found


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
    # ONE finding, however many processes. A worm that spawns produces a wall of near-identical
    # lines — 135 of them in one measured run — and a wall nobody can read is not a report.
    first, code, reason = holding[0]
    pids = sorted(p.pid for p, _c, _r in holding)
    where = ", ".join(str(pid) for pid in pids[:_PIDS_SHOWN])
    if len(pids) > _PIDS_SHOWN:
        where += f", and {len(pids) - _PIDS_SHOWN} more"
    count = ("A running process is executing code that is not on disk" if len(pids) == 1 else
             f"{len(pids)} running processes are executing code that is not on disk")
    # The payload itself is NOT printed. It carries the campaign's own markers and the address it
    # talks to, and this line reaches the terminal, the JSON, the SARIF and any saved report. It is
    # written to the capture file, which is where an operator can hand it to someone.
    return [HygieneIssue(
        id="live-obfuscated-process",
        severity="warning",
        title=count,
        detail=f"pid {where} ({resolve_invocation(first.argv).interpreter or first.program}): "
               f"{reason}{_fingerprint(code)}.",
        remediation=f"Rotate credentials LAST — {_WIPER_NOTE}.",
    )]
