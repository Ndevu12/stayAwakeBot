#!/usr/bin/env python3
"""Which running processes are executing code that never touched the disk.

A loader passed as an interpreter argument leaves nothing to scan: the files are clean and the only
copy is the process. `utils/procsnap` reads the kernel's argv; this decides what it means.

Detection only. Nothing here signals, stops or ends a process, and nothing here builds a report —
`hygiene/process.py` renders the finding, `harden/live.py` acts on it, and both ask this module so
the two cannot disagree about what is running.
"""
from __future__ import annotations

from stayawake.utils.invocation import resolve_invocation


def _obfuscation_verdict(code: str):
    """The scan side's own judgement, imported locally so a default audit that finds no candidate
    never pays for the engine. `constructs_only` is the calibrated tier for a single argument: an
    argv is one dense line by construction, so the density heuristic below it would be all noise."""
    from stayawake.bots.security.obfuscation.entry import analyze_file
    return analyze_file(code, constructs_only=True)


def snapshot():
    """The process table, read through the kernel's own argv."""
    from stayawake.utils.procsnap import snapshot as read
    return read()


def program_is_gone(pid: int) -> bool:
    """Whether `pid` is running something that is no longer a file on this disk."""
    from stayawake.utils.procsnap import program_is_gone as ask
    return ask(pid)


def live_code_processes(snap=None) -> list[tuple[object, str, str]]:
    """Every running process executing code with no file behind it, as `(process, code, reason)`.

    The single authority: the report and anything that acts on these ask the same function.
    """
    snap = snap if snap is not None else snapshot()
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
            if invocation.reads_stdin:
                graded = ("", "a program handed to it on standard input")
            elif program_is_gone(process.pid):
                graded = ("", "a program that is no longer on this disk")
        if graded is not None:
            found.append((process, graded[0], graded[1]))
    return found
