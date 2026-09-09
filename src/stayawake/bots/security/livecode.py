#!/usr/bin/env python3
"""Which running processes are executing code that never touched the disk.

`utils/procsnap` reads the kernel's argv; this decides what it means.

Detection only: `hygiene/process.py` renders the finding and `harden/live.py` acts on it, and both
ask this module so the two cannot disagree about what is running.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass

from stayawake.utils.invocation import resolve_invocation

_IDENTIFIES = None


@dataclass(frozen=True)
class LiveCode:
    """One running process holding code with no file behind it.

    `confirmed` carries the same meaning here as on the scan side."""
    process: object
    code: str
    reason: str
    confirmed: bool = False

    def __iter__(self):
        """Unpack as `(process, code, reason)`."""
        return iter((self.process, self.code, self.reason))


def _known_loader(code: str) -> bool:
    """Whether the signature corpus identifies `code` as a loader.

    TRAP: asked of the corpus's own authority. Reading the entries here instead grades text the
    corpus would not, and this answer ends processes.

    Imported locally so an audit that finds no candidate never pays to load the corpus."""
    global _IDENTIFIES
    if _IDENTIFIES is None:
        from stayawake.bots.security.matchers.base import build_corroborated_loader_check
        from stayawake.bots.security.signatures import load_signatures
        _IDENTIFIES = build_corroborated_loader_check(load_signatures()["content"])
    return _IDENTIFIES(code) is not None


def fingerprint(code: str) -> str:
    """A short stable identifier for a code argument, or an empty string when there is none.

    Stands in for the payload, which is never carried into a report or a record."""
    if not code:
        return ""
    return hashlib.sha256(code.encode("utf-8", "replace")).hexdigest()[:12]


def _obfuscation_verdict(code: str):
    """The scan side's own judgement of `code`, on the tier calibrated for a single argument.

    Imported locally so an audit that finds no candidate never pays for the engine."""
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


def live_code_processes(snap=None) -> list[LiveCode]:
    """Every running process executing code with no file behind it.

    The single authority: the report and anything that acts on these ask this function.
    """
    snap = snap if snap is not None else snapshot()
    found: list[LiveCode] = []
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
            if _known_loader(code):
                graded = (code, "code this tool has identified", True)
                break
            verdict = _obfuscation_verdict(code)
            if verdict.obfuscated:
                graded = (code, verdict.reason, False)
                break              # one per process; the rest of its argv is the same code
        if graded is None:
            if invocation.reads_stdin:
                graded = ("", "a program handed to it on standard input", False)
            elif program_is_gone(process.pid):
                graded = ("", "a program that is no longer on this disk", False)
        if graded is not None:
            found.append(LiveCode(process, graded[0], graded[1], graded[2]))
    return found
