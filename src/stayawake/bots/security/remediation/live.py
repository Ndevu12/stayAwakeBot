#!/usr/bin/env python3
"""Apply the remediation plan to the checkout the operator is standing in."""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from stayawake.bots.security.remediation import changes as ch
from stayawake.bots.security.remediation.oracle import CARRIES, UNREADABLE, still_condemned


@dataclass
class LiveResult:
    """What a run did to the live checkout."""

    removed: list[str] = field(default_factory=list)
    left: list[str] = field(default_factory=list)
    unread: list[str] = field(default_factory=list)

    @property
    def complete(self) -> bool:
        """Whether every condemned path was accounted for."""
        return not self.unread

    def note(self) -> str:
        """Describe what happened in the checkout."""
        parts = []
        if self.removed:
            parts.append(f"removed {len(self.removed)} file(s) from your checkout")
        if self.left:
            parts.append(f"left {len(self.left)} that no longer carried it")
        if self.unread:
            parts.append(f"COULD NOT READ {len(self.unread)} — your checkout is not clean")
        return "; ".join(parts)


def clean(root: Path, findings, signatures, allowlist, opts) -> LiveResult:
    """Remove from `root` what the findings condemn.

    Takes the checkout, the findings, the by-matcher signatures, the allowlist and the scan
    options. Returns what was removed, what was left, and what could not be read.
    """
    plan = [c for c in ch.plan(findings) if c.action == "remove"]
    if not plan:
        return LiveResult()
    check = still_condemned(root, signatures, allowlist, opts)
    result = LiveResult()
    verdicts = {}

    def _asked(path: str) -> str:
        verdicts[path] = check(path)
        return verdicts[path]

    applied = ch.apply(root, plan, None, condemned=_asked)
    done = {c.path for c in applied}
    for c in plan:
        if c.path in done:
            result.removed.append(c.path)
        elif verdicts.get(c.path) == UNREADABLE:
            result.unread.append(c.path)
        elif verdicts.get(c.path) is not None:
            result.left.append(c.path)
    return result
