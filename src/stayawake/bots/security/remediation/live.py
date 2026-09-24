#!/usr/bin/env python3
"""Apply the remediation plan to the checkout the operator is standing in."""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from stayawake.bots.security.remediation import changes as ch
from stayawake.bots.security.remediation.oracle import (ABSENT, CHANGED, REFUSED, UNREADABLE,
                                                        still_condemned)


@dataclass
class LiveResult:
    """What a run did to the live checkout."""

    removed: list[str] = field(default_factory=list)
    changed: list[str] = field(default_factory=list)
    absent: list[str] = field(default_factory=list)
    unread: list[str] = field(default_factory=list)
    refused: list[str] = field(default_factory=list)

    @property
    def unfinished(self) -> list[str]:
        """The paths still to account for."""
        return self.unread + self.refused

    @property
    def complete(self) -> bool:
        """Whether every condemned path was accounted for."""
        return not self.unfinished

    def note(self, detail: bool = False) -> str:
        """Describe what happened in the checkout. Takes whether paths may be named."""
        parts = []
        if self.removed:
            parts.append(f"removed {len(self.removed)} file(s) from your checkout")
        if self.changed:
            parts.append(f"left {len(self.changed)} that no longer carried it")
        if self.unfinished:
            head = f"{len(self.unfinished)} still to deal with — your checkout is not clean"
            parts.append(f"{head}: {', '.join(self.unfinished)}" if detail else head)
        return "; ".join(parts)


def clean(root: Path, findings, signatures, allowlist, opts) -> LiveResult:
    """Remove from `root` what the findings condemn.

    Takes the checkout, the findings, the by-matcher signatures, the allowlist and the scan
    options. Returns what was removed and what was not.
    """
    plan = [c for c in ch.plan(findings) if c.action == "remove"]
    if not plan:
        return LiveResult()
    result = LiveResult()
    bucket = {CHANGED: result.changed, ABSENT: result.absent,
              UNREADABLE: result.unread, REFUSED: result.refused}

    def skipped(path: str, reason: str) -> None:
        bucket.get(reason, result.unread).append(path)

    applied = ch.apply(root, plan, None,
                       condemned=still_condemned(root, signatures, allowlist, opts),
                       on_skip=skipped)
    result.removed.extend(c.path for c in applied)
    return result
