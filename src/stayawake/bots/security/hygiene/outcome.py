#!/usr/bin/env python3
"""What one probe established — including whether it was in a position to establish anything.

A probe that returns no issues is saying one of two very different things: *I looked and there was
nothing*, or *I could not look*. Collapsed into an empty list they are the same answer, and the run
reports the surface as enumerated and clean over probes that never ran.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable

from .models import HygieneIssue, BLOCKED_ID, BLOCKED_SURFACE_ID

CHECKED_CLEAN = "checked-clean"
FOUND = "found"
UNKNOWN = "unknown"
BLOCKED = "blocked"


@dataclass(frozen=True)
class CheckOutcome:
    """One probe's result and the state it was in when it produced it."""
    label: str
    state: str
    issues: tuple[HygieneIssue, ...] = field(default_factory=tuple)
    reason: str | None = None

    @property
    def established(self) -> bool:
        return self.state != BLOCKED


def blocked_issue(label: str, reason: str, *, certifies_surface: bool) -> HygieneIssue:
    """The finding a blocked probe contributes, so a reader of the report sees the hole and the
    verdict machinery gates on it. A probe that certifies the start-up surface withholds the
    rotation all-clear as well; one that does not is a coverage gap, not a rotation hazard."""
    return HygieneIssue(
        id=BLOCKED_SURFACE_ID if certifies_surface else BLOCKED_ID,
        severity="unknown",
        title=f"This host did not let the {label} check finish",
        detail=f"{reason} This run did not cover that surface.",
        remediation="Resolve what stopped it and re-run, or inspect that surface yourself.",
    )


def run_probe(label: str, check: Callable[[], list[HygieneIssue]],
              predicate: Callable[[], str | None] | None = None,
              *, certifies_surface: bool = False) -> CheckOutcome:
    """Run one probe and say what state it ended in.

    The discriminator is checked BEFORE the silence is trusted, and failing it does not skip the
    probe: a probe reads several things and usually only one goes blind, so what it did establish is
    kept and the hole is added to it. A probe that raises is blocked, not fatal, and it must not
    vanish either. `KeyboardInterrupt` is deliberately not caught."""
    reason: str | None = None
    if predicate is not None:
        try:
            reason = predicate()
        except Exception as exc:
            reason = f"{type(exc).__name__} while preparing it."
    try:
        issues = list(check())
    except Exception as exc:
        stopped = f"{type(exc).__name__}: {exc}."
        return CheckOutcome(label, BLOCKED,
                            (blocked_issue(label, stopped, certifies_surface=certifies_surface),),
                            stopped)
    if reason:
        issues.append(blocked_issue(label, reason, certifies_surface=certifies_surface))
        return CheckOutcome(label, BLOCKED, tuple(issues), reason)
    if any(i.severity == "unknown" for i in issues):
        return CheckOutcome(label, UNKNOWN, tuple(issues))
    if issues:
        return CheckOutcome(label, FOUND, tuple(issues))
    return CheckOutcome(label, CHECKED_CLEAN, ())
