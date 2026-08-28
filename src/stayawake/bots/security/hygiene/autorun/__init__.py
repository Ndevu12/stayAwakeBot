#!/usr/bin/env python3
"""Autorun-surface monitor — catch a NOVEL foothold in a KNOWN location without a signature."""
from __future__ import annotations

from stayawake.utils import parallel

from ..models import HygieneIssue, could_not_read
from . import surface, provenance, baseline, grade

__all__ = ["check_autorun", "surface", "provenance", "baseline", "grade"]


def check_autorun(jobs: int | None = None) -> list[HygieneIssue]:
    """The audit probe. Enumerate the autorun surface, attribute every entry (in parallel), fuse the
    signals, and return graded issues. Snapshots the surface for the next run's novelty diff."""
    entries, unread = surface.enumerate_entries()
    issues: list[HygieneIssue] = [could_not_read(unread)] if unread else []
    if not entries:
        return issues

    workers = parallel.resolve_jobs(jobs, len(entries))
    outcomes = parallel.run_ordered(provenance.attribute, entries, jobs=workers,
                                    backend=parallel.THREAD)
    attribs = [o.value if not o.error else provenance.Attribution(exec_class="unknown")
               for o in outcomes]
    attributed = {e.key(): a.attributed for e, a in zip(entries, attribs)}

    base = baseline.load_baseline()
    novel = baseline.novelty(entries, base)
    correlated = grade.correlate(entries, attributed)

    for entry, attrib in zip(entries, attribs):
        read_ref = not attrib.attributed or grade.launched_via_interpreter(entry)
        shape = grade.content_signal(entry, read_referenced=read_ref)
        issue = grade.grade(entry, attrib, novel.get(entry.key(), baseline.KNOWN),
                            shape, entry.key() in correlated)
        if issue is not None:
            issues.append(issue)

    if base.status == "tampered":
        issues.append(HygieneIssue(
            id="autorun-baseline-tampered", severity="info",
            title="Autorun baseline failed its integrity check",
            # "detection is not weakened" stays — without it this reads as a coverage loss, which is
            # the one wrong conclusion to draw. The mechanism of the hash check does not stay.
            detail="The autorun baseline was modified out-of-band, so its novelty signal is ignored "
                   "this run. Detection is not weakened — every entry was still graded — but a "
                   "tampered baseline can mean someone tried to launder a foothold into it.",
            remediation="Delete the baseline to re-snapshot from the current (re-graded) surface."))

    baseline.save_baseline(entries)          # snapshot for the next run's novelty diff (best-effort)
    return issues
