#!/usr/bin/env python3
"""Autorun-surface monitor — catch a NOVEL foothold in a KNOWN location without a signature."""
from __future__ import annotations

from stayawake.utils import parallel

from ..models import HygieneIssue, could_not_read

BASELINE_UNSAVED_ID = "autorun-baseline-not-saved"
REMOVALS_DROPPED_ID = "autorun-removals-dropped"
from . import surface, provenance, baseline, grade

__all__ = ["check_autorun", "surface", "provenance", "baseline", "grade"]


def check_autorun(jobs: int | None = None) -> list[HygieneIssue]:
    """The audit probe. Enumerate the autorun surface, attribute every entry (in parallel), fuse the
    signals, and return graded issues. Snapshots the surface, and what has gone from it, for the
    next run's novelty diff — including when the surface is empty."""
    listing: dict = {}
    entries, unread = surface.enumerate_entries(listing)
    issues: list[HygieneIssue] = [could_not_read(unread)] if unread else []
    base = baseline.load_baseline()

    if entries:
        workers = parallel.resolve_jobs(jobs, len(entries))
        outcomes = parallel.run_ordered(provenance.attribute, entries, jobs=workers,
                                        backend=parallel.THREAD)
        attribs = [o.value if not o.error else provenance.Attribution(exec_class="unknown")
                   for o in outcomes]
        attributed = {e.key(): a.attributed for e, a in zip(entries, attribs)}

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

    written, dropped = baseline.save_baseline(entries, base, listing)
    if dropped:
        issues.append(HygieneIssue(
            id=REMOVALS_DROPPED_ID, severity="info",
            title="saw could not keep every removal it had recorded",
            detail=f"{dropped} start-up entries removed earlier are no longer tracked, so if one "
                   "comes back it will read as new rather than as returned.",
            remediation="Audit again after checking the start-up surface by hand."))
    if not written:
        issues.append(HygieneIssue(
            id=BASELINE_UNSAVED_ID, severity="info",
            title="This audit could not be remembered for the next run",
            detail="saw could not update its own record of the start-up surface, so what it calls "
                   "new — or back — will not move on from this run.",
            remediation="Make saw's state directory writable by the account running the audit."))
    return issues
