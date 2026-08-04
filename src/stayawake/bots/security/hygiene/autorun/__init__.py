#!/usr/bin/env python3
"""Autorun-surface monitor (#1333) — catch a NOVEL foothold in a KNOWN location without a signature.

Signature matching asks "does this location hold something I already recognise?" and fails on a novel
payload by construction — and with the worm's source public, novel variants are the expected case. This
monitor instead treats the autorun surface as monitored state and fuses four orthogonal, statically-
observable signals per entry:

  1. provenance   — is the referenced executable owned by a package/app, signed, on a trusted path?
  2. content-shape — does it fetch/decode-execute, poll on a short interval? (the existing engines)
  3. novelty      — is it new/changed since a trusted baseline? (never escalates alone)
  4. correlation  — is one unattributed payload wired into several re-run points? (campaign shape)

Provenance is I/O-bound (dpkg/rpm/codesign), so it fans out over the shared THREAD parallel seam;
results come back in submission order, so the graded findings are byte-identical at any worker count,
and a provenance worker that errors/times-out fails closed to UNATTRIBUTED (surfaced, never blessed).
Safety never depends on the baseline — provenance/content/correlation grade every entry regardless.
"""
from __future__ import annotations

from stayawake.utils import parallel

from ..models import HygieneIssue
from . import surface, provenance, baseline, grade

__all__ = ["check_autorun", "surface", "provenance", "baseline", "grade"]


def check_autorun(jobs: int | None = None) -> list[HygieneIssue]:
    """The audit probe. Enumerate the autorun surface, attribute every entry (in parallel), fuse the
    signals, and return graded issues. Snapshots the surface for the next run's novelty diff."""
    entries = surface.enumerate_entries()
    if not entries:
        return []

    # Provenance is the subprocess-heavy leg → fan out over the shared THREAD seam. Submission-order
    # results keep grading deterministic (-j1 == -jN); a worker error fails closed to UNATTRIBUTED.
    workers = parallel.resolve_jobs(jobs, len(entries))
    outcomes = parallel.run_ordered(provenance.attribute, entries, jobs=workers,
                                    backend=parallel.THREAD)
    attribs = [o.value if not o.error else provenance.Attribution(exec_class="unknown")
               for o in outcomes]
    attributed = {e.key(): a.attributed for e, a in zip(entries, attribs)}

    base = baseline.load_baseline()
    novel = baseline.novelty(entries, base)
    correlated = grade.correlate(entries, attributed)

    issues: list[HygieneIssue] = []
    for entry, attrib in zip(entries, attribs):
        # Read the referenced script (the payload usually lives there, not in the unit file) for an
        # UNATTRIBUTED entry — and ALSO when the entry launders through a trusted interpreter (#1335):
        # `node /path/daemon.js` is "attributed" to node, but node's trust does not vouch for the
        # arbitrary script it runs, so that script must still be content-scanned.
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
            detail="The stored autorun baseline was modified out-of-band (its integrity hash does not "
                   "match its contents), so its novelty signal is being ignored this run. This does "
                   "not weaken detection — provenance, content-shape and correlation still graded "
                   "every entry — but a tampered baseline can indicate someone tried to launder a "
                   "foothold into the 'known' set.",
            remediation="Delete the baseline to re-snapshot from the current (re-graded) surface."))

    baseline.save_baseline(entries)          # snapshot for the next run's novelty diff (best-effort)
    return issues
