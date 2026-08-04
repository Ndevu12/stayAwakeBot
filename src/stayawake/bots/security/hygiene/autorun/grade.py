#!/usr/bin/env python3
"""Autorun GRADING (#1333) — fuse novelty + provenance + content-shape + correlation into one verdict.

No single signal is enough: a signature misses a novel payload; a bare diff alarms on every install; a
bare provenance check flags a legitimately hand-installed agent. Fused, they separate a foothold from a
legit install accurately — and the fusion is what lets a NOVEL payload be flagged without a signature
(it is unattributed, runs from a scratch path, and something new appeared), while a signed package agent
stays quiet even though it, too, is new.

Grades map onto the existing hygiene severities so they flow through #1332's rotation-safety contract:
a high-confidence foothold is a `warning` under `autorun-unattributed-foothold` (an ACTIVE_PERSISTENCE
id → rotation UNSAFE, exit 3); a merely-new unattributed entry is an `info` review item. Novelty NEVER
escalates on its own, and — the load-bearing property — provenance/content/correlation run on EVERY
entry regardless of the baseline, so a tampered or first-run baseline can never launder a foothold.
"""
from __future__ import annotations

import os
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path

from stayawake.utils import pathsafe
from ..models import HygieneIssue, _WIPER_NOTE
from .. import mechanism
from ...taint import analyzer
from .baseline import NEW, CHANGED

_MAX_REFERENCED = 256 * 1024        # cap the referenced-script read — a real dropper is tiny


def _referenced_text(entry) -> str:
    """The content of the entry's referenced executable, capped, or '' — so the content-shape engines
    see the payload where it usually LIVES (a script the unit runs), not just the unit file. FIFO-safe
    via pathsafe; a compiled binary simply won't match the (JS/shell-shaped) detectors."""
    if not entry.exec_path:
        return ""
    data = pathsafe.read_regular_bytes(Path(os.path.expanduser(entry.exec_path)))
    if data is None:
        return ""
    return data[:_MAX_REFERENCED].decode("utf-8", "replace")

FOOTHOLD_ID = "autorun-unattributed-foothold"   # strong → ACTIVE_PERSISTENCE (rotation UNSAFE, exit 3)
REVIEW_ID = "autorun-new-unattributed"          # weak → info review item


@dataclass
class ContentSignal:
    hit: bool = False               # a decisive fetch/decode-exec shape (act-now regardless of owner)
    reasons: list[str] = field(default_factory=list)


def content_signal(entry, *, read_referenced: bool = False) -> ContentSignal:
    """Run the existing content-shape engines on the entry's command + body — and, when
    `read_referenced` (used for UNATTRIBUTED entries, where the referenced script is worth reading),
    on the referenced script's content too. `hit` is a decisive fetch/decode-execute shape; a short
    poll interval (the Mini wiper's 60s GitHub poll) is a corroborating reason, not decisive alone."""
    text = entry.shape_text()
    if read_referenced:
        text += "\n" + _referenced_text(entry)
    reasons: list[str] = []
    hit = False
    if mechanism._FETCH_PIPE_EXEC.search(text):
        reasons.append("fetch/decode-to-shell command")
        hit = True
    if analyzer.detect_dropper(text):
        reasons.append("decode→execute dropper")
        hit = True
    for pflag in entry.persistence:
        if pflag.startswith("poll-interval="):
            try:
                secs = int(pflag.split("=", 1)[1].rstrip("s") or "0")
            except ValueError:
                secs = 0
            if 0 < secs <= 300:
                reasons.append(f"short poll interval ({secs}s)")
    return ContentSignal(hit=hit, reasons=reasons)


def correlate(entries, attributed: dict[str, bool]) -> set[str]:
    """Keys of UNATTRIBUTED entries whose referenced executable is shared by ≥2 entries — the
    multi-foothold campaign shape (a worm planting several re-run points at one payload). `attributed`
    maps entry-key → whether provenance attributed it."""
    execs = Counter()
    for e in entries:
        if e.exec_path and not attributed.get(e.key(), False):
            execs[os.path.normpath(os.path.expanduser(e.exec_path))] += 1
    shared = {p for p, n in execs.items() if n >= 2}
    return {e.key() for e in entries
            if e.exec_path and not attributed.get(e.key(), False)
            and os.path.normpath(os.path.expanduser(e.exec_path)) in shared}


def _where(entry, attrib) -> str:
    run = f"runs {entry.exec_path}" if entry.exec_path else "references no executable"
    tags = list(entry.persistence)
    if attrib.signed is False:
        tags.append("unsigned")
    if attrib.exec_class == "untrusted":
        tags.append("scratch/cache path")
    return f"{entry.path.name} ({run}" + (f"; {', '.join(tags)}" if tags else "") + ")"


def grade(entry, attrib, novel: str, shape: ContentSignal, correlated: bool) -> HygieneIssue | None:
    """Fuse the four signals for one entry into a graded HygieneIssue (or None = clean)."""
    is_new = novel in (NEW, CHANGED)
    unattributed = not attrib.attributed

    # STRONG foothold (→ warning, rotation UNSAFE): a decisive content shape (even a signed binary that
    # fetch-execs is act-now), OR an unattributed entry that is correlated across the surface, OR an
    # unattributed entry that both runs from a scratch/cache path AND re-executes (a persistence shape).
    strong = shape.hit or (unattributed and (correlated
             or (attrib.exec_class == "untrusted" and bool(entry.persistence))))
    if strong:
        why = list(shape.reasons)
        if correlated:
            why.append("shared payload across multiple autorun entries")
        detail = (f"An autorun entry re-executes code that is not attributable to a package, app, or "
                  f"signed binary — {_where(entry, attrib)}. " + (
                      "It " + "; ".join(why) + ". " if why else "")
                  + "A novel worm variant plants a foothold in a known location like this; being new "
                  "and unattributed is the signal, not a signature match.")
        return HygieneIssue(
            id=FOOTHOLD_ID, severity="warning",
            title="Unattributed autorun foothold (re-runs after the package is gone)",
            detail=detail,
            remediation="Verify you installed it; if not, treat the host as possibly compromised — "
                        f"disable/remove the entry, and {_WIPER_NOTE} (neutralize before rotating).")

    # REVIEW (→ info): something NEW and unattributed appeared since your last audit, without a decisive
    # bad shape. Requires trusted-baseline novelty, so a known benign-but-unattributed entry (e.g. your
    # own ~/bin tool) does not nag every run, and a first run stays quiet on this tier.
    if unattributed and is_new:
        verb = "appeared" if novel == NEW else "changed"
        return HygieneIssue(
            id=REVIEW_ID, severity="info",
            title="New unattributed autorun entry since your last audit",
            detail=f"An autorun entry {verb} that is not attributable to a package/app/signed binary — "
                   f"{_where(entry, attrib)}. New in itself is not proof of malware, but this is where "
                   "a novel foothold would appear; confirm you installed it.",
            remediation="If you set this up, it's fine. If not, inspect and remove it.")
    return None
