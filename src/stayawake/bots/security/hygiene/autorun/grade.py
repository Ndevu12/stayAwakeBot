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
import re
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path

from stayawake.utils import pathsafe
from ..models import HygieneIssue, _WIPER_NOTE
from .. import mechanism
from ...taint import analyzer
from ...taint.destructive import detect_destructive
from .baseline import NEW, CHANGED

_MAX_REFERENCED = 256 * 1024        # cap the referenced-script read — a real dropper is tiny


# Script interpreters: when one of these is argv[0], the real payload is the SCRIPT ARGUMENT, not the
# interpreter binary. A LaunchAgent/unit that runs `node /path/daemon.js` launders provenance through
# the trusted interpreter — the daemon's code is what determines behaviour, so that is what we read.
_INTERPRETERS = frozenset({
    "node", "nodejs", "deno", "bun", "python", "python2", "python3", "ruby", "perl", "php",
    "sh", "bash", "zsh", "dash", "ksh", "osascript", "tsx", "ts-node"})


# Inline-eval flags: the code is IN argv (already seen via `shape_text()`), not in a script file — so
# `node -e '<code>'` / `python -c '<code>'` must NOT mistake the code argument for a path to read.
_INLINE_EVAL_FLAGS = frozenset({"-e", "--eval", "-c", "-p", "--print", "-"})


def _payload_path(entry) -> str | None:
    """The path of the code the entry actually RUNS. Normally argv[0]; but when argv[0] is a script
    INTERPRETER (`node`, `python`, `sh`, …), it is the first non-flag script ARGUMENT — the payload the
    interpreter executes. So a `node /path/daemon.js` autorun is read at daemon.js, not at the trusted
    `node` binary (which would launder the payload past the content-shape engines). An inline-eval
    invocation (`node -e '<code>'`) has no script file — the code is already in argv (seen via
    `shape_text()`), so fall back to argv[0] rather than treat the code as a phantom path."""
    if not entry.argv:
        return None
    if os.path.basename(entry.argv[0]).split(".")[0] in _INTERPRETERS:
        args = entry.argv[1:]
        if any(a in _INLINE_EVAL_FLAGS for a in args):
            return entry.argv[0]
        for arg in args:
            if not arg.startswith("-"):        # the first non-flag argument is the script
                return arg
    return entry.argv[0]


def launched_via_interpreter(entry) -> bool:
    """True when argv[0] is a script interpreter running a distinct script argument — so the payload
    script must be read for content-shape EVEN IF the interpreter is an attributed/trusted binary
    (its trust does not vouch for the arbitrary script it runs)."""
    return bool(entry.argv) and _payload_path(entry) not in (None, entry.argv[0])


_POSIX_SHELLS = frozenset({"sh", "bash", "zsh", "dash", "ksh"})
_SHELL_SUFFIXES = (".sh", ".bash", ".zsh", ".ksh")
# `lstrip` the BOM explicitly: it is not whitespace, so a UTF-8 BOM ahead of `#!` would otherwise
# defeat the anchor — and the payload author chooses the encoding.
_SHEBANG_SHELL = re.compile(r"^#!.*\b(?:sh|bash|zsh|dash|ksh)\b")
_LEADING_NOISE = "﻿ \t\r\n"


def _runs_as_shell(entry, referenced: str) -> bool:
    """Whether the referenced payload is EXECUTED as a shell script.

    Decided first from how the entry runs it: `argv[0]` being a POSIX shell is authoritative, and is
    the one signal the payload cannot rename away — dropping the shebang and calling itself `.dat`
    changes nothing about `["/bin/bash", "payload.dat"]`. Shebang and suffix are additional signals
    for the case where the invoking binary is something else; both are attacker-controlled, so
    neither is relied on alone."""
    argv = entry.argv or []
    if argv and os.path.basename(argv[0]).split(".")[0] in _POSIX_SHELLS:
        return True
    payload = _payload_path(entry)
    if payload and payload.lower().endswith(_SHELL_SUFFIXES):
        return True
    return bool(_SHEBANG_SHELL.match(referenced.lstrip(_LEADING_NOISE)))


def _shell_context_text(entry, referenced: str) -> str:
    """The parts of an entry that genuinely ARE a shell command line, for the shell-grammar matcher.

    The argv line always is one; a referenced payload is one when `_runs_as_shell`. The unit BODY is
    deliberately excluded — that is where a JS template literal or a comment lives, and reading
    shell operators there is what produced the false positives this split exists to fix."""
    parts = [" ".join(entry.argv or [])]
    if referenced and _runs_as_shell(entry, referenced):
        parts.append(referenced)
    return "\n".join(parts)


def _referenced_text(entry) -> str:
    """The content of the entry's referenced PAYLOAD (interpreter-aware, see `_payload_path`), capped,
    or '' — so the content-shape engines see the payload where it usually LIVES (a script the unit
    runs), not just the unit file or a trusted interpreter binary. FIFO-safe via pathsafe; a compiled
    binary simply won't match the (JS/shell-shaped) detectors."""
    payload = _payload_path(entry)
    if not payload:
        return ""
    data = pathsafe.read_regular_bytes(Path(os.path.expanduser(payload)))
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
    """Run the content-shape engines on the entry's command + body — and, when `read_referenced`
    (used for UNATTRIBUTED entries, where the referenced script is worth reading), on the referenced
    script's content too. `hit` is a decisive shape (act-now regardless of owner).

    #1335 — a malicious daemon that polls a legitimate endpoint (e.g. `api.github.com` every 60s) can't
    be caught by WHERE it connects; the discriminating features are BEHAVIOURAL, and for a script-based
    daemon they are STATIC: the poll interval is a literal in the code / the persistence artifact, and a
    persistence entry is non-interactive (no TTY, launchd/systemd-spawned) BY CONSTRUCTION. So we fuse,
    never blocklist a destination:
      * decisive `hit` — a fetch/decode-to-shell command, a decode→execute dropper, OR the dead-man
        self-destruct shape (#1334's corroborated `$HOME`-wipe) in the daemon's own code. The Mini
        Shai-Hulud wiper is plain code (poll → on token-revoke, delete `$HOME`), NOT a decode→exec
        dropper, so fusing `detect_destructive` here is what actually catches it.
      * corroborating reason — a short poll interval (the timer the dead-man loop runs on). Never
        decisive alone: benign software polls on a timer too (the FP guard is that escalation needs a
        decisive shape, and `detect_destructive` is itself corroborated home-root ∧ recursive ∧ delete,
        so firing it adds no new false positive)."""
    text = entry.shape_text()
    referenced = _referenced_text(entry) if read_referenced else ""
    if referenced:
        text += "\n" + referenced
    reasons: list[str] = []
    hit = False
    if mechanism._FETCH_PIPE_EXEC.search(text):
        reasons.append("fetch/decode-to-shell command")
        hit = True
    # Scratch execution is asked TWO ways, because the entry carries two kinds of evidence.
    # By PATH — what the entry runs, immune to how the surrounding code is written:
    payload = _payload_path(entry)
    if payload and mechanism._under_scratch(Path(payload)):
        reasons.append("runs code from a world-writable scratch directory")
        hit = True
    # By shell GRAMMAR — but only over the parts that genuinely are a shell command line. Asking it
    # of arbitrary payload text is what #1393 fixed; asking it of nothing loses `sh -c '…; /tmp/x'`,
    # where the path check resolves to the shell binary and the scratch payload is invisible.
    elif mechanism._SCRATCH_EXEC.search(_shell_context_text(entry, referenced)):
        reasons.append("runs code from a world-writable scratch directory")
        hit = True
    if analyzer.detect_dropper(text):
        reasons.append("decode→execute dropper")
        hit = True
    if detect_destructive(text) is not None:
        reasons.append("dead-man self-destruct ($HOME wipe on an auth/token condition)")
        hit = True
    secs = _poll_seconds(entry.persistence)
    if secs is not None and 0 < secs <= 300:
        reasons.append(f"short poll interval ({secs}s)")
    return ContentSignal(hit=hit, reasons=reasons)


def _poll_seconds(persistence) -> int | None:
    """The daemon's poll/timer period in seconds, read STATICALLY from the persistence artifact —
    macOS `StartInterval` (`poll-interval=Ns`) or a systemd `OnUnitActiveSec` timer (`60`, `30s`,
    `1min`). This is the static analog of "interval regularity": a poll loop's cadence is a literal in
    the artifact, no live observation needed. None when no periodic timer is declared."""
    for pflag in persistence:
        if pflag.startswith("poll-interval="):
            try:
                return int(pflag.split("=", 1)[1].rstrip("s") or "0")
            except ValueError:
                return None
        if pflag.startswith("timer:OnUnitActiveSec="):
            return _systemd_seconds(pflag.split("=", 1)[1])
    return None


def _systemd_seconds(dur: str) -> int | None:
    """Parse a simple systemd time span (`60`, `30s`, `5min`, `1h`) to seconds — enough for the
    short-interval corroboration; an unrecognised/compound span returns None (no corroboration, never
    a crash)."""
    m = re.fullmatch(r"\s*(\d+)\s*(s|sec|secs|seconds|min|minutes|m|h|hours?)?\s*", dur)
    if not m:
        return None
    n, unit = int(m.group(1)), (m.group(2) or "s")
    mult = 60 if unit.startswith("m") and unit != "s" else 3600 if unit.startswith("h") else 1
    return n * mult


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
