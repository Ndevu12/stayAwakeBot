#!/usr/bin/env python3
"""Checks that the user-owned persistence locations could actually be read.

Emits one issue naming any location that exists but could not be read, so a run that could not
enumerate the surface reports UNKNOWN rather than clean. Runs alongside the detection probes and
changes none of their findings.
"""
from __future__ import annotations

import os
import stat
from pathlib import Path

from .models import HygieneIssue, _WIPER_NOTE, persistence_surface_is_enumerable
from . import os_service, runner, mechanism

_ANCHOR_LABEL = "shell startup file"


_AGENT_LABEL = "launch-agent / service dir"
_RUNNER_LABEL = "self-hosted-runner dir"
_RUNNER_MARKER = ".runner"

_DIRECTORIES_HOLDING_RECORDS = frozenset({_AGENT_LABEL, _ANCHOR_LABEL})


_RECORD_SUBDIRECTORY_DEPTH = 1


def _record_paths(directory: Path, depth: int = _RECORD_SUBDIRECTORY_DEPTH) -> list[Path]:
    """Every path inside `directory`, NAMED rather than inspected — `_coverage` is the one place
    that separates absent from unreadable, and asking twice is how the second answer goes wrong."""
    try:
        with os.scandir(directory) as entries:
            names = sorted(entry.name for entry in entries)
    except OSError:
        return []                         # the directory is already graded on its own row
    found: list[Path] = []
    for name in names:
        child = directory / name
        found.append(child)
        if depth:
            found += _record_paths(child, depth - 1)
    return found


def _must_verify_locations() -> list[tuple[str, Path]]:
    """(surface-label, path) for the user-owned persistence locations whose unreadability must
    withhold an all-clear — the launch-agent/service dirs and the self-hosted-runner install dirs
    (active footholds), ~/.ssh/authorized_keys, and shell startup files. Derived from the detection
    probes' own location definitions so the certified surface can never drift from the scanned one.

    A location that HOLDS records is expanded into them: the file is what a probe reads, so the file
    is what has to be readable for its silence to mean anything."""
    home = Path.home()
    locs: list[tuple[str, Path]] = [(_AGENT_LABEL, d) for d in os_service.user_persistence_dirs()]
    locs += [(_RUNNER_LABEL, d) for d in runner.user_runner_dirs()]
    ssh = home / ".ssh"
    locs += [("SSH authorized_keys", ssh / name) for name in mechanism._SSH_AUTHKEYS]
    locs += [(_ANCHOR_LABEL, p) for p in mechanism.shell_rc_locations()]
    # The runner install dir is not expanded — hundreds of files, of which one is the record.
    locs += [(_RUNNER_LABEL, d / _RUNNER_MARKER) for d in runner.user_runner_dirs()]
    expanded: list[tuple[str, Path]] = []
    for label, path in locs:
        expanded.append((label, path))
        if label in _DIRECTORIES_HOLDING_RECORDS:
            expanded += [(label, child) for child in _record_paths(path)]
    return expanded


def _coverage(p: Path) -> str:
    """'ok' (read it) | 'absent' (nothing planted here) | 'unverified' (exists but can't be certified).

    ABSENT is clean: a user-level worm planting persistence must CREATE the path (as the user, who can
    then read it), so a path that does not exist carries nothing. UNVERIFIED is the unsafe case — it
    exists but could not be read (a permission/OS error, or an unreadable PARENT). `stat` separates the
    two: FileNotFoundError → absent; any other OSError → unverified. Existence isn't enough — we confirm
    we can actually enumerate a dir / read a regular file.

    A non-regular, non-dir path (FIFO / socket / device) at a persistence location is UNVERIFIED and is
    NEVER opened: opening a FIFO read-blocks forever (the hazard), and a normal authorized_keys /
    rc / agent is a regular file — a non-regular one there is itself anomalous, not a certifiable clean."""
    try:
        st = p.stat()
    except FileNotFoundError:
        return "absent"
    except OSError:
        return "unverified"                     # e.g. an unreadable PARENT — exists-ish, can't confirm
    if stat.S_ISDIR(st.st_mode):
        try:
            for _ in p.iterdir():               # can we actually list it?
                break
        except OSError:
            return "unverified"
        return "ok"
    if stat.S_ISREG(st.st_mode):
        try:
            with p.open("rb"):                  # regular file → safe to open; can we actually read it?
                pass
        except OSError:
            return "unverified"
        return "ok"
    return "unverified"                         # FIFO/socket/device — anomalous AND unsafe to open


def _surface_is_absent(graded: list[tuple[str, Path, str]]) -> bool:
    """True when EVERY certified location is absent — nothing was enumerated, so nothing can be called
    clean. Guarded on the anchor and on the platform: on Windows every certified location is
    absent by construction, so firing there would say nothing about the host."""
    if not persistence_surface_is_enumerable():
        return False
    if not any(label == _ANCHOR_LABEL for label, _p, _state in graded):
        return False
    # NOT relaxed for a dangling symlink, though one is visible in `ls` on a configured account: a
    # wipe of `~/dotfiles` leaves `~/.zshrc -> …` dangling, and `ln -s /nonexistent ~/.zlogin` would
    return all(state == "absent" for _label, _p, state in graded)


def check_persistence_coverage() -> list[HygieneIssue]:
    """Emit a single severity-`unknown` issue when the persistence surface could not be established —
    either because a location exists but could not be READ, or because the whole surface is ABSENT and
    so nothing was enumerated at all. Both make the run UNKNOWN rather than a false clean.

    The two states are mutually exclusive by construction (an unreadable location is not an absent
    one), so each condition is asked independently and neither has to know about the other."""
    graded = [(label, p, _coverage(p)) for label, p in _must_verify_locations()]
    issues: list[HygieneIssue] = []

    unverified = [f"{label} ({p})" for label, p, state in graded if state == "unverified"]
    if unverified:
        issues.append(HygieneIssue(
            id="persistence-surface-unverified",
            severity="unknown",
            title="Persistence surface could not be fully verified",
            detail="These persistence locations exist but could not be read, so this host is "
                   "UNKNOWN, not clean: " + "; ".join(unverified) + ".",
            remediation="Read them, or inspect them by hand. Until then do not rotate credentials: "
                        f"{_WIPER_NOTE}.",
        ))

    if _surface_is_absent(graded):
        kinds = ", ".join(sorted({label for label, _p, _state in graded}))
        issues.append(HygieneIssue(
            id="persistence-surface-not-established",
            severity="unknown",
            title="Persistence surface could not be established",
            detail=f"Every persistence location this audit certifies is absent ({kinds}), so nothing "
                   "was examined. That is a new account, a container or a CI image — or a destroyed "
                   "home directory. From disk they are indistinguishable.",
            # The INCIDENT reading leads: this also renders under an active-persistence verdict,
            # where a reader whose eye stops after one sentence must not have read "nothing to do".
            remediation="Confirm which it is. If files are gone, treat it as an incident: image the "
                        "disk before any further write — what is recoverable depends on the wipe "
                        f"variant. Do not rotate credentials — {_WIPER_NOTE}. New account, "
                        "container or CI image: nothing to do.",
        ))
    return issues
