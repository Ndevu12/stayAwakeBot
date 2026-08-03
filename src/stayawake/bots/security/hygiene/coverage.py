#!/usr/bin/env python3
"""Persistence-surface COVERAGE (#1332) — did we actually READ the user-owned persistence locations?

`saw` never claims clean over content it did not read. The detection probes (os_service, mechanism)
degrade gracefully when a path is absent — correct — but they degrade the SAME way when a path exists
yet cannot be read, so "couldn't enumerate" was silently indistinguishable from "enumerated and clean".
Where the mistake costs a wiped home directory (rotating a token while a `gh-token-monitor` daemon is
live), that silence is unsafe.

This probe is the enumeration-HONESTY layer. It does NOT re-implement detection and does NOT touch the
detection probes (their findings stay byte-identical). It independently checks whether each USER-OWNED
persistence location is READABLE, and emits ONE `persistence-surface-unverified` (severity `unknown`)
issue naming any that exist but could not be read — so the run reads (and exits) as UNKNOWN, not clean,
and the rotation-safety verdict withholds its all-clear. Locations are sourced from the detection
modules themselves (single source of truth), so the surface we certify is exactly the surface we scan.
"""
from __future__ import annotations

import stat
from pathlib import Path

from .models import HygieneIssue, _WIPER_NOTE
from . import os_service, runner, mechanism


def _must_verify_locations() -> list[tuple[str, Path]]:
    """(surface-label, path) for the user-owned persistence locations whose unreadability must
    withhold an all-clear — the launch-agent/service dirs and the self-hosted-runner install dirs
    (active footholds), ~/.ssh/authorized_keys, and shell startup files. Derived from the detection
    probes' own location definitions so the certified surface can never drift from the scanned one."""
    home = Path.home()
    locs: list[tuple[str, Path]] = [("launch-agent / service dir", d)
                                    for d in os_service.user_persistence_dirs()]
    locs += [("self-hosted-runner dir", d) for d in runner.user_runner_dirs()]
    ssh = home / ".ssh"
    locs += [("SSH authorized_keys", ssh / name) for name in mechanism._SSH_AUTHKEYS]
    locs += [("shell startup file", home / name) for name in mechanism._SHELL_RC_FILES]
    return locs


def _coverage(p: Path) -> str:
    """'ok' (read it) | 'absent' (nothing planted here) | 'unverified' (exists but can't be certified).

    ABSENT is clean: a user-level worm planting persistence must CREATE the path (as the user, who can
    then read it), so a path that does not exist carries nothing. UNVERIFIED is the unsafe case — it
    exists but could not be read (a permission/OS error, or an unreadable PARENT). `stat` separates the
    two: FileNotFoundError → absent; any other OSError → unverified. Existence isn't enough — we confirm
    we can actually enumerate a dir / read a regular file.

    A non-regular, non-dir path (FIFO / socket / device) at a persistence location is UNVERIFIED and is
    NEVER opened: opening a FIFO read-blocks forever (the #1226 hazard), and a normal authorized_keys /
    rc / agent is a regular file — a non-regular one there is itself anomalous, not a certifiable clean."""
    try:
        st = p.stat()                           # follows symlinks; does NOT open (safe on a FIFO)
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


def check_persistence_coverage() -> list[HygieneIssue]:
    """Emit a single `persistence-surface-unverified` (severity `unknown`) issue when any user-owned
    persistence location exists but could not be read — so the run is UNKNOWN, never a false clean."""
    unverified = [f"{label} ({p})" for label, p in _must_verify_locations()
                  if _coverage(p) == "unverified"]
    if not unverified:
        return []
    return [HygieneIssue(
        id="persistence-surface-unverified",
        severity="unknown",
        title="Persistence surface could not be fully verified",
        detail="These user-owned persistence locations exist but could not be read, so this host "
               "cannot be certified free of a credential-rotation wiper: " + "; ".join(unverified)
               + ". A run that could not enumerate the surface is UNKNOWN, not clean.",
        remediation="Re-run with permission to read them (or inspect them by hand). Until the surface "
                    f"is verified, treat credential rotation as UNSAFE — {_WIPER_NOTE}.",
    )]
