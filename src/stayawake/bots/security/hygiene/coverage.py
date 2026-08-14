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

**Absent is clean per location, but an ENTIRELY absent surface is not (#120).** A wipe does not suppress
these checks — it SATISFIES them: every location raises FileNotFoundError, every location grades
`absent` ("nothing planted here"), zero issues are raised, and the run reaches its most reassuring line,
*"persistence surface enumerated and clean — rotating credentials is safe"*, on a host whose home was
just destroyed. Nothing was enumerated, so "enumerated" is the false word, and the verdict lands on the
one action a rotation-triggered wiper is armed for. `persistence-surface-not-established` is that third
state: absent because there is nothing to find, versus absent because nothing could be established. It
fails to UNKNOWN and never to a finding — a new account, a container and a CI image present identically
(measured: macOS creates an account from a template carrying no shell startup file and no
`~/Library/LaunchAgents`), and from disk alone the two are indistinguishable.
"""
from __future__ import annotations

import stat
from pathlib import Path

from .models import HygieneIssue, _WIPER_NOTE, persistence_surface_is_enumerable
from . import os_service, runner, mechanism

# The ANCHOR of the certified surface: the one location class an account in real USE acquires, and
# therefore the one whose absence makes a wholly-absent surface worth saying out loud. Named once
# because `_surface_is_absent` requires it to be present in the list — "everything is absent" over a
# list that happens to contain no anchor is vacuously true, not evidence.
_ANCHOR_LABEL = "shell startup file"


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
    locs += [(_ANCHOR_LABEL, home / name) for name in mechanism._SHELL_RC_FILES]
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


def _surface_is_absent(graded: list[tuple[str, Path, str]]) -> bool:
    """True when EVERY certified location is absent — the run enumerated nothing, so it cannot call
    the surface clean (#120).

    Two guards keep the claim honest rather than vacuous. The ANCHOR must be in the list, because
    "all absent" over a list with nothing an in-use account acquires proves nothing. And the platform
    must be one whose surface `saw` enumerates at all — on Windows every certified location is absent
    by construction, which would make this fire on every host and say nothing (models is the one
    authority for that, shared with the scope note)."""
    if not persistence_surface_is_enumerable():
        return False
    if not any(label == _ANCHOR_LABEL for label, _p, _state in graded):
        return False
    # A DANGLING symlink is `absent` to `_coverage` — correctly, since nothing readable is planted
    # there — but it is not absent to this question. A dotfile manager that has not run yet, or a
    # dotfiles repo on an unmounted volume, leaves `~/.zshrc -> …` visible in `ls` on an obviously
    # configured account; reporting "nothing is here" over a link the operator can see is wrong.
    return all(state == "absent" and not p.is_symlink() for _label, p, state in graded)


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
            detail="These user-owned persistence locations exist but could not be read, so this host "
                   "cannot be certified free of a credential-rotation wiper: " + "; ".join(unverified)
                   + ". A run that could not enumerate the surface is UNKNOWN, not clean.",
            remediation="Re-run with permission to read them (or inspect them by hand). Until the "
                        f"surface is verified, treat credential rotation as UNSAFE — {_WIPER_NOTE}.",
        ))

    if _surface_is_absent(graded):
        # The location classes are NAMED FROM THE DATA, never a prose list: a hand-written one drifts
        # the moment the certified surface gains or loses a class, and a scope claim that misdescribes
        # what was looked at is the same defect this module exists to remove.
        kinds = ", ".join(sorted({label for label, _p, _state in graded}))
        issues.append(HygieneIssue(
            id="persistence-surface-not-established",
            severity="unknown",
            title="Persistence surface could not be established",
            detail=f"Every user-owned persistence location this audit certifies is absent ({kinds}), "
                   "so nothing was enumerated here and nothing can be certified clean. A host in this "
                   "state is a new account, a container or a CI image — or one whose home directory "
                   "has been destroyed. From disk alone the two are indistinguishable, and a wipe "
                   "leaves this check looking exactly like a clean host.",
            remediation="Confirm which it is. On a new account, a container or a CI image this is "
                        "expected and there is nothing to do. If this host had files and they are "
                        "gone, treat it as an incident: image the disk BEFORE using it further — a "
                        "plain delete leaves the content recoverable in freed blocks and continued "
                        "use overwrites it — and treat credential rotation as UNSAFE until the "
                        f"surface is confirmed ({_WIPER_NOTE}).",
        ))
    return issues
