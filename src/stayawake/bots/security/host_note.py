#!/usr/bin/env python3
"""The line every repository verdict carries about this machine: a repository result is not a
verdict on the host, and `saw audit` comes before any credential is rotated."""
from __future__ import annotations

_ROTATE_AFTER_AUDIT = ("Before rotating any credential, run `saw audit` (rotating while a "
                       "persistence daemon is live can arm a home-directory wiper).")


def scan_host_note(*, infected: bool, local_loaders: list[str] | tuple[str, ...] = (),
                   clean: bool | None = None) -> str:
    """Say what a scan's verdict covers on this machine. Takes whether any target is infected, the
    paths of code loaders confirmed in working trees on this machine, and whether every target was
    scanned and found clean (taken as `not infected` when not given). Returns the note."""
    if local_loaders:
        return ("Host note: a code loader was found in a working tree ON THIS MACHINE "
                f"({', '.join(local_loaders[:3])}). It may already have run — the ways it arrives "
                "execute when the folder is opened or the project is built. Treat this host as "
                "compromised until `saw audit` says otherwise, and do NOT rotate credentials first "
                "(rotating while a persistence daemon is live can arm a home-directory wiper).")
    if infected or clean is False:
        return ("Host note: this scan checked repositories, not this machine. "
                + _ROTATE_AFTER_AUDIT)
    return ("Host note: a clean repo scan is NOT a host all-clear — it does not check host "
            "persistence. " + _ROTATE_AFTER_AUDIT)


def fix_host_note() -> str:
    """Say what a fix run covers on this machine. Returns the note."""
    return "Host note: saw fix cleans repositories, not this machine. " + _ROTATE_AFTER_AUDIT
