#!/usr/bin/env python3
"""The line every repository verdict carries about this machine: a repository result is not a
verdict on the host, and `saw audit` comes before any credential is rotated."""
from __future__ import annotations

_AUDIT_FIRST = ("Before you change any password or token, run `saw audit`: changing them first "
                "can set off code that deletes your files.")


def scan_host_note(*, infected: bool, local_loaders: list[str] | tuple[str, ...] = (),
                   clean: bool | None = None) -> str:
    """Say what a scan's verdict covers on this machine. Takes whether any target is infected, the
    paths of code loaders confirmed in working trees on this machine, and whether every target was
    scanned and found clean (taken as `not infected` when not given). Returns the note."""
    if local_loaders:
        return ("Host note: malicious code is in a folder on this machine "
                f"({', '.join(local_loaders[:3])}), and it may already have run. Run `saw audit` "
                "now: changing a password or token before it has checked this machine can set off "
                "code that deletes your files. Do not open, install or build that folder until it "
                "is cleaned.")
    if infected or clean is False:
        return f"Host note: this scan checked repositories, not this machine. {_AUDIT_FIRST}"
    return f"Host note: a clean result covers these repositories, not this machine. {_AUDIT_FIRST}"


def fix_host_note() -> str:
    """Say what a fix run covers on this machine. Returns the note."""
    return f"Host note: saw fix cleans repositories, not this machine. {_AUDIT_FIRST}"
