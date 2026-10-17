#!/usr/bin/env python3
"""The line every repository verdict carries about this machine: a repository result is not a
verdict on the host, and `saw audit` comes before any credential is rotated."""
from __future__ import annotations

_AUDIT_FIRST = ("Before you change any password or token, run `saw audit`: changing them first "
                "can set off code that deletes your files.")


def scan_host_note(*, infected: bool, local_loaders: list[str] | tuple[str, ...] = (),
                   folders: int = 1, clean: bool | None = None) -> str:
    """Say what a scan's verdict covers on this machine. Takes whether any target is infected, the
    files on this machine holding confirmed code that runs when their folder is opened, installed or
    built (each named with its folder), how many folders hold them, and whether every target was
    scanned and found clean (taken as `not infected` when not given). Returns the note."""
    if local_loaders:
        many = folders > 1
        where = ", ".join(local_loaders[:3])
        if len(local_loaders) > 3:
            where += f", and {len(local_loaders) - 3} more"
        return (f"Host note: {folders} folder{'s' if many else ''} on this machine hold"
                f"{'' if many else 's'} malicious code that runs when a folder is opened, installed "
                f"or built ({where}). If you opened, installed or built "
                f"{'one of them' if many else 'it'}, that code may have run. Run `saw audit` now: "
                "changing a password or token before it has checked this machine can set off code "
                f"that deletes your files. Do not open, install or build {'those folders' if many else 'that folder'} "
                f"until `saw fix` has cleaned {'them' if many else 'it'}.")
    if infected or clean is False:
        return f"Host note: this scan checked repositories, not this machine. {_AUDIT_FIRST}"
    return f"Host note: a clean result covers these repositories, not this machine. {_AUDIT_FIRST}"


def fix_host_note() -> str:
    """Say what a fix run covers on this machine. Returns the note."""
    return f"Host note: saw fix cleans repositories, not this machine. {_AUDIT_FIRST}"
