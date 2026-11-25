#!/usr/bin/env python3
"""One run at a time in a folder, with a hold the system releases if the run ends."""
from __future__ import annotations

import contextlib
import os
import time
from pathlib import Path

LOCK_NAME = ".saw-lock"
_RETRY_SECONDS = 0.1


class Busy(Exception):
    """Another run holds the folder."""


def _take(fd: int) -> bool:
    """Try to take the hold on an open lock file. Takes its descriptor. Returns whether it was taken."""
    if os.name == "nt":
        import msvcrt
        try:
            msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)
            return True
        except OSError:
            return False
    import fcntl
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        return True
    except BlockingIOError:
        return False


@contextlib.contextmanager
def held(folder: Path, *, wait: float):
    """Hold an existing folder for this run. Takes the folder and how long to wait for another run
    to let go. Raises `Busy` when another run still holds it after that, and `OSError` when the
    folder cannot be held."""
    fd = os.open(Path(folder) / LOCK_NAME, os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0), 0o600)
    try:
        deadline = time.monotonic() + wait
        while not _take(fd):
            if time.monotonic() >= deadline:
                raise Busy(str(folder))
            time.sleep(_RETRY_SECONDS)
        yield
    finally:
        os.close(fd)
