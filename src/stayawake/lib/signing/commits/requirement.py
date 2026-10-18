#!/usr/bin/env python3
"""Tell whether the commits a rewrite replaces carry signatures."""
from __future__ import annotations

from pathlib import Path

from stayawake.lib.git.run import UNTRUSTED, run
from stayawake.lib.signing.commits.probe import PROBE_TIMEOUT



def carries_signature(repo: str | Path, sha: str) -> bool | None:
    """Whether the commit object holds a signature header. None when git could not be asked.

    The header, never `%G?`: that reports VERIFICATION, so a perfectly signed ssh commit reads as
    `N` on a host with no `allowedSignersFile` — and a rewrite would then strip a signature it had
    just decided was not there.
    """
    res = run(repo, ["cat-file", "commit", sha], timeout=PROBE_TIMEOUT, context=UNTRUSTED)
    if res is None or res.returncode != 0:
        return None
    headers = res.stdout.split("\n\n", 1)[0]
    return any(line.startswith("gpgsig") for line in headers.splitlines())


def any_signed(repo: str | Path, shas) -> bool:
    """True when any of `shas` carries a signature, and ALSO when git could not answer for one of
    them — an unreadable commit is not evidence that nothing was signed."""
    for sha in shas:
        if carries_signature(repo, sha) is not False:
            return True
    return False
