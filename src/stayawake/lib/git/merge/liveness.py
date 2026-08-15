#!/usr/bin/env python3
"""Is the content a merge introduced STILL in the working tree, or was it removed afterwards?

"This merge was evil" and "this payload is in the file you are about to run" call for different
responses, and every tool in this space answers only the first. Blob identity answers the second
cheaply: git addresses content by hash, so the blob a merge recorded at a path either is still the
blob at HEAD or is not.

The direction of that evidence is asymmetric, which is the whole design. An identical blob PROVES the
bytes are still there. A different blob proves only that the file changed — the introduced lines may
be untouched inside it — so it is reported as CHANGED, never as removed. Treating "the hash moved" as
"the payload is gone" is the mistake the vulnerable-code-lineage literature warns about: a reformat,
a cherry-pick or an unrelated edit all move the hash while the code stays.
"""
from __future__ import annotations

from pathlib import Path

from stayawake.lib.git.run import run

PRESENT = "present"    # byte-identical blob still at HEAD — the introduced content is live
CHANGED = "changed"    # the file changed since; whether the introduced lines survive is UNKNOWN
GONE = "gone"          # the path no longer exists at HEAD
UNKNOWN = "unknown"    # could not be established (detached/empty HEAD, unreadable object)


def _blob(repo: str | Path, rev: str, path: str) -> str | None:
    res = run(repo, ["rev-parse", f"{rev}:{path}"])
    if res is None or res.returncode != 0:
        return None
    oid = (res.stdout or "").strip()
    return oid or None


def introduced_liveness(repo: str | Path, merge_sha: str, path: str, head: str = "HEAD") -> str:
    """Whether the blob this merge recorded at `path` is still the blob at `head`."""
    at_merge = _blob(repo, merge_sha, path)
    if at_merge is None:
        return UNKNOWN
    at_head = _blob(repo, head, path)
    if at_head is None:
        # Absent at HEAD. Distinguish "the path was removed" from "HEAD is unreadable", so an
        # unreadable HEAD never renders as a reassuring "it is gone".
        return GONE if run(repo, ["rev-parse", f"{head}^{{tree}}"]) is not None else UNKNOWN
    return PRESENT if at_head == at_merge else CHANGED


def describe(state: str) -> str:
    """One clause for the finding, saying what the operator can act on."""
    return {
        PRESENT: "still present in the working tree byte-for-byte",
        CHANGED: "the file changed after this merge — whether the introduced lines survive is "
                 "UNVERIFIED, so do not read this as removed",
        GONE: "the path no longer exists at HEAD, but the content remains in history and in any fork",
        UNKNOWN: "liveness could not be established",
    }.get(state, "liveness could not be established")
