#!/usr/bin/env python3
"""Read the objects a repository holds, never a view configured over them."""
from __future__ import annotations

import locale
import os
import sys
from pathlib import Path

from stayawake.lib.git.run import run, stdout_bytes_fed

MAX_LINK_TARGET_BYTES = 4096

_INHERITED_LOCATION = ("GIT_DIR", "GIT_COMMON_DIR", "GIT_WORK_TREE", "GIT_OBJECT_DIRECTORY",
                       "GIT_ALTERNATE_OBJECT_DIRECTORIES", "GIT_INDEX_FILE", "GIT_NAMESPACE")


def own_env() -> dict:
    """Build the environment a query of a repository's own objects runs in. Returns it."""
    env = {k: v for k, v in os.environ.items() if k not in _INHERITED_LOCATION}
    env["GIT_TERMINAL_PROMPT"] = "0"
    return env


def own_view(repo: str | Path, args: list[str], extra_env: dict | None = None):
    """Ask git about the objects a repository holds. Takes the repo, the arguments and any variables
    to add to the environment. Returns the completed process, or None when it could not run."""
    return run(repo, args, env={**own_env(), **(extra_env or {})})


def own_view_fed(repo: str | Path, args: list[str], stdin: bytes) -> bytes | None:
    """Ask git about the objects a repository holds, feeding `stdin`. Takes the repo, the arguments
    and the bytes to write. Returns the raw stdout, or None on any failure."""
    return stdout_bytes_fed(repo, args, stdin, env=own_env())


def batch_objects(raw: bytes):
    """Frame each object in a `cat-file --batch` stream. Takes the raw stream. Yields
    `(id, kind, body, whole)` per object, with empty strings and False for an id git did not
    resolve, and `whole` False for a body the stream ended before."""
    at = 0
    while at < len(raw):
        nl = raw.find(b"\n", at)
        if nl == -1:
            return
        parts = raw[at:nl].split()
        if len(parts) < 3 or not parts[2].isdigit():
            yield "", "", b"", False
            at = nl + 1
            continue
        size = int(parts[2])
        body, at = raw[nl + 1:nl + 1 + size], nl + 1 + size + 1
        yield parts[0].decode(), parts[1].decode(), body, len(body) == size


def link_targets(repo: str | Path, oids: list[str]) -> tuple[dict[str, str], bool]:
    """Read the target each stored symlink blob names. Takes the repo and the blob ids. Returns each
    readable id mapped to its target, and whether every id was read."""
    wanted = sorted(set(oids))
    if not wanted:
        return {}, True
    sized = own_view_fed(repo, ["cat-file", "--batch-check"], "\n".join(wanted).encode())
    if sized is None:
        return {}, False
    readable = []
    for line in sized.decode("utf-8", "replace").splitlines():
        parts = line.split()
        if (len(parts) >= 3 and parts[1] == "blob" and parts[2].isdigit()
                and int(parts[2]) <= MAX_LINK_TARGET_BYTES):
            readable.append(parts[0])
    raw = own_view_fed(repo, ["cat-file", "--batch"], "\n".join(readable).encode())
    if raw is None:
        return {}, False
    text_of: dict[str, str] = {}
    complete = True
    for oid, kind, body, whole in batch_objects(raw):
        if not whole or kind != "blob":
            complete = False
            continue
        text_of[oid] = body.split(b"\0", 1)[0].decode("utf-8", "replace")
    return text_of, complete and len(text_of) == len(wanted)


def read_blobs(repo: str | Path, oids: list[str], *, max_each: int,
               max_total: int) -> tuple[dict[str, bytes], dict[str, int]]:
    """Read stored blobs in one pass. Takes the repo, the blob ids, the largest blob to read and the
    most bytes to read in all. Returns each blob read whole, and each blob's size; one too large,
    missing or past the total is left out of the first, for the caller to read another way."""
    wanted = list(dict.fromkeys(oids))
    if not wanted:
        return {}, {}
    sized = own_view_fed(repo, ["cat-file", "--batch-check"], "\n".join(wanted).encode())
    if sized is None:
        return {}, {}
    sizes = {}
    for line in sized.decode("utf-8", "replace").splitlines():
        parts = line.split()
        if len(parts) == 3 and parts[1] == "blob" and parts[2].isdigit():
            sizes[parts[0]] = int(parts[2])
    chosen, total = [], 0
    for oid, size in sorted(sizes.items(), key=lambda item: item[1]):
        if size <= max_each and total + size <= max_total:
            chosen.append(oid)
            total += size
    raw = own_view_fed(repo, ["cat-file", "--batch"], "\n".join(chosen).encode()) if chosen else b""
    return ({oid: body for oid, kind, body, whole in batch_objects(raw or b"")
             if whole and kind == "blob"}, sizes)


def reachable_objects(repo: str | Path, tips: list[str], exclude: list[str] | None = None) -> set[str] | None:
    """Ask which objects are reachable from some commits and not from others. Takes the repo, the
    commits to walk from and the commits to exclude. Returns the object ids, or None when git could
    not answer."""
    if not tips:
        return set()
    feed = "".join(f"{tip}\n" for tip in tips) + "".join(f"^{tip}\n" for tip in exclude or ())
    out = own_view_fed(repo, ["rev-list", "--objects", "--stdin"], feed.encode())
    if out is None:
        return None
    return {line.split()[0].decode("ascii", "replace") for line in out.splitlines() if line.split()}


def blob(repo: str | Path, oid: str) -> bytes | None:
    """Read one stored blob as the repository holds it. Takes the repo and the object id. Returns
    its bytes, or None when git could not read it."""
    return own_view_fed(repo, ["cat-file", "blob", oid], b"")


def blob_text(repo: str | Path, oid: str) -> str | None:
    """Read one stored blob as text, decoded and line-ended the way git's other text output reaches
    saw. Takes the repo and the object id. Returns the text, or None when git could not read it."""
    data = blob(repo, oid)
    if data is None:
        return None
    encoding = "utf-8" if sys.flags.utf8_mode else locale.getencoding()
    return data.decode(encoding, "replace").replace("\r\n", "\n").replace("\r", "\n")
