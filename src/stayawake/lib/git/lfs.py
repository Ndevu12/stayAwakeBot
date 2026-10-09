#!/usr/bin/env python3
"""Git LFS pointers, and the objects a repository keeps for them."""
from __future__ import annotations

import hashlib
import os
import stat
from pathlib import Path

from stayawake.lib.git.objects import own_view

SPEC_URLS = (b"https://git-lfs.github.com/spec/v1", b"https://hawser.github.com/spec/v1",
             b"http://git-media.io/v/2")
POINTER_MAX_BYTES = 1024
_HEX = frozenset(b"0123456789abcdef")
_CHUNK = 1 << 20


def _sha256_ref(value: bytes) -> bool:
    """Tell whether a pointer value is a sha256 reference. Takes the value. Returns the answer."""
    digest = value[len(b"sha256:"):]
    return value.startswith(b"sha256:") and len(digest) == 64 and set(digest) <= _HEX


def _extension_key(key: bytes) -> bool:
    """Tell whether a pointer key names an extension. Takes the key. Returns the answer."""
    parts = key.split(b"-", 2)
    return (len(parts) == 3 and parts[0] == b"ext" and len(parts[1]) == 1
            and parts[1].isdigit() and parts[2].replace(b"_", b"").isalnum())


def _fields(data: bytes) -> dict[bytes, bytes] | None:
    """Split stored bytes into a pointer's fields. Takes the bytes. Returns each key's value when
    every line is one a Git LFS pointer holds and it names an object, else None."""
    if not data or len(data) > POINTER_MAX_BYTES:
        return None
    lines = data.strip().split(b"\n")
    if not any(lines[0] == b"version " + url for url in SPEC_URLS):
        return None
    fields: dict[bytes, bytes] = {}
    for line in lines[1:]:
        key, sp, value = line.partition(b" ")
        known = ((key == b"oid" and _sha256_ref(value))
                 or (key == b"size" and value.isdigit() and len(value) <= 20)
                 or (_extension_key(key) and _sha256_ref(value)))
        if not sp or key in fields or not known:
            return None
        fields[key] = value
    return fields if b"oid" in fields and b"size" in fields else None


def is_pointer(data: bytes) -> bool:
    """Tell whether stored bytes are a Git LFS pointer. Takes the bytes. Returns True when git-lfs
    reads them as one: a version line, then only the keys a pointer holds."""
    return _fields(data) is not None


def pointed_object(data: bytes) -> tuple[str, int] | None:
    """Read the object a pointer names. Takes the pointer bytes. Returns its sha256 id and size, or
    None when the bytes are not a pointer."""
    fields = _fields(data)
    if fields is None:
        return None
    return fields[b"oid"][len(b"sha256:"):].decode("ascii"), int(fields[b"size"])


def store_of(repo: str | Path) -> Path | None:
    """Find where a repository keeps its Git LFS objects. Takes the repository or its git
    directory. Returns the objects directory, or None when git could not say."""
    res = own_view(repo, ["rev-parse", "--path-format=absolute", "--git-common-dir"])
    if res is None or res.returncode != 0 or not (res.stdout or "").strip():
        return None
    return Path(res.stdout.strip()) / "lfs" / "objects"


def local_object(store: Path, data: bytes) -> Path | None:
    """Find the object a pointer names in a local store, checked against the pointer. Takes the
    objects directory and the pointer bytes. Returns the object's path when it is a regular file
    inside the store, reached through no link, whose size and sha256 match the pointer, else
    None."""
    named = pointed_object(data)
    if named is None:
        return None
    oid, size = named
    path = store / oid[:2] / oid[2:4] / oid
    try:
        st = os.lstat(path)
        if not stat.S_ISREG(st.st_mode) or st.st_size != size:
            return None
        if os.path.realpath(path) != os.path.join(os.path.realpath(store), oid[:2], oid[2:4], oid):
            return None
        digest = hashlib.sha256()
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
        with os.fdopen(fd, "rb") as fh:
            for chunk in iter(lambda: fh.read(_CHUNK), b""):
                digest.update(chunk)
    except OSError:
        return None
    return path if digest.hexdigest() == oid else None
