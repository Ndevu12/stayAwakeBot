#!/usr/bin/env python3
"""Git LFS pointers, and the objects a repository keeps for them."""
from __future__ import annotations

import hashlib
import os
import re
import stat
from pathlib import Path

from stayawake.lib.git.objects import own_view

SPEC_URLS = (b"https://git-lfs.github.com/spec/v1", b"https://hawser.github.com/spec/v1",
             b"http://git-media.io/v/2")
POINTER_MAX_BYTES = 1024
_SPEC_NAMES = (b"git-lfs", b"hawser", b"git-media")
_POINTER_KEYS = (b"version", b"oid", b"size")
_EXTENSION_KEY = re.compile(rb"ext-[0-9]-[0-9A-Za-z_]")
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


def _size(value: bytes) -> int | None:
    """Read a pointer's size. Takes the value. Returns the size, or None when it is not a whole
    number of zero or more."""
    digits = value[1:] if value[:1] in (b"+", b"-") else value
    if not digits.isdigit():
        return None
    size = -int(digits) if value[:1] == b"-" else int(digits)
    return size if size >= 0 else None


def _trimmed(data: bytes) -> bytes:
    """Trim the white space around stored bytes. Takes the bytes. Returns them without it."""
    return data.decode("utf-8", "surrogateescape").strip().encode("utf-8", "surrogateescape")


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


def _decoded(head: bytes) -> tuple[str, int] | None:
    """Decode a pointer as git-lfs decodes one. Takes the first bytes of a stored file, at most a
    pointer's length. Returns the object's sha256 id and size, or None when git-lfs reads none."""
    fields: dict[bytes, bytes] = {}
    extensions: dict[bytes, bytes] = {}
    for line in _trimmed(head).split(b"\n"):
        line = line[:-1] if line.endswith(b"\r") else line
        if not line:
            continue
        key, sp, value = line.partition(b" ")
        if not sp or len(fields) == len(_POINTER_KEYS):
            return None
        if key == _POINTER_KEYS[len(fields)]:
            fields[key] = value
        elif _EXTENSION_KEY.match(key):
            extensions[key] = value
        else:
            return None
    size = _size(fields.get(b"size", b""))
    if (fields.get(b"version") not in SPEC_URLS
            or not _sha256_ref(fields.get(b"oid", b"")) or size is None or size >= 1 << 63
            or not all(_sha256_ref(value) for value in extensions.values())
            or len({key[4] for key in extensions}) != len(extensions)):
        return None
    return fields[b"oid"][len(b"sha256:"):].decode("ascii"), size


def _listed(data: bytes) -> tuple[str, int] | None:
    """Find the object a pointer's lines name, in any order and among any other lines. Takes stored
    bytes of at most a pointer's length. Returns the object's sha256 id and size, or None when they name
    none."""
    lines = [line.strip() for line in _trimmed(data).split(b"\n")]
    if not any(line == b"version " + url for line in lines for url in SPEC_URLS):
        return None
    oid = size = None
    for line in lines:
        key, _sp, value = line.partition(b" ")
        if key == b"oid" and _sha256_ref(value):
            oid = value[len(b"sha256:"):]
        elif key == b"size" and _size(value) is not None:
            size = _size(value)
    return None if oid is None or size is None else (oid.decode("ascii"), size)


def only_a_pointer(data: bytes) -> bool:
    """Tell whether stored bytes hold a Git LFS pointer and nothing else. Takes the bytes. Returns
    True when they are a version line, then only the keys a pointer holds."""
    return _fields(data) is not None


def named_object(data: bytes) -> tuple[str, int] | None:
    """Read the object a stored file names as a Git LFS pointer. Takes the file's bytes, or its first
    bytes when there are more than a pointer holds. Returns the object's sha256 id and size, or None
    when it names none."""
    if not data or not any(name in data[:POINTER_MAX_BYTES] for name in _SPEC_NAMES):
        return None
    if len(data) > POINTER_MAX_BYTES:
        return _decoded(data[:POINTER_MAX_BYTES])
    return _listed(data)


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
    named = named_object(data)
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
