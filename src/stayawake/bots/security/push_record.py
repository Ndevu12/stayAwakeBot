#!/usr/bin/env python3
"""What saw has already verified for a repository's pushes, under which policy, and what it has
still to read."""
from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass, field
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path

from stayawake.utils import atomicwrite, env

MAX_VERIFIED = 200_000
MAX_PENDING = 200_000


def policy_digest(signatures, allowlist, max_file_bytes: int) -> str:
    """Name the policy a verdict was reached under. Takes the signatures, the allowlist and the
    per-file read cap. Returns a digest that changes when any of them, or saw, changes."""
    try:
        saw = version("stayawakebot")
    except PackageNotFoundError:
        saw = "unknown"
    text = json.dumps([saw, signatures, allowlist or [], max_file_bytes], sort_keys=True,
                      default=str)
    return hashlib.sha256(text.encode("utf-8", "surrogateescape")).hexdigest()


def version_key(path: str, oid: str) -> str:
    """Name one stored version of one path. Takes the path and the object id. Returns the key."""
    return hashlib.sha256(path.encode("utf-8", "surrogateescape") + b"\0" + oid.encode()).hexdigest()[:40]


@dataclass
class PushRecord:
    """The verified versions and the versions still to read, for one repository."""

    where: Path
    policy: str
    verified: set[str] = field(default_factory=set)
    pending: list[dict] = field(default_factory=list)
    unlisted: list[dict] = field(default_factory=list)

    def is_verified(self, path: str, oid: str) -> bool:
        """Whether this version was verified clean under the current policy."""
        return version_key(path, oid) in self.verified

    def mark_verified(self, path: str, oid: str) -> None:
        """Record a version as verified clean, while the record has room."""
        if len(self.verified) < MAX_VERIFIED:
            self.verified.add(version_key(path, oid))

    def save(self) -> bool:
        """Write the record. Returns True only when it was written and read back."""
        body = {"policy": self.policy, "verified": sorted(self.verified), "pending": self.pending,
                "unlisted": self.unlisted}
        return atomicwrite.replace(self.where, json.dumps(body))


def record_path(git_dir: str | Path) -> Path:
    """Where the record for a repository lives. Takes its git directory. Returns the path."""
    try:
        key = os.path.realpath(str(git_dir))
    except (OSError, ValueError):
        key = str(git_dir)
    name = hashlib.sha256(key.encode("utf-8", "surrogateescape")).hexdigest()[:32]
    return Path(env.xdg_cache_home()) / "saw" / "push-record" / f"{name}.json"


def load(git_dir: str | Path, policy: str) -> PushRecord:
    """Read the record for a repository under the current policy. Takes its git directory and the
    policy digest. Returns the record; verified versions from another policy are dropped, and what
    was still to read is kept."""
    where = record_path(git_dir)
    record = PushRecord(where, policy)
    try:
        if where.is_symlink():
            return record
        body = json.loads(where.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return record
    if not isinstance(body, dict):
        return record
    if body.get("policy") == policy and isinstance(body.get("verified"), list):
        record.verified = {k for k in body["verified"] if isinstance(k, str)}
    unlisted = body.get("unlisted")
    if isinstance(unlisted, list):
        record.unlisted = [c for c in unlisted if isinstance(c, dict)
                           and isinstance(c.get("commit"), str) and isinstance(c.get("role"), str)
                           and isinstance(c.get("parents"), list)
                           and all(isinstance(i, str) for i in c["parents"])]
    pending = body.get("pending")
    if isinstance(pending, list):
        record.pending = [p for p in pending if isinstance(p, dict)
                          and all(isinstance(p.get(k), str) for k in ("path", "oid", "commit"))]
    return record
