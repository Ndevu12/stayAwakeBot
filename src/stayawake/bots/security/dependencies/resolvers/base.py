#!/usr/bin/env python3
"""Resolver interface — one ecosystem's manifests/lockfiles → normalized deps."""
from __future__ import annotations

from typing import Iterator

from stayawake.bots.security.dependencies.purl import ResolvedDependency

_MAX_LOCKFILE_BYTES = 32_000_000


class Resolver:
    """Base class: turn a scan `target` into the packages it declares/locks."""

    ecosystem: str = ""

    def resolve(self, target) -> Iterator[ResolvedDependency]:
        raise NotImplementedError

    @staticmethod
    def _read_whole(target, rel: str) -> str | None:
        """Read a manifest/lockfile WHOLE (bypassing the scan's head/tail truncation, which would
        turn a large lockfile into unparseable JSON/TOML/YAML). Falls back to read_text. Shared by
        every resolver — reading a lockfile in full is ecosystem-agnostic."""
        raw = target.read_bytes(rel, limit=_MAX_LOCKFILE_BYTES)
        if raw is not None:
            return raw.decode("utf-8", errors="replace")
        return target.read_text(rel)
