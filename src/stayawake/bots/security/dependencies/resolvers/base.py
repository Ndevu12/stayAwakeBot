#!/usr/bin/env python3
"""Resolver interface — one ecosystem's manifests/lockfiles → normalized deps (#1119).

A `Resolver` has a single responsibility: parse an ecosystem's dependency declarations into
`ResolvedDependency` (a `Purl` + its source file). It knows nothing about advisories or
matching — the store answers "is this bad", the matcher orchestrates.

Concrete resolvers share this **interface, not their internals**. Every ecosystem's lockfile
grammar is genuinely different (npm JSON trees, yarn's header blocks, pnpm's YAML keys, PyPI's
requirements/TOML/JSON locks, and later Cargo/Go/…), so a universal parameterized super-parser
would be the wrong abstraction — the epic's explicit "not too DRY" boundary. Adding an ecosystem
= add a resolver and register it; nothing else changes (Open/Closed).

**Interface status: FROZEN.** Validated by two independent implementations (npm #1119 + PyPI
#1122): `resolve(target) -> Iterator[ResolvedDependency]`, plus the shared `_read_whole` helper.
The #1123 fan-out (Go, Rust, Ruby, Composer, .NET, Maven) adds resolvers against this surface
without changing it.
"""
from __future__ import annotations

from typing import Iterator

from stayawake.bots.security.dependencies.purl import ResolvedDependency

# Lockfiles must be parsed WHOLE (a head/tail-truncated lockfile is invalid JSON/TOML/YAML and
# yields nothing), so read up to this generous cap instead of the scan's default source cap. 32 MB
# covers any realistic lockfile while bounding memory on a pathological one.
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
