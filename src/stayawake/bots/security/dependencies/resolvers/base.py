#!/usr/bin/env python3
"""Resolver interface — one ecosystem's manifests/lockfiles → normalized deps.

A `Resolver` has a single responsibility: parse an ecosystem's dependency declarations into
`ResolvedDependency` (a `Purl` + its source file). It knows nothing about advisories or
matching — the store answers "is this bad", the matcher orchestrates.

Concrete resolvers share this **interface, not their internals**. Every ecosystem's lockfile
grammar is genuinely different (npm JSON trees, yarn's header blocks, pnpm's YAML keys, PyPI's
requirements/TOML/JSON locks, and later Cargo/Go/…), so a universal parameterized super-parser
would be the wrong abstraction — the epic's explicit "not too DRY" boundary. Adding an ecosystem
= add a resolver and register it; nothing else changes (Open/Closed).

**Interface status: FROZEN.** Validated by two independent implementations (npm + PyPI): `resolve(target) -> Iterator[ResolvedDependency]`, plus the shared `_read_whole` helper.
The fan-out (Go, Rust, Ruby, Composer, .NET, Maven) adds resolvers against this surface
without changing it.
"""
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
