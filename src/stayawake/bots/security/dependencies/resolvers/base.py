#!/usr/bin/env python3
"""Resolver interface — one ecosystem's manifests/lockfiles → normalized deps (#1119).

A `Resolver` has a single responsibility: parse an ecosystem's dependency declarations into
`ResolvedDependency` (a `Purl` + its source file). It knows nothing about advisories or
matching — the store answers "is this bad", the matcher orchestrates.

Concrete resolvers share this **interface, not their internals**. Every ecosystem's lockfile
grammar is genuinely different (npm JSON trees, yarn's header blocks, pnpm's YAML keys, and
later PyPI/Cargo/Go/…), so a universal parameterized super-parser would be the wrong
abstraction — the epic's explicit "not too DRY" boundary. Adding an ecosystem = add a
resolver and register it; nothing else changes (Open/Closed).
"""
from __future__ import annotations

from typing import Iterator

from stayawake.bots.security.dependencies.purl import ResolvedDependency


class Resolver:
    """Base class: turn a scan `target` into the packages it declares/locks."""

    ecosystem: str = ""

    def resolve(self, target) -> Iterator[ResolvedDependency]:
        raise NotImplementedError
