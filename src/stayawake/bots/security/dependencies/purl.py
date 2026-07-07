#!/usr/bin/env python3
"""Normalized package identity — the PURL spine (#1119).

`Purl` is a small subset of the package-url spec (`pkg:{type}/{name}@{version}`): the
lingua franca every ecosystem resolver emits and the advisory store keys on. Adopting the
standard here (rather than inventing our own identity) is the DRY that de-hardcodes "how do
we name a package" across every ecosystem and every knowledge source — see the dynamic
dependency-audit epic.

`ResolvedDependency` pairs a `Purl` with the repo-relative manifest/lockfile it was
declared or locked in, so a finding can be anchored to the exact file the way the
pre-refactor matcher did.
"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Purl:
    """A package identity as `pkg:{type}/{name}@{version}`.

    `type` is the ecosystem (``npm``, ``pypi``, …). `name` includes any scope/namespace
    exactly as the ecosystem writes it (npm's ``@scope/pkg``), so it round-trips the
    coordinate the inline known-bad seed uses.
    """

    type: str
    name: str
    version: str

    @property
    def coordinate(self) -> str:
        """``name@version`` — the ecosystem-agnostic key the inline `known_bad` seed uses.

        Phase 1a matches on this (npm-only reality, preserving the pre-refactor behaviour);
        phase 1b will key advisories on the full ecosystem-qualified identity via `__str__`.
        """
        return f"{self.name}@{self.version}"

    def __str__(self) -> str:
        return f"pkg:{self.type}/{self.name}@{self.version}"


@dataclass(frozen=True)
class ResolvedDependency:
    """A `Purl` tagged with the repo-relative file it was declared or locked in."""

    purl: Purl
    source_path: str

    @property
    def source_name(self) -> str:
        """The bare filename of the source manifest/lockfile (for finding evidence)."""
        return self.source_path.rsplit("/", 1)[-1]
