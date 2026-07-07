#!/usr/bin/env python3
"""Dependency-audit domain: resolve a repo's declared/locked packages to `Purl`s and match
them against an advisory store (#1119).

Kept a sibling of `matchers/` — not inside it — because these pieces (repo → PURLs, and the
advisory store) are reusable beyond the `dependency-audit` matcher (a future SBOM or
provenance feature is the obvious second consumer). The matcher is one thin coordinator over
them. See the dynamic dependency-audit epic.
"""
from __future__ import annotations

from stayawake.bots.security.dependencies.purl import Purl, ResolvedDependency
from stayawake.bots.security.dependencies.store import Advisory, AdvisoryStore
from stayawake.bots.security.dependencies.resolvers import RESOLVERS, Resolver

__all__ = [
    "Purl", "ResolvedDependency",
    "Advisory", "AdvisoryStore",
    "Resolver", "RESOLVERS",
]
