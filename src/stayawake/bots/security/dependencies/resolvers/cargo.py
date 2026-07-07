#!/usr/bin/env python3
"""Rust / Cargo resolver — Cargo.lock → `pkg:cargo/…` PURLs (#1123).

Cargo.lock is a TOML `[[package]]` array (same shape as poetry.lock / uv.lock), so it reuses the
shared `toml_packages` parser. Crate names and versions map 1:1 onto the OSV `crates.io` ecosystem.
"""
from __future__ import annotations

from typing import Iterator

from stayawake.bots.security.dependencies.purl import Purl, ResolvedDependency
from stayawake.bots.security.dependencies.resolvers.base import Resolver
from stayawake.bots.security.dependencies.resolvers._lockfiles import toml_packages


class CargoResolver(Resolver):
    ecosystem = "cargo"

    def resolve(self, target) -> Iterator[ResolvedDependency]:
        for rel in target.iter_files():
            if rel.rsplit("/", 1)[-1] == "Cargo.lock":
                for name, version in toml_packages(self._read_whole(target, rel)):
                    yield ResolvedDependency(Purl(self.ecosystem, name, version), rel)
