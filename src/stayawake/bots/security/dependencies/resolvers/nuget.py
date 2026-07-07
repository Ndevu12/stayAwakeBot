#!/usr/bin/env python3
"""NuGet / .NET resolver — packages.lock.json → `pkg:nuget/…` PURLs (#1123).

`packages.lock.json` maps each target framework to its packages; the `resolved` field is the exact
locked version. Package ids and versions map onto the OSV `NuGet` ecosystem. (NuGet ids are
case-insensitive; we keep the lockfile's casing — a case mismatch vs. an advisory's canonical id is
a documented residual.)
"""
from __future__ import annotations

from typing import Iterator

from stayawake.bots.security.dependencies.purl import Purl, ResolvedDependency
from stayawake.bots.security.dependencies.resolvers.base import Resolver
from stayawake.bots.security.jsonc import load_jsonc


class NuGetResolver(Resolver):
    ecosystem = "nuget"

    def resolve(self, target) -> Iterator[ResolvedDependency]:
        for rel in target.iter_files():
            if rel.rsplit("/", 1)[-1] == "packages.lock.json":
                for name, version in _nuget_lock_deps(self._read_whole(target, rel)):
                    yield ResolvedDependency(Purl(self.ecosystem, name, version), rel)


def _nuget_lock_deps(text) -> list[tuple[str, str]]:
    data = load_jsonc(text or "")
    if not isinstance(data, dict):
        return []
    out: list[tuple[str, str]] = []
    frameworks = data.get("dependencies")
    if isinstance(frameworks, dict):
        for pkgs in frameworks.values():
            if isinstance(pkgs, dict):
                for name, meta in pkgs.items():
                    if isinstance(name, str) and isinstance(meta, dict):
                        version = meta.get("resolved")
                        if isinstance(version, str):
                            out.append((name, version))
    return out
