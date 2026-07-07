#!/usr/bin/env python3
"""PHP / Composer resolver — composer.lock → `pkg:composer/…` PURLs (#1123).

`composer.lock` is JSON with `packages` (+ `packages-dev`), each `{name: "vendor/pkg", version}`.
Composer sometimes prefixes tags with `v` (`v1.2.3`); the OSV `Packagist` ecosystem uses the bare
version, so a leading `v` is dropped.
"""
from __future__ import annotations

from typing import Iterator

from stayawake.bots.security.dependencies.purl import Purl, ResolvedDependency
from stayawake.bots.security.dependencies.resolvers.base import Resolver
from stayawake.bots.security.jsonc import load_jsonc


def _strip_v(version: str) -> str:
    return version[1:] if version[:1] == "v" and version[1:2].isdigit() else version


class ComposerResolver(Resolver):
    ecosystem = "composer"

    def resolve(self, target) -> Iterator[ResolvedDependency]:
        for rel in target.iter_files():
            if rel.rsplit("/", 1)[-1] == "composer.lock":
                for name, version in _composer_lock_deps(self._read_whole(target, rel)):
                    yield ResolvedDependency(Purl(self.ecosystem, name, version), rel)


def _composer_lock_deps(text) -> list[tuple[str, str]]:
    data = load_jsonc(text or "")
    if not isinstance(data, dict):
        return []
    out: list[tuple[str, str]] = []
    for section in ("packages", "packages-dev"):
        for pkg in (data.get(section) or []):
            if isinstance(pkg, dict):
                name, version = pkg.get("name"), pkg.get("version")
                if isinstance(name, str) and isinstance(version, str):
                    out.append((name, _strip_v(version)))
    return out
