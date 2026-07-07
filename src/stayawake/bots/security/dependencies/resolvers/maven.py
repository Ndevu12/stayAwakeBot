#!/usr/bin/env python3
"""Java / Maven resolver — gradle.lockfile / pom.xml → `pkg:maven/…` PURLs (#1123).

`gradle.lockfile` lists fully-resolved `group:artifact:version=configs` lines — the authoritative
source. `pom.xml` declares `<dependency>` coordinates; only *literal* versions are taken (a
`${property}` or a Maven version range is unresolved → deferred). The OSV `Maven` ecosystem names a
package `groupId:artifactId`.

pom.xml is parsed by regex, NOT an XML parser: `saw` must never be DoS'd by a hostile scanned file,
and XML entity-expansion ("billion laughs") / XXE are exactly that risk. Regex extraction has no
such attack surface.
"""
from __future__ import annotations

import re
from typing import Iterator

from stayawake.bots.security.dependencies.purl import Purl, ResolvedDependency
from stayawake.bots.security.dependencies.resolvers.base import Resolver

_DEP_BLOCK = re.compile(r"<dependency\b[^>]*>(.*?)</dependency>", re.S | re.I)
_GRADLE_LINE = re.compile(r"^(?P<group>[^:\s#]+):(?P<artifact>[^:\s]+):(?P<version>[^=\s]+)=")


def _tag(block: str, tag: str) -> str | None:
    m = re.search(rf"<{tag}\b[^>]*>\s*([^<]+?)\s*</{tag}>", block, re.I)
    return m.group(1).strip() if m else None


def _is_literal_version(v: str) -> bool:
    """A concrete version — not a `${property}` and not a Maven range (`[1,2)`, `(,1]`, …)."""
    return bool(v) and "${" not in v and not any(c in v for c in "[](),")


class MavenResolver(Resolver):
    ecosystem = "maven"

    def resolve(self, target) -> Iterator[ResolvedDependency]:
        for rel in target.iter_files():
            base = rel.rsplit("/", 1)[-1]
            if base == "gradle.lockfile":
                deps = _gradle_lock_deps(self._read_whole(target, rel))
            elif base == "pom.xml":
                deps = _pom_deps(self._read_whole(target, rel))
            else:
                continue
            for name, version in deps:
                yield ResolvedDependency(Purl(self.ecosystem, name, version), rel)


def _gradle_lock_deps(text) -> list[tuple[str, str]]:
    out: list[tuple[str, str]] = []
    for line in (text or "").splitlines():
        m = _GRADLE_LINE.match(line.strip())
        if m:
            out.append((f"{m.group('group')}:{m.group('artifact')}", m.group("version")))
    return out


def _pom_deps(text) -> list[tuple[str, str]]:
    out: list[tuple[str, str]] = []
    for block in _DEP_BLOCK.findall(text or ""):
        group = _tag(block, "groupId")
        artifact = _tag(block, "artifactId")
        version = _tag(block, "version")
        if group and artifact and version and _is_literal_version(version):
            out.append((f"{group}:{artifact}", version))
    return out
