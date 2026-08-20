#!/usr/bin/env python3
"""Java / Maven resolver — Gradle lockfiles / pom.xml → `pkg:maven/…` PURLs."""
from __future__ import annotations

import re
from typing import Iterator

from stayawake.bots.security.dependencies.purl import Purl, ResolvedDependency
from stayawake.bots.security.dependencies.resolvers.base import Resolver

_DEP_BLOCK = re.compile(
    r"<dependency\b[^>]*>((?:(?!</dependency>)(?!<dependency\b)[\s\S])*)</dependency>", re.S | re.I)
_GRADLE_LINE = re.compile(r"^(?P<group>[^:\s#]+):(?P<artifact>[^:\s]+):(?P<version>[^=\s]+)(?:=|$)")
_GRADLE_LOCK_NAMES = ("gradle.lockfile", "buildscript-gradle.lockfile")


def _is_gradle_lock(rel: str, base: str) -> bool:
    return (base in _GRADLE_LOCK_NAMES
            or (base.endswith(".lockfile") and "gradle/dependency-locks/" in rel))


_TAG_RE = {t: re.compile(rf"<{t}\b[^>]*>([^<]*)</{t}>", re.I)
           for t in ("groupId", "artifactId", "version")}


def _tag(block: str, tag: str) -> str | None:
    m = _TAG_RE[tag].search(block)
    return (m.group(1).strip() or None) if m else None


def _is_literal_version(v: str) -> bool:
    """A concrete version — not a `${property}` and not a Maven range (`[1,2)`, `(,1]`, …)."""
    return bool(v) and "${" not in v and not any(c in v for c in "[](),")


class MavenResolver(Resolver):
    ecosystem = "maven"

    def resolve(self, target) -> Iterator[ResolvedDependency]:
        for rel in target.iter_files():
            base = rel.rsplit("/", 1)[-1]
            if _is_gradle_lock(rel, base):
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
