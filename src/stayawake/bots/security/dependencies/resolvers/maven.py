#!/usr/bin/env python3
"""Java / Maven resolver — Gradle lockfiles / pom.xml → `pkg:maven/…` PURLs (#1123).

Fully-resolved Gradle locks are the authoritative source, across all three formats:
  * `gradle.lockfile` and `buildscript-gradle.lockfile` (Gradle ≥ 6.8): `group:artifact:version=configs`
  * legacy `gradle/dependency-locks/<config>.lockfile` (Gradle 4.8–6.7): bare `group:artifact:version`
`pom.xml` declares `<dependency>` coordinates; only *literal* versions are taken (a `${property}`,
a `<dependencyManagement>`/BOM-managed version, or a Maven range is unresolved → deferred). The OSV
`Maven` ecosystem names a package `groupId:artifactId`.

pom.xml is parsed by regex, NOT an XML parser: `saw` must never be DoS'd by a hostile scanned file,
and XML entity-expansion ("billion laughs") / XXE are exactly that risk. The extraction regex must
itself be ReDoS-safe — the block body is a TEMPERED run (non-`</dependency>` chars that also don't
start a NEW `<dependency`), so an opener with no closer can't scan to end-of-file at every opener
(a plain `(.*?)` did → O(n^2) on `<dependency>`-spam, #1158). `<dependency>` blocks never nest, so
the tempering is detection-identical.
"""
from __future__ import annotations

import re
from typing import Iterator

from stayawake.bots.security.dependencies.purl import Purl, ResolvedDependency
from stayawake.bots.security.dependencies.resolvers.base import Resolver

_DEP_BLOCK = re.compile(
    r"<dependency\b[^>]*>((?:(?!</dependency>)(?!<dependency\b)[\s\S])*)</dependency>", re.S | re.I)
# `group:artifact:version`, with the version terminated by `=configs` (new format) OR end-of-line
# (legacy per-configuration format). Comment/`empty=` lines don't start with a coordinate → skipped.
_GRADLE_LINE = re.compile(r"^(?P<group>[^:\s#]+):(?P<artifact>[^:\s]+):(?P<version>[^=\s]+)(?:=|$)")
_GRADLE_LOCK_NAMES = ("gradle.lockfile", "buildscript-gradle.lockfile")


def _is_gradle_lock(rel: str, base: str) -> bool:
    return (base in _GRADLE_LOCK_NAMES
            or (base.endswith(".lockfile") and "gradle/dependency-locks/" in rel))


# Per-tag body extractors, PRECOMPILED at module level (not built per call) — both so the ReDoS guard
# enumerates them and so the body is unambiguous: `([^<]*)` is greedy with no overlapping `\s*` wrappers.
# The old `>\s*([^<]+?)\s*<` had THREE whitespace-capable quantifiers around the body → ~O(n^3)
# catastrophic backtracking on a whitespace-filled tag with no closer (a ~2 KB pom.xml hung the scan,
# #1158). `[^<]` never matches `<`, so the greedy body can't backtrack across it — linear. Python
# `.strip()` reproduces the trimming the wrapping `\s*` used to do.
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
