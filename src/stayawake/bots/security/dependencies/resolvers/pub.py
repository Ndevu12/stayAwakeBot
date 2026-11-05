#!/usr/bin/env python3
"""Dart / Flutter (pub) resolver — pubspec.lock -> `pkg:pub/...` PURLs.

`pubspec.lock` locks each dependency under `packages:` with its resolved `version` and a `source`.
Only `source: hosted` packages come from a pub registry (pub.dev) and carry OSV `Pub` advisories;
`git`, `path` and `sdk` sources are not registry packages and are skipped. The lock is the audit
surface -- `pubspec.yaml` holds version ranges, not resolved versions.

Parsed line by line (bounded, no YAML alias expansion on an untrusted file) keyed on indentation:
a package is a two-space `name:`, its `source:` and `version:` are four-space fields; the deeper
`description:` block (six-space) is ignored. Malformed input yields no packages.
"""
from __future__ import annotations

import re
from typing import Iterator

from stayawake.bots.security.dependencies.purl import Purl, ResolvedDependency
from stayawake.bots.security.dependencies.resolvers.base import Resolver

_PKG = re.compile(r"^ {2}(?P<name>[A-Za-z0-9_][A-Za-z0-9_.-]*):[ \t]*$")
_FIELD = re.compile(r"^ {4}(?P<key>source|version):[ \t]+(?P<val>.+)$")


class PubResolver(Resolver):
    ecosystem = "pub"

    def resolve(self, target) -> Iterator[ResolvedDependency]:
        for rel in target.iter_files():
            if rel.rsplit("/", 1)[-1] == "pubspec.lock":
                for name, version in _pubspec_lock_deps(self._read_whole(target, rel)):
                    yield ResolvedDependency(Purl(self.ecosystem, name, version), rel)


def _pubspec_lock_deps(text) -> list[tuple[str, str]]:
    """(name, version) for each hosted (pub.dev) package in a pubspec.lock. Malformed -> []."""
    out: list[tuple[str, str]] = []
    name: str | None = None
    source: str | None = None
    version: str | None = None
    in_packages = False

    def flush() -> None:
        if name and source == "hosted" and version:
            out.append((name, version))

    for line in (text or "").splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        if not line[:1].isspace():                      # a top-level key (packages:, sdks:, ...)
            flush()
            name = source = version = None
            in_packages = line.strip() == "packages:"
            continue
        if not in_packages:
            continue
        pkg = _PKG.match(line)
        if pkg:
            flush()
            name, source, version = pkg.group("name"), None, None
            continue
        field = _FIELD.match(line)
        if field and name is not None:
            value = field.group("val").strip().strip('"')
            if field.group("key") == "source":
                source = value
            else:
                version = value
    flush()
    return out
