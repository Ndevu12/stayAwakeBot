#!/usr/bin/env python3
"""Go modules resolver — go.sum / go.mod → `pkg:golang/…` PURLs (#1123).

`go.sum` is the authoritative resolved set (every module@version, two lines each — one for the
zip, one for `/go.mod`); `go.mod` `require` directives are also exact pins and cover repos that
commit only `go.mod`. Module paths are the OSV `Go` package name; versions are normalized to the
OSV form — the leading `v` dropped (`v1.2.3` → `1.2.3`), the `/go.mod` suffix stripped. Duplicate
(module, version) pairs are harmless — the matcher de-dups per file.
"""
from __future__ import annotations

import re
from typing import Iterator

from stayawake.bots.security.dependencies.purl import Purl, ResolvedDependency
from stayawake.bots.security.dependencies.resolvers.base import Resolver

_GOMOD_REQUIRE = re.compile(r"^(?P<module>[^\s]+)\s+(?P<version>v[^\s/]+)")


def _norm_version(v: str) -> str:
    v = v.split("/", 1)[0]                       # drop a `/go.mod` suffix (go.sum)
    return v[1:] if v[:1] == "v" and v[1:2].isdigit() else v   # `v1.2.3` → `1.2.3`


class GoResolver(Resolver):
    ecosystem = "golang"

    def resolve(self, target) -> Iterator[ResolvedDependency]:
        for rel in target.iter_files():
            base = rel.rsplit("/", 1)[-1]
            if base == "go.sum":
                deps = _go_sum_deps(self._read_whole(target, rel))
            elif base == "go.mod":
                deps = _go_mod_deps(self._read_whole(target, rel))
            else:
                continue
            for name, version in deps:
                yield ResolvedDependency(Purl(self.ecosystem, name, version), rel)


def _go_sum_deps(text) -> list[tuple[str, str]]:
    out: list[tuple[str, str]] = []
    for line in (text or "").splitlines():
        parts = line.split()
        if len(parts) >= 2 and parts[1].startswith("v"):
            out.append((parts[0], _norm_version(parts[1])))
    return out


def _go_mod_deps(text) -> list[tuple[str, str]]:
    out: list[tuple[str, str]] = []
    in_block = False
    for raw in (text or "").splitlines():
        line = raw.split("//", 1)[0].strip()        # drop `// indirect` comments
        if not line:
            continue
        if line.startswith("require (") or line == "require (":
            in_block = True
            continue
        if in_block:
            if line == ")":
                in_block = False
                continue
            m = _GOMOD_REQUIRE.match(line)
        else:
            m = _GOMOD_REQUIRE.match(line[8:].strip()) if line.startswith("require ") else None
        if m:
            out.append((m.group("module"), _norm_version(m.group("version"))))
    return out
