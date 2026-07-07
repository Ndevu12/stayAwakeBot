#!/usr/bin/env python3
"""Ruby / RubyGems resolver — Gemfile.lock → `pkg:gem/…` PURLs (#1123).

In `Gemfile.lock`, resolved gems are the 4-space-indented `name (version)` lines under `specs:`;
the 6-space lines beneath them are dependency *constraints* (ranges) and are skipped. A platform
suffix on a locked version (`nokogiri (1.13.6-x86_64-linux)`) is stripped to the gem version
(`1.13.6`) to match the OSV `RubyGems` ecosystem (gem versions never contain `-`, so the split is
unambiguous).
"""
from __future__ import annotations

import re
from typing import Iterator

from stayawake.bots.security.dependencies.purl import Purl, ResolvedDependency
from stayawake.bots.security.dependencies.resolvers.base import Resolver

# Exactly four leading spaces, `name (version)`, version starting with a digit → a resolved gem.
_SPEC = re.compile(r"^ {4}(?P<name>[A-Za-z0-9._-]+) \((?P<version>[0-9][^)]*)\)$")


class RubyGemsResolver(Resolver):
    ecosystem = "gem"

    def resolve(self, target) -> Iterator[ResolvedDependency]:
        for rel in target.iter_files():
            if rel.rsplit("/", 1)[-1] == "Gemfile.lock":
                for name, version in _gemfile_lock_deps(self._read_whole(target, rel)):
                    yield ResolvedDependency(Purl(self.ecosystem, name, version), rel)


def _gemfile_lock_deps(text) -> list[tuple[str, str]]:
    out: list[tuple[str, str]] = []
    for line in (text or "").splitlines():
        m = _SPEC.match(line)
        if m:
            out.append((m.group("name"), m.group("version").split("-", 1)[0]))  # drop platform
    return out
