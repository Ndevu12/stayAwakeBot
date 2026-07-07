#!/usr/bin/env python3
"""Advisory corpus — index normalized OSV records for lookup by package (#1120).

One responsibility: "given a `Purl`, is there an advisory whose explicit affected-version list
contains this exact version?" It knows nothing about signatures, files, or verdicts — the store
wraps a match into an `Advisory`, the matcher emits the finding. Ecosystem comparison is
case-insensitive (OSV writes `PyPI`, our PURLs write `pypi`) and drops any OSV suffix
(`Debian:11` → `debian`) so a bare ecosystem token still keys correctly.
"""
from __future__ import annotations

from typing import Iterable

from stayawake.bots.security.dependencies.osv import OsvRecord


def _eco(ecosystem: str) -> str:
    return ecosystem.lower().split(":", 1)[0]


class AdvisoryCorpus:
    """Package identity → the OSV records (with explicit versions) that name it."""

    def __init__(self, by_package: dict[tuple[str, str], list[tuple[frozenset[str], OsvRecord]]]):
        self._by_package = by_package

    @classmethod
    def from_records(cls, records: Iterable[OsvRecord]) -> "AdvisoryCorpus":
        by_package: dict[tuple[str, str], list[tuple[frozenset[str], OsvRecord]]] = {}
        for rec in records:
            for aff in rec.affected:
                by_package.setdefault((_eco(aff.ecosystem), aff.name), []).append((aff.versions, rec))
        return cls(by_package)

    def match(self, purl) -> OsvRecord | None:
        """The advisory whose explicit version set contains `purl.version`, or None."""
        for versions, rec in self._by_package.get((_eco(purl.type), purl.name), ()):
            if purl.version in versions:
                return rec
        return None

    def is_empty(self) -> bool:
        return not self._by_package
