#!/usr/bin/env python3
"""Advisory corpus — index normalized OSV records for lookup by package (#1120, #1124).

One responsibility: "given a `Purl`, is there an advisory affecting this exact version?" — matched
either by the advisory's explicit version list or by a version range (#1124). It knows nothing about
signatures, files, or verdicts — the store wraps a match into an `Advisory`, the matcher emits the
finding. Ecosystem comparison is canonicalized (OSV's `crates.io`/`PyPI` ↔ our `cargo`/`pypi`) so a
resolver's PURL keys the same slot as the advisory record.

Scale note: most malware advisories say "this package is malware at *every* version" (a lone
`introduced: "0"` range). There are hundreds of thousands of those, so they are kept in a compact
**whole-package** index (a light record per name, no version/range payload, O(1) lookup), separate
from the smaller set of version- or range-bounded records that need real evaluation. This keeps a
fully-populated corpus's memory modest even though the malware set is huge.
"""
from __future__ import annotations

from typing import Iterable

from stayawake.bots.security.dependencies.comparators import version_in_any_range
from stayawake.bots.security.dependencies.ecosystems import canonical_ecosystem as _eco
from stayawake.bots.security.dependencies.osv import OsvAffected, OsvRecord


def _covers_all_versions(aff: OsvAffected) -> bool:
    """True when this affected entry means "every version" — no explicit versions and a range that
    opens at `introduced: "0"` and never closes."""
    if aff.versions:
        return False
    for r in aff.ranges:
        kinds = [k for k, _ in r.events]
        if kinds == ["introduced"] and r.events[0][1] == "0":
            return True
    return False


class AdvisoryCorpus:
    """Package identity → the advisories affecting it, split into a whole-package fast path and a
    version/range-bounded list."""

    def __init__(self, whole: dict[tuple[str, str], list[OsvRecord]],
                 bounded: dict[tuple[str, str], list[tuple[OsvAffected, OsvRecord]]]):
        self._whole = whole        # (eco, name) → [light OsvRecord] — affects every version
        self._bounded = bounded    # (eco, name) → [(affected, record)] — needs version/range check

    @classmethod
    def from_records(cls, records: Iterable[OsvRecord]) -> "AdvisoryCorpus":
        whole: dict[tuple[str, str], list[OsvRecord]] = {}
        bounded: dict[tuple[str, str], list[tuple[OsvAffected, OsvRecord]]] = {}
        for rec in records:
            for aff in rec.affected:
                key = (_eco(aff.ecosystem), aff.name)
                if _covers_all_versions(aff):
                    # Drop the version/range payload — a whole-package hit needs only id/aliases/tier.
                    whole.setdefault(key, []).append(
                        OsvRecord(rec.id, rec.aliases, rec.malicious, ()))
                else:
                    bounded.setdefault(key, []).append((aff, rec))
        return cls(whole, bounded)

    def _bounded_hit(self, key, eco, version, want_malicious):
        for aff, rec in self._bounded.get(key, ()):
            if rec.malicious == want_malicious and (
                    version in aff.versions or version_in_any_range(version, aff.ranges, eco)):
                return rec
        return None

    def malicious_match(self, purl) -> OsvRecord | None:
        """The first MALWARE advisory affecting `purl.version` (drives the verdict → INFECTED)."""
        eco = _eco(purl.type)
        key = (eco, purl.name)
        for rec in self._whole.get(key, ()):
            if rec.malicious:
                return rec
        return self._bounded_hit(key, eco, purl.version, want_malicious=True)

    def vulnerability_matches(self, purl) -> list[OsvRecord]:
        """All NON-malware advisories (ordinary CVEs) affecting `purl.version` — the opt-in advisory
        tier, which never moves the worm verdict."""
        eco = _eco(purl.type)
        key = (eco, purl.name)
        out = [rec for rec in self._whole.get(key, ()) if not rec.malicious]
        for aff, rec in self._bounded.get(key, ()):
            if not rec.malicious and (
                    purl.version in aff.versions or version_in_any_range(purl.version, aff.ranges, eco)):
                out.append(rec)
        return out

    def is_empty(self) -> bool:
        return not self._whole and not self._bounded
