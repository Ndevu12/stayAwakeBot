#!/usr/bin/env python3
"""Advisory store — maps a resolved package to the advisory that flags it (#1119).

One responsibility: "given a package, is it known-bad, and why?" The store knows nothing
about repos or lockfile formats — resolvers hand it `Purl`s, it answers. The matcher
depends on this type, not on where the data lives (dependency inversion), so a test can
build an in-memory store directly and future phases can swap the backing source without
touching the matcher.

Phase 1a is backed **only** by the inline `known_bad` seed shipped in signatures.yml —
always in the wheel, so detection needs zero setup and zero network. Phase 1b (#1120) adds
the offline OSV corpus (OpenSSF / GitHub Advisories / OSV.dev) behind this same interface,
with the inline seed remaining as an always-ships supplement.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from stayawake.bots.security.dependencies.purl import Purl


@dataclass(frozen=True)
class Advisory:
    """Why a package is flagged.

    Phase 1a wraps the owning signature (the source of the finding's id/category/severity).
    Phase 1b will carry OSV metadata (advisory id, aliases, source feed) on this same type.
    """

    signature: dict[str, Any]


class AdvisoryStore:
    """Package coordinate → `Advisory`. Built from the data, queried by the matcher."""

    def __init__(self, by_coordinate: dict[str, Advisory]):
        self._by_coordinate = by_coordinate

    @classmethod
    def from_signatures(cls, signatures: list[dict[str, Any]]) -> "AdvisoryStore":
        """Build the store from the `dependency-audit` signatures' inline `known_bad` lists.

        An entry must carry a version separator (an ``@`` past any leading scope), so a
        malformed bare-name entry can't silently match every version of a package.
        """
        by_coordinate: dict[str, Advisory] = {}
        for sig in signatures:
            for entry in sig.get("known_bad", []) or []:
                if isinstance(entry, str) and entry.strip().rfind("@") > 0:
                    by_coordinate[entry.strip()] = Advisory(signature=sig)
        return cls(by_coordinate)

    def advisory_for(self, purl: Purl) -> Advisory | None:
        """The advisory flagging this package, or None if it is not known-bad.

        Phase 1a keys on the ecosystem-agnostic ``name@version`` coordinate (the inline
        seed carries no ecosystem prefix); phase 1b will key on the full PURL.
        """
        return self._by_coordinate.get(purl.coordinate)

    def is_empty(self) -> bool:
        """True when there is nothing to match against — the matcher then short-circuits."""
        return not self._by_coordinate
