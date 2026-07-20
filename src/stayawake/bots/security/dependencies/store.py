#!/usr/bin/env python3
"""Advisory store — maps a resolved package to the advisory that flags it (#1119, #1120).

One responsibility: "given a package, is it known-bad, and why?" The store knows nothing about
repos or lockfile formats — resolvers hand it `Purl`s, it answers. The matcher depends on this
type, not on where the data lives (dependency inversion), so a test can build an in-memory store
directly and future phases can swap the backing source without touching the matcher.

Two backing sources, checked in order:
  1. the inline `known_bad` seed shipped in signatures.yml — always in the wheel, so detection
     needs zero setup and zero network; and
  2. the offline malicious-package **corpus** (`db.load_corpus`), populated by `saw db update`
     from OpenSSF / GitHub Advisories / OSV.dev — a *superset* of the seed, never a prerequisite.
No cache → corpus is None → behaviour is identical to the seed-only path (#1119).
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from stayawake.bots.security.dependencies.purl import Purl


@dataclass(frozen=True)
class Advisory:
    """Why a package is flagged.

    `signature` is the source of the finding's id/category/severity (the `malicious-dependency`
    signature, whether the hit came from the inline seed or the corpus). `osv_id`/`aliases` carry
    the advisory identity for corpus hits so the finding can cite it (e.g. `MAL-2024-1234`).
    `fixed_version` is the first patched version to upgrade to (the remediation target, #1252), or
    None when the advisory names no fix (whole-package/explicit-version/open-ended, or malware —
    which is removed, not upgraded).
    """

    signature: dict[str, Any]
    osv_id: str | None = None
    aliases: tuple[str, ...] = field(default_factory=tuple)
    fixed_version: str | None = None


_CORPUS_UNSET = object()   # sentinel: "corpus not built yet" (distinct from a built-but-absent None)


class AdvisoryStore:
    """Package `Purl` → `Advisory`. Built from the data, queried by the matcher.

    The corpus is loaded LAZILY: building it is ~10s / hundreds of MB, and a scan of a repo with no
    dependency files never resolves a package — so `advisory_for`/`vulnerabilities_for` are never
    called and the corpus is never built (#1163). `is_empty()` short-circuits on the inline seed and
    does not trigger the load unless the seed is empty. A pre-built `corpus` (tests) is used as-is.
    """

    def __init__(self, by_coordinate: dict[str, Advisory], corpus=None,
                 corpus_signature: dict[str, Any] | None = None,
                 vulnerability_signature: dict[str, Any] | None = None,
                 corpus_loader=None):
        self._by_coordinate = by_coordinate
        self._corpus_signature = corpus_signature   # stamps MALWARE (verdict) corpus hits
        self._vulnerability_signature = vulnerability_signature   # stamps CVE (advisory) hits
        # A loader defers the expensive build to first query; a directly-passed corpus is already built.
        self._corpus_loader = corpus_loader
        self._corpus = _CORPUS_UNSET if corpus_loader is not None else corpus   # AdvisoryCorpus | None

    def _corpus_or_load(self):
        """The corpus, built on first access (once) — or None when there is no corpus tier."""
        if self._corpus is _CORPUS_UNSET:
            self._corpus = self._corpus_loader() if self._corpus_loader is not None else None
        return self._corpus

    @classmethod
    def from_signatures(cls, signatures: list[dict[str, Any]]) -> "AdvisoryStore":
        """Inline-seed-only store (no corpus) — the #1119 constructor, unchanged."""
        return cls(cls._inline_index(signatures))

    @classmethod
    def default(cls, signatures: list[dict[str, Any]], cache_dir=None) -> "AdvisoryStore":
        """The scan-time store: inline seed **plus** the offline corpus, if a cache exists.

        Malware hits are stamped with the signature that opts in via `corpus: true` (the
        `malicious-dependency` id → same verdict/allowlist as the seed); CVE hits are stamped with
        the `advisory_corpus: true` signature (`vulnerable-dependency`). No opted-in signature, or
        no cache → that tier is disabled; with neither, this is exactly `from_signatures`.
        """
        # Local import: db imports this package's siblings; importing it here (not at module load)
        # keeps the dependencies package's import graph acyclic.
        from stayawake.bots.security.dependencies import db
        corpus_sig = next((s for s in signatures if s.get("corpus")), None)
        vuln_sig = next((s for s in signatures if s.get("advisory_corpus")), None)
        # Pass a LOADER, not a loaded corpus: db.load_corpus (~10s) runs only if a package is actually
        # queried (a repo with no lockfile/manifest never gets here → the load is skipped, #1163). The
        # loader is memoized in db, so a repo WITH dependencies still builds it at most once.
        loader = (lambda: db.load_corpus(cache_dir)) if (corpus_sig or vuln_sig) else None
        return cls(cls._inline_index(signatures), corpus_signature=corpus_sig,
                   vulnerability_signature=vuln_sig, corpus_loader=loader)

    @staticmethod
    def _inline_index(signatures: list[dict[str, Any]]) -> dict[str, Advisory]:
        """`name@version` → Advisory from every signature's inline `known_bad` list. An entry must
        carry a version separator (`@` past any leading scope) so a bare-name entry can't match
        every version of a package."""
        by_coordinate: dict[str, Advisory] = {}
        for sig in signatures:
            for entry in sig.get("known_bad", []) or []:
                if isinstance(entry, str) and entry.strip().rfind("@") > 0:
                    by_coordinate[entry.strip()] = Advisory(signature=sig)
        return by_coordinate

    def advisory_for(self, purl: Purl) -> Advisory | None:
        """The MALWARE advisory flagging this package (inline seed first, then corpus), or None.
        This is the verdict-driving tier (→ INFECTED)."""
        advisory = self._by_coordinate.get(purl.coordinate)
        if advisory is not None:
            return advisory                          # inline-seed hit → no corpus load needed
        if self._corpus_signature is not None:
            corpus = self._corpus_or_load()
            if corpus is not None:
                rec = corpus.malicious_match(purl)
                if rec is not None:
                    return Advisory(signature=self._corpus_signature,
                                    osv_id=rec.id, aliases=rec.aliases)
        return None

    def vulnerabilities_for(self, purl: Purl) -> list[Advisory]:
        """Non-malware advisories (CVEs) affecting this package — the opt-in advisory tier that
        never moves the verdict. Empty unless a `vulnerable-dependency` signature and a corpus
        are both present."""
        if self._vulnerability_signature is None:
            return []
        corpus = self._corpus_or_load()
        if corpus is None:
            return []
        return [Advisory(signature=self._vulnerability_signature, osv_id=m.record.id,
                         aliases=m.record.aliases, fixed_version=m.fixed)
                for m in corpus.vulnerability_matches(purl)]

    def is_empty(self) -> bool:
        """True when there is nothing to match against — the matcher then short-circuits. The `and`
        short-circuits on a non-empty inline seed, so this does NOT trigger the corpus load in the
        common case (a seed is always shipped)."""
        return (not self._by_coordinate
                and (self._corpus_or_load() is None or self._corpus_or_load().is_empty()))
