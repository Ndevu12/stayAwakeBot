#!/usr/bin/env python3
"""Typed model for the security scanner: Severity, Finding, ScanResult.

Kept dependency-free (stdlib only) so every other security module can import it
without pulling in heavier deps. One responsibility: describe scan output.
"""
from __future__ import annotations

from dataclasses import dataclass, field, asdict
from enum import IntEnum
from typing import Any

QUARANTINE_DIR = ".malware-quarantine"

CONFIRMED = "confirmed"
HEURISTIC = "heuristic"
RESIDUE = "residue"
CONFIDENCE_LEVELS = (CONFIRMED, HEURISTIC, RESIDUE)

CLEAN = "clean"
RESIDUE_VERDICT = "residue"
SUSPICIOUS = "suspicious"
INFECTED = "infected"

BORN_INFECTED = "born-infected"
INTRINSIC_MATCH = "intrinsic-match"
LEGIT_CHANGES = "legit-changes"
UNTRACKED = "untracked"
NO_VCS = "no-vcs"
SUSPECT_HEURISTIC = "suspicious-heuristic"
INSPECT_FAILED = "inspect-failed"
MERGE_CLEAN_RECOVERED = "merge-clean-recovered"
                                            # version is available → offered as a REVIEW-required
                                            # Suggested (second-parent-derived, never auto-applied)


class Severity(IntEnum):
    """Ordered so thresholds can compare numerically (CRITICAL is highest)."""

    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @classmethod
    def parse(cls, value: str) -> "Severity":
        try:
            return cls[str(value).strip().upper()]
        except KeyError:
            return cls.MEDIUM

    def label(self) -> str:
        return self.name.lower()


@dataclass
class Finding:
    """A single detection. `evidence` is a short, redaction-safe snippet."""

    signature_id: str
    category: str
    severity: Severity
    path: str
    description: str
    remediation: str = "manual"
    line: int | None = None
    evidence: str | None = None
    vector: str | None = None
    confidence: str = CONFIRMED
    related_paths: tuple[str, ...] = ()
    commit_sha: str | None = None
    # Did saw compose this sentence, or is it bytes from the scanned file? Default False so the
    # report fingerprints unless told otherwise: an opt-in flag was one forgotten call from a leak.
    composed_evidence: bool = False
    advisory_only: bool = False
    fix_advice: str | None = None
    fixed_version: str | None = None
    reference: str | None = None

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["severity"] = self.severity.label()
        return d


@dataclass
class ScanResult:
    """All findings for one target (one repository)."""

    target: str
    source: str
    findings: list[Finding] = field(default_factory=list)
    error: str | None = None
    advisories: list[Finding] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    @property
    def verdict(self) -> str:
        """Four-state, confidence-graded repo verdict.

        INFECTED only when at least one CONFIRMED finding is present (a signature
        decisive on its own). Findings that are all HEURISTIC — a shape benign code can
        share — are SUSPICIOUS: surfaced for review, but never asserted as malware. This
        is the honest replacement for the old `bool(findings)`, which labelled a base64
        avatar or a crypto test vector "infected".

        RESIDUE is the state neither of those could express: nothing here executes, and the
        tree is not what the project would carry. Calling it clean hides that someone has
        already been inside it; calling it infected starts an incident the evidence does not
        support. It is the weakest state, so it can never mask one of the others."""
        if not self.findings:
            return CLEAN
        if any(f.confidence == CONFIRMED for f in self.findings):
            return INFECTED
        if any(f.confidence == HEURISTIC for f in self.findings):
            return SUSPICIOUS
        return RESIDUE_VERDICT

    @property
    def infected(self) -> bool:
        """Back-compat boolean: True only for a CONFIRMED-driven INFECTED verdict, so
        every existing consumer (CI gate, alerter, reports) stops firing on heuristics."""
        return self.verdict == INFECTED

    @property
    def suspicious(self) -> bool:
        return self.verdict == SUSPICIOUS

    @property
    def residue(self) -> bool:
        return self.verdict == RESIDUE_VERDICT

    @property
    def max_severity(self) -> Severity | None:
        return max((f.severity for f in self.findings), default=None)

    def summary(self) -> dict[str, Any]:
        by_sev: dict[str, int] = {}
        by_cat: dict[str, int] = {}
        by_conf: dict[str, int] = {}
        for f in self.findings:
            by_sev[f.severity.label()] = by_sev.get(f.severity.label(), 0) + 1
            by_cat[f.category] = by_cat.get(f.category, 0) + 1
            by_conf[f.confidence] = by_conf.get(f.confidence, 0) + 1
        return {
            "total": len(self.findings),
            "by_severity": by_sev,
            "by_category": by_cat,
            "by_confidence": by_conf,
            "max_severity": self.max_severity.label() if self.max_severity else None,
            "advisories": len(self.advisories),
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            "target": self.target,
            "source": self.source,
            "verdict": self.verdict,
            "infected": self.infected,
            "suspicious": self.suspicious,
            "residue": self.residue,
            "error": self.error,
            "summary": self.summary(),
            "findings": [f.to_dict() for f in self.findings],
            "advisories": [a.to_dict() for a in self.advisories],
            "notes": list(self.notes),
        }


@dataclass
class ScanReport:
    """A whole scan run: all per-target results plus the run timestamp.

    The single in-memory object the scanner hands to its output sinks. `to_payload()` is
    the one serialization point every sink shares (terminal, json, sarif, file, alert), so
    they can never disagree on the shape — and the scanner itself performs no output I/O.
    """

    generated_at: str
    results: list[ScanResult] = field(default_factory=list)

    @property
    def any_infected(self) -> bool:
        return any(r.infected for r in self.results)

    @property
    def any_suspicious(self) -> bool:
        return any(r.suspicious for r in self.results)

    @property
    def any_residue(self) -> bool:
        return any(r.residue for r in self.results)

    @property
    def any_error(self) -> bool:
        """True if any target could not be scanned (an unreadable/malformed config, a read
        failure, a failed clone). Such a target carries NO verdict — the gate must fail closed
        on it rather than read the absence of findings as 'clean'."""
        return any(r.error for r in self.results)

    def to_payload(self) -> dict[str, Any]:
        """The canonical scan payload dict consumed by every sink."""
        results = self.results
        return {
            "generated_at": self.generated_at,
            "summary": {
                "targets": len(results),
                "infected": sum(1 for r in results if r.infected),
                "suspicious": sum(1 for r in results if r.suspicious),
                "residue": sum(1 for r in results if r.residue),
                "findings": sum(len(r.findings) for r in results),
                "critical": sum(1 for r in results for f in r.findings
                                if f.severity.label() == "critical"),
                "high": sum(1 for r in results for f in r.findings
                            if f.severity.label() == "high"),
                "advisories": sum(len(r.advisories) for r in results),
            },
            "any_infected": self.any_infected,
            "any_suspicious": self.any_suspicious,
            "any_residue": self.any_residue,
            "any_error": self.any_error,
            "results": [r.to_dict() for r in results],
        }
