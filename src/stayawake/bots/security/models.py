#!/usr/bin/env python3
"""Typed model for the security scanner: Severity, Finding, ScanResult.

Kept dependency-free (stdlib only) so every other security module can import it
without pulling in heavier deps. One responsibility: describe scan output.
"""
from __future__ import annotations

from dataclasses import dataclass, field, asdict
from enum import IntEnum
from typing import Any

# Single source of truth for the quarantine directory name, shared by the
# remediation engine (writes backups), the remediator (commits), and the scanner
# (excludes it from scans). Keep these in sync via this constant only.
QUARANTINE_DIR = ".malware-quarantine"

# ── Finding confidence — orthogonal to severity (the verdict tier) ───────────────
# Only a `confirmed` finding — a signature specific enough to be decisive on its own
# (a known loader literal, the worm's exact tooling markers, an autorun harness) —
# drives an INFECTED verdict. A `heuristic` finding matches a SHAPE that benign code can
# also have (a packed/encoded blob, an oversized config line, a review-evading merge);
# it is surfaced as SUSPICIOUS so the user is informed, but never alone asserts
# "infected". This keeps the verdict honest: we only say malware when we are sure.
CONFIRMED = "confirmed"
HEURISTIC = "heuristic"
CONFIDENCE_LEVELS = (CONFIRMED, HEURISTIC)

# Repo verdict states (a graded replacement for the old infected/clean boolean).
CLEAN = "clean"
SUSPICIOUS = "suspicious"
INFECTED = "infected"

# ── Remediation manual-review reasons ────────────────────────────────────────────
# Why an auto-fix deferred a code-loader finding to a human instead of acting on it. Each
# maps to a specific recommended action in the remediator. Kept here (with the other domain
# constants) so producers and tests share one source of truth, not an inline literal.
BORN_INFECTED = "born-infected"             # no clean version in history AND content is packed
INTRINSIC_MATCH = "intrinsic-match"         # signature is part of committed content (likely test/research)
LEGIT_CHANGES = "legit-changes"             # clean version exists but payload isn't a separable append
UNTRACKED = "untracked"                     # file not tracked in git → no clean version to recover
NO_VCS = "no-vcs"                           # not a git repository
SUSPECT_HEURISTIC = "suspicious-heuristic"  # heuristic-only match (asset/minified shape) → review, never auto-recover
INSPECT_FAILED = "inspect-failed"           # git history could not be read (e.g. corrupt repo) → defer, never guess


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
    path: str                      # repo-relative path (or git ref for history findings)
    description: str
    remediation: str = "manual"
    line: int | None = None
    evidence: str | None = None
    vector: str | None = None      # e.g. "vscode-autorun", "evil-merge"
    confidence: str = CONFIRMED    # confirmed | heuristic — stamped by the scanner from the signature

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["severity"] = self.severity.label()
        return d


@dataclass
class ScanResult:
    """All findings for one target (one repository)."""

    target: str                    # display name (repo path or owner/repo)
    source: str                    # "local" | "remote"
    findings: list[Finding] = field(default_factory=list)
    error: str | None = None

    @property
    def verdict(self) -> str:
        """Three-state, confidence-graded repo verdict.

        INFECTED only when at least one CONFIRMED finding is present (a signature
        decisive on its own). Findings that are all HEURISTIC — a shape benign code can
        share — are SUSPICIOUS: surfaced for review, but never asserted as malware. This
        is the honest replacement for the old `bool(findings)`, which labelled a base64
        avatar or a crypto test vector "infected"."""
        if not self.findings:
            return CLEAN
        if any(f.confidence == CONFIRMED for f in self.findings):
            return INFECTED
        return SUSPICIOUS

    @property
    def infected(self) -> bool:
        """Back-compat boolean: True only for a CONFIRMED-driven INFECTED verdict, so
        every existing consumer (CI gate, alerter, reports) stops firing on heuristics."""
        return self.verdict == INFECTED

    @property
    def suspicious(self) -> bool:
        return self.verdict == SUSPICIOUS

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
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            "target": self.target,
            "source": self.source,
            "verdict": self.verdict,
            "infected": self.infected,
            "suspicious": self.suspicious,
            "error": self.error,
            "summary": self.summary(),
            "findings": [f.to_dict() for f in self.findings],
        }
