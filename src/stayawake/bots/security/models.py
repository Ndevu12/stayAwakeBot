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
    remediation: str = "manual"    # the machine STRATEGY keyword that drives `saw fix`
                                   # (recover/quarantine-*/manual…) — NOT user-facing prose
    line: int | None = None
    evidence: str | None = None
    vector: str | None = None      # e.g. "vscode-autorun", "evil-merge"
    confidence: str = CONFIRMED    # confirmed | heuristic — stamped by the scanner from the signature
    advisory_only: bool = False    # informational (e.g. a dependency CVE) — the scanner routes these
                                   # OUT of the worm verdict into ScanResult.advisories; a repo with
                                   # only advisory_only findings stays CLEAN (reported, never gated).
    # Actionable remediation for the reader (#1252) — populated for dependency findings; the render
    # prints a "→ fix" / "→ details" line when present. `fix_advice` is the human sentence (incl. an
    # upgrade command), `fixed_version` the structured upgrade target, `reference` the advisory URL.
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

    target: str                    # display name (repo path or owner/repo)
    source: str                    # "local" | "remote"
    findings: list[Finding] = field(default_factory=list)
    error: str | None = None
    # Advisory-tier results (dependency CVEs, opt-in) — deliberately NOT part of `findings`, so the
    # verdict below can never see them. Reported in their own section; they never gate a scan.
    advisories: list[Finding] = field(default_factory=list)

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
            "advisories": len(self.advisories),
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
            "advisories": [a.to_dict() for a in self.advisories],
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
                "findings": sum(len(r.findings) for r in results),
                "critical": sum(1 for r in results for f in r.findings
                                if f.severity.label() == "critical"),
                "high": sum(1 for r in results for f in r.findings
                            if f.severity.label() == "high"),
                "advisories": sum(len(r.advisories) for r in results),
            },
            "any_infected": self.any_infected,
            "any_suspicious": self.any_suspicious,
            "any_error": self.any_error,
            "results": [r.to_dict() for r in results],
        }
