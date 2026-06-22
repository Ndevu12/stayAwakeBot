#!/usr/bin/env python3
"""Typed model for the security scanner: Severity, Finding, ScanResult.

Kept dependency-free (stdlib only) so every other security module can import it
without pulling in heavier deps. One responsibility: describe scan output.
"""
from __future__ import annotations

from dataclasses import dataclass, field, asdict
from enum import IntEnum
from typing import Any


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
    def infected(self) -> bool:
        return bool(self.findings)

    @property
    def max_severity(self) -> Severity | None:
        return max((f.severity for f in self.findings), default=None)

    def summary(self) -> dict[str, Any]:
        by_sev: dict[str, int] = {}
        by_cat: dict[str, int] = {}
        for f in self.findings:
            by_sev[f.severity.label()] = by_sev.get(f.severity.label(), 0) + 1
            by_cat[f.category] = by_cat.get(f.category, 0) + 1
        return {
            "total": len(self.findings),
            "by_severity": by_sev,
            "by_category": by_cat,
            "max_severity": self.max_severity.label() if self.max_severity else None,
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            "target": self.target,
            "source": self.source,
            "infected": self.infected,
            "error": self.error,
            "summary": self.summary(),
            "findings": [f.to_dict() for f in self.findings],
        }
