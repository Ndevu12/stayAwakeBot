#!/usr/bin/env python3
"""Filename/path-glob matcher."""
from __future__ import annotations

from fnmatch import fnmatch

from stayawakebot.security.models import Finding, Severity
from stayawakebot.security.matchers.base import Matcher


class FilenameMatcher(Matcher):
    handles = "filename"

    def scan(self, target, signatures):
        findings: list[Finding] = []
        for rel in target.iter_files():
            base = rel.rsplit("/", 1)[-1]
            for s in signatures:
                pat = s.get("pattern", "")
                if base == pat or fnmatch(base, pat) or fnmatch(rel, pat):
                    findings.append(Finding(
                        signature_id=s["id"], category=s["category"],
                        severity=Severity.parse(s["severity"]), path=rel,
                        description=s["description"], remediation=s.get("remediation", "manual"),
                        vector=s["category"]))
        return findings
