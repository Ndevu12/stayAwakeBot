#!/usr/bin/env python3
"""IssueSink — open/close one idempotent GitHub issue per infected repo.

A durable record that lives OUTSIDE the scanned tree (so an attacker with write access to
the repo can't tamper with it). Issue bodies are evidence-free by construction, so no
redaction is needed. No-ops with a friendly note when no GITHUB_TOKEN/REPOSITORY is set.
"""
from __future__ import annotations

from stayawake.bots.security import alerter
from stayawake.bots.security.models import ScanReport
from stayawake.bots.security.sinks.base import Sink


class IssueSink(Sink):
    def emit(self, report: ScanReport) -> None:
        alerter.sync_github_issues(report.to_payload())
