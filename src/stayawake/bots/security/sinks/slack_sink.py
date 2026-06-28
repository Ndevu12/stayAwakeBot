#!/usr/bin/env python3
"""SlackSink — post a Slack summary for infected / suspicious repos.

A durable, push-style record outside the tree. Slack bodies are evidence-free, so nothing
to redact. No-ops silently when SLACK_WEBHOOK_URL is unset.
"""
from __future__ import annotations

from stayawake.bots.security import alerter
from stayawake.bots.security.models import ScanReport
from stayawake.bots.security.sinks.base import Sink


class SlackSink(Sink):
    def emit(self, report: ScanReport) -> None:
        alerter.post_slack_summary(report.to_payload())
