#!/usr/bin/env python3
"""Output sinks (Strategy): where a ScanReport goes. One technique per module."""
from __future__ import annotations

from stayawake.bots.security.sinks.base import Sink
from stayawake.bots.security.sinks.file_sink import FileSink
from stayawake.bots.security.sinks.issue_sink import IssueSink
from stayawake.bots.security.sinks.json_sink import JsonSink
from stayawake.bots.security.sinks.sarif_sink import SarifSink
from stayawake.bots.security.sinks.slack_sink import SlackSink
from stayawake.bots.security.sinks.terminal import TerminalSink

__all__ = ["Sink", "TerminalSink", "JsonSink", "SarifSink", "FileSink",
           "IssueSink", "SlackSink"]
