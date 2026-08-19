#!/usr/bin/env python3
"""Obfuscation analysis for a chunk of source, or a delta of one.

`entry` is the public surface; `execsink` and `heuristics` are its parts.
"""
from __future__ import annotations

from stayawake.bots.security.obfuscation.entry import (
    analyze_file, analyze_delta, ObfuscationVerdict)
from stayawake.bots.security.obfuscation.heuristics import is_generated_context

__all__ = ["analyze_file", "analyze_delta", "ObfuscationVerdict", "is_generated_context"]
