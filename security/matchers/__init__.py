#!/usr/bin/env python3
"""Matcher registry — maps a signature's `matcher` value to its strategy.

Adding a detection technique = add a module here and register its class.
"""
from __future__ import annotations

from security.matchers.base import Matcher
from security.matchers.content import ContentMatcher
from security.matchers.filename import FilenameMatcher
from security.matchers.structural import StructuralJsonMatcher
from security.matchers.heuristic import HeuristicMatcher
from security.matchers.git_history import GitHistoryMatcher

REGISTRY: dict[str, Matcher] = {
    m.handles: m for m in (
        ContentMatcher(), FilenameMatcher(), StructuralJsonMatcher(),
        HeuristicMatcher(), GitHistoryMatcher(),
    )
}

__all__ = ["REGISTRY", "Matcher"]
