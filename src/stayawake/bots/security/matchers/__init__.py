#!/usr/bin/env python3
"""Matcher registry — maps a signature's `matcher` value to its strategy.

Adding a detection technique = add a module here and register its class.
"""
from __future__ import annotations

from stayawake.bots.security.matchers.base import Matcher
from stayawake.bots.security.matchers.content import ContentMatcher
from stayawake.bots.security.matchers.filename import FilenameMatcher
from stayawake.bots.security.matchers.structural import StructuralJsonMatcher
from stayawake.bots.security.matchers.heuristic import HeuristicMatcher
from stayawake.bots.security.matchers.git_history import GitHistoryMatcher
from stayawake.bots.security.matchers.obfuscation import ObfuscationMatcher
from stayawake.bots.security.matchers.npm_manifest import NpmManifestMatcher
from stayawake.bots.security.matchers.workflow import WorkflowYamlMatcher
from stayawake.bots.security.matchers.dependency_audit import DependencyAuditMatcher

REGISTRY: dict[str, Matcher] = {
    m.handles: m for m in (
        ContentMatcher(), FilenameMatcher(), StructuralJsonMatcher(),
        HeuristicMatcher(), GitHistoryMatcher(), ObfuscationMatcher(),
        NpmManifestMatcher(), WorkflowYamlMatcher(), DependencyAuditMatcher(),
    )
}

__all__ = ["REGISTRY", "Matcher"]
