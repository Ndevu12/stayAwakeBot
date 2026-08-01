#!/usr/bin/env python3
"""Context-aware obfuscation analysis for a *delta* (or whole file) of source text.

Split per concern: `execsink` (self-evident dynamic-exec sink constructs) / `heuristics` (whole-file
density / entropy / escape-run / minification + the `is_generated_context` suppression predicate) /
`entry` (the `analyze_file` / `analyze_delta` verdicts that compose them). The decode→exec dropper
FLOW primitives now live in `taint/` (imported the one way, `obfuscation → taint`); the shared
low-level text utilities (entropy, data-URI, de-chunk) live in `sourcescan`.

Single responsibility: decide whether a chunk of newly-introduced text in a hand-authored source
file is obfuscated/packed payload, as opposed to ordinary hand-written code. No I/O, no git, no regex
catalogue duplication: callers pass in plain strings. This package re-exports only the public API;
internal helpers (`_has_exec_sink`, the density constants, …) are reached at their submodule home
(`obfuscation.execsink.*` / `obfuscation.heuristics.*`).
"""
from __future__ import annotations

from stayawake.bots.security.obfuscation.entry import (
    analyze_file, analyze_delta, ObfuscationVerdict)
from stayawake.bots.security.obfuscation.heuristics import is_generated_context

__all__ = ["analyze_file", "analyze_delta", "ObfuscationVerdict", "is_generated_context"]
