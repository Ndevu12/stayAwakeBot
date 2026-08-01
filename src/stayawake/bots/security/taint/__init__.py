#!/usr/bin/env python3
"""Decode→exec dropper detection: `model` (what a dropper is) + `analyzer` (tracing the flow).

Kept import-light on purpose — `analyzer` imports `obfuscation` for its hardened primitives, so
callers reach it via `from stayawake.bots.security.taint.analyzer import detect_dropper` (a lazy,
function-level import in `obfuscation`) to avoid an import cycle. Nothing is imported here at
package-init time.
"""
