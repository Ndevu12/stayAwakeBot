#!/usr/bin/env python3
"""Decode→exec dropper detection: the ONE place the decode→exec capability lives.

Three concerns: `model` (what a dropper IS — the threat as data), `flow` (the hardened decode→exec
primitives: decode/sink regexes, blob corroborators, the scope-aware variable walk, the scrubber),
and `analyzer` (traces the flow end-to-end via `detect_dropper`). `obfuscation` depends on THIS
package — `execsink` reuses `flow._has_corroborated_dynamic_exec`, and `entry` calls
`analyzer.detect_dropper` (a lazy, function-level import) — so the dependency flows one way,
`obfuscation → taint`. Nothing is imported here at package-init time to keep that load order clean.
"""
