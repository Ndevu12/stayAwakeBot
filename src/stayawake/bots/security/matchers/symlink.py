#!/usr/bin/env python3
"""Symlink matcher.

Reports two anomalies from a symlink's own metadata — one confirmed, one heuristic — without ever
following the link or reading what is behind it.
"""
from __future__ import annotations

import os
import re
from pathlib import Path

from stayawake.bots.security.models import Finding, Severity
from stayawake.bots.security.matchers.base import Matcher
from stayawake.bots.security.write_sinks import sink_label


def _finding(sig: dict, rel: str, evidence: str) -> Finding:
    return Finding(
        signature_id=sig["id"], category=sig["category"], severity=Severity.parse(sig["severity"]),
        path=rel, description=sig["description"], remediation=sig.get("remediation", "manual"),
        evidence=evidence, vector=sig["category"], composed_evidence=True)


def _classify(p: Path, repo_root: Path, resolved_root: Path,
              redirect_sig: dict | None, escape_sig: dict | None, is_dir: bool) -> Finding | None:
    """The finding this symlink warrants, or None. Only ESCAPING links matter: a write-redirect sink is
    outside the repo, and a scan-evasion escape is by definition outside. An intra-repo link (a monorepo
    alias, a link to the repo's OWN dotfile) is neither. resolve() canonicalizes without reading the
    target; ELOOP/unresolvable/unreadable → skipped (no DoS, no crash)."""
    try:
        if not p.is_symlink():
            return None
    except OSError:
        return None
    try:
        resolved = p.resolve()
    except (OSError, RuntimeError):
        return None                           # ELOOP / unresolvable → skip
    if resolved == resolved_root or resolved_root in resolved.parents:
        return None                           # stays inside the repo → normal
    try:
        raw = os.readlink(p)
    except OSError:
        raw = "?"
    try:
        rel = str(p.relative_to(repo_root))
    except ValueError:
        rel = str(p)
    if redirect_sig is not None:
        label = sink_label(raw, resolved)
        if label is not None:                 # escaping → a sensitive write-sink → CONFIRMED critical
            return _finding(redirect_sig, rel, f"symlink → {raw} redirects a write into {label}")
    if escape_sig is not None and is_dir:      # escaping directory → non-sink → scan-evasion HEURISTIC
        return _finding(escape_sig, rel, f"symlink → {raw} resolves outside the repo root (contents unscanned)")
    return None


class SymlinkMatcher(Matcher):
    handles = "symlink"

    def scan(self, target, signatures):
        by_id = {s["id"]: s for s in signatures}
        redirect_sig = by_id.get("symlink-write-redirect")
        escape_sig = by_id.get("symlink-escapes-repo")
        if redirect_sig is None and escape_sig is None:
            return []
        try:
            root = target.root.resolve()
        except (OSError, RuntimeError):
            return []
        exclude = getattr(target.opts, "exclude_dirs", set())
        findings: list[Finding] = []
        if getattr(target, "names_one_file", False):
            for rel in (target.include_only or ()):
                entry = target.root / rel
                # Same rule the walk applies to an excluded NAME: a build-output link is checked for
                # a write redirect, never for an escape — naming it must not invent a finding.
                esc = None if entry.name in exclude else escape_sig
                f = _classify(entry, target.root, root, redirect_sig, esc, entry.is_dir())
                if f is not None:
                    findings.append(f)
            return findings
        for dirpath, dirnames, filenames in os.walk(target.scan_root):  # followlinks=False (default)
            # Classify DIRECTORY entries BEFORE pruning for descent, so a write-redirect symlink whose
            # NAME is an excluded dir (`dist -> ~/.ssh`, `node_modules -> ~/.ssh`) is still caught —
            # `dist`/`build` are exactly where build tools write. Pruning only stops DESCENT, and
            # os.walk(followlinks=False) never descends a symlink anyway. For an excluded name we run the
            # write-redirect check ONLY (escape_sig=None): a benign build-output dir link escaping to a
            for name in dirnames:
                esc = None if name in exclude else escape_sig
                f = _classify(Path(dirpath) / name, target.root, root, redirect_sig, esc, True)
                if f is not None:
                    findings.append(f)
            dirnames[:] = [d for d in dirnames if d not in exclude]
            # FILE symlinks: a write-redirect can be a file link (the canonical GhostApproval shape); a
            for name in filenames:
                f = _classify(Path(dirpath) / name, target.root, root, redirect_sig, escape_sig, False)
                if f is not None:
                    findings.append(f)
        return findings
