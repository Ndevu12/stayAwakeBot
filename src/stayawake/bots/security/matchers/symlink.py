#!/usr/bin/env python3
"""Symlink-escape matcher — a symlink resolving OUTSIDE the repo root (#1146, blind spot #9 of #1141).

The scanner walks with ``followlinks=False`` (a deliberate cycle/DoS guard), so a symlinked directory
is never traversed and its contents go unscanned. That silent skip is a scan-evasion hole: a committed
``src/lib -> ../../outside`` (or a link into a pruned ``node_modules``) hides code from every content
matcher. This matcher REPORTS such symlinks as a heuristic → SUSPICIOUS anomaly (a link is an anomaly,
not a payload) WITHOUT ever following them:

  * ``Path.resolve()`` only CANONICALIZES the path — it never reads the target's contents, so there is
    no traversal cost and no directory-tree DoS (a link to ``/`` or ``/dev`` is free to resolve).
  * symlink loops (ELOOP) raise and are skipped — no infinite walk.
  * ``followlinks=False`` is preserved, so we report but never descend into / open the target.

Scope is DIRECTORY symlinks only: a dir symlink escaping the repo can hide a whole code subtree (the
real scan-evasion), whereas escaping FILE symlinks are overwhelmingly benign dev-env links (a venv's
``bin/python -> /usr/.../python3.14``, tool shims) — reporting those is pure noise, so they are a
documented residual, not a finding. A symlink whose target stays INSIDE the repo is normal (monorepo
relative links) and is not flagged; only an escape past the repo root is surfaced. The *contents*
behind any symlink stay unscanned by design. Reporting stays heuristic because legitimate escaping
links exist (dotfile repos linking to ``$HOME``, tooling fixtures).
"""
from __future__ import annotations

import os
from pathlib import Path

from stayawake.bots.security.models import Finding, Severity
from stayawake.bots.security.matchers.base import Matcher


class SymlinkMatcher(Matcher):
    handles = "symlink"

    def scan(self, target, signatures):
        sig = next(iter(signatures), None)
        if sig is None:
            return []
        try:
            root = target.root.resolve()
        except (OSError, RuntimeError):
            return []
        exclude = getattr(target.opts, "exclude_dirs", set())
        findings: list[Finding] = []
        for dirpath, dirnames, filenames in os.walk(target.root):   # followlinks=False (default)
            dirnames[:] = [d for d in dirnames if d not in exclude]  # prune as iter_files does
            for name in dirnames:                                    # DIRECTORY symlinks only (see docstring)
                p = Path(dirpath) / name
                if not p.is_symlink():
                    continue
                try:
                    resolved = p.resolve()          # canonicalize only — never reads target; loop-safe
                except (OSError, RuntimeError):
                    continue                          # ELOOP / unresolvable → skip (no DoS)
                if resolved == root or root in resolved.parents:
                    continue                          # stays inside the repo → normal
                try:
                    tgt = os.readlink(p)
                except OSError:
                    tgt = "?"
                findings.append(Finding(
                    signature_id=sig["id"], category=sig["category"],
                    severity=Severity.parse(sig["severity"]),
                    path=str(p.relative_to(target.root)),
                    description=sig["description"], remediation=sig.get("remediation", "manual"),
                    evidence=f"symlink → {tgt} resolves outside the repo root (contents unscanned)",
                    vector=sig["category"]))
        return findings
