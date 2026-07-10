#!/usr/bin/env python3
"""npm manifest matcher — install-time lifecycle-hook execution in package.json.

npm auto-runs `preinstall`/`install`/`postinstall`/`prepare` on `npm install`, so a command
planted in one of those keys executes with no user action — the classic Shai-Hulud vector
(`"preinstall": "node setup_bun.js"`), and the Bun-smuggling / remote-fetch variants.

Kept separate from the VS Code `structural-json` matcher (whose `.vscode/`-only gate must not
be relaxed). It inspects ONLY the npm-auto-run lifecycle keys' command strings — never user
scripts like `test`/`build` (which run only when a human invokes them), so a normal manifest
stays clean. Detection is data-driven: each `matcher: npm-manifest` signature's `pattern` is
tested against each lifecycle command, so new indicators are a signatures.yml add, no code.
"""
from __future__ import annotations

import re

from stayawake.bots.security.models import Finding, Severity
from stayawake.bots.security.matchers.base import Matcher, load_jsonc
from stayawake.bots.security.dependencies.installed import NPM_LIFECYCLE_KEYS


class NpmManifestMatcher(Matcher):
    handles = "npm-manifest"

    # The keys npm runs automatically on `npm install` (T1546); `test`/`build`/etc. run only when a
    # human invokes them, so they are not this vector. One source, shared with the installed-tree hook
    # scan (the same keys of an installed dependency's package.json).
    LIFECYCLE_KEYS = NPM_LIFECYCLE_KEYS

    def scan(self, target, signatures):
        compiled = [(s, re.compile(s["pattern"], re.IGNORECASE))
                    for s in signatures if s.get("pattern")]
        findings: list[Finding] = []
        for rel in target.iter_files():
            if rel.rsplit("/", 1)[-1] != "package.json":
                continue
            data = load_jsonc(target.read_text(rel) or "")
            scripts = data.get("scripts") if isinstance(data, dict) else None
            if not isinstance(scripts, dict):
                continue
            for key in self.LIFECYCLE_KEYS:
                cmd = scripts.get(key)
                if not isinstance(cmd, str):
                    continue
                for sig, rx in compiled:
                    if rx.search(cmd):
                        findings.append(self._emit(sig, rel, f"{key}: {cmd[:80]}"))
        return findings

    @staticmethod
    def _emit(sig, rel, ev):
        return Finding(signature_id=sig["id"], category=sig["category"],
                       severity=Severity.parse(sig["severity"]), path=rel,
                       description=sig["description"], remediation=sig.get("remediation", "manual"),
                       evidence=ev, vector=sig["category"])
