#!/usr/bin/env python3
"""npm manifest matcher — package.json script execution.

Install-time lifecycle hooks are scanned by the signatures that do not opt out; a signature that
sets `scripts: run` is scanned over every script entry instead (dev/build/start and the rest), for
shapes that fire when a project is run rather than installed.
"""
from __future__ import annotations

import re

from stayawake.bots.security.jsonc import line_of_entry, object_spans
from stayawake.bots.security.models import Finding, Severity
from stayawake.bots.security.matchers.base import Matcher, load_jsonc
from stayawake.bots.security.dependencies.installed import NPM_LIFECYCLE_KEYS, stated_at


class NpmManifestMatcher(Matcher):
    handles = "npm-manifest"
    partitionable = True

    LIFECYCLE_KEYS = NPM_LIFECYCLE_KEYS

    def scan(self, target, signatures):
        compiled = [(s, re.compile(s["pattern"], re.IGNORECASE))
                    for s in signatures if s.get("pattern")]
        lifecycle = [(s, rx) for s, rx in compiled if s.get("scripts") != "run"]
        run = [(s, rx) for s, rx in compiled if s.get("scripts") == "run"]
        findings: list[Finding] = []
        for rel in target.iter_files():
            if rel.rsplit("/", 1)[-1] != "package.json":
                continue
            text = target.read_text(rel) or ""
            spans = object_spans(text, "scripts")
            span = spans[0] if spans else None
            for key, cmd in all_scripts(text):
                applicable = (lifecycle if key in NPM_LIFECYCLE_KEYS else []) + run
                if not applicable:
                    continue
                line = line_of_entry(text, key, cmd, span)
                for sig, rx in applicable:
                    if rx.search(cmd):
                        findings.append(self._emit(sig, rel, f"{key}: {cmd[:80]}", line=line))
        return findings

    @staticmethod
    def _emit(sig, rel, ev, *, line=None):
        return Finding(signature_id=sig["id"], category=sig["category"],
                       severity=Severity.parse(stated_at(sig, "severity", rel)), path=rel,
                       description=sig["description"], remediation=sig.get("remediation", "manual"),
                       line=line, evidence=ev, vector=sig["category"])


def lifecycle_scripts(text: str) -> list[tuple[str, str]]:
    """List the install-time scripts a package.json runs. Takes its text. Returns `(key, command)`
    pairs in lifecycle order, none when the text holds no scripts."""
    data = load_jsonc(text)
    scripts = data.get("scripts") if isinstance(data, dict) else None
    if not isinstance(scripts, dict):
        return []
    return [(key, scripts[key]) for key in NPM_LIFECYCLE_KEYS if isinstance(scripts.get(key), str)]


def all_scripts(text: str) -> list[tuple[str, str]]:
    """List every script a package.json declares. Takes its text. Returns `(key, command)` pairs in
    file order, none when the text holds no scripts."""
    data = load_jsonc(text)
    scripts = data.get("scripts") if isinstance(data, dict) else None
    if not isinstance(scripts, dict):
        return []
    return [(k, v) for k, v in scripts.items() if isinstance(v, str)]
