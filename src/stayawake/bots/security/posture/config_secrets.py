#!/usr/bin/env python3
"""Posture matcher: a real credential committed as a `${VAR:default}` fallback in a config file."""
from __future__ import annotations

import re

from stayawake.bots.security.matchers.base import Matcher
from stayawake.bots.security.models import Finding, Severity

_CONFIG_EXTS = {".yml", ".yaml", ".properties", ".json", ".toml", ".env", ".conf", ".cfg", ".ini"}
_CRED_NAME = re.compile(
    r"(?i)(?:pass(?:word|wd)?|secret|token|api[_-]?key|credential|signing[_-]?key|private[_-]?key)")
_PLACEHOLDER = re.compile(r"\$\{([A-Za-z0-9_.]+):([^}\r\n]*)\}")
_DUMMY = re.compile(
    r"(?i)^(?:change[-_]?me|placeholder|example|sample|dummy|secret|password|none|null|undefined|"
    r"your[-_].*|test(?:[-_].*)?|x{2,}|\*+|<.*>|t(?:rue)?|f(?:alse)?|localhost|127\.0\.0\.1)$")


def _ext(rel: str) -> str:
    i = rel.rfind(".")
    return rel[i:].lower() if i != -1 else ""


def _is_real_default(value: str) -> bool:
    """Tell whether a placeholder default looks like a real committed secret rather than a dummy or a
    non-secret. Takes the default text; returns the answer."""
    v = value.strip()
    if len(v) < 8 or v.startswith("${") or v.isdigit() or _DUMMY.match(v):
        return False
    return True


def _line_of(text: str, index: int) -> int:
    return text.count("\n", 0, index) + 1


class ConfigSecretMatcher(Matcher):
    handles = "config-secret"
    partitionable = True

    def scan(self, target, signatures):
        sig = next((s for s in signatures if s.get("kind") == "config-credential-default"), None)
        if sig is None:
            return []
        findings: list[Finding] = []
        for rel in target.iter_files():
            if _ext(rel) not in _CONFIG_EXTS:
                continue
            text = target.read_text(rel)
            if not text or "${" not in text:
                continue
            for match in _PLACEHOLDER.finditer(text):
                var, default = match.group(1), match.group(2)
                if _CRED_NAME.search(var) and _is_real_default(default):
                    findings.append(_emit(sig, rel, var, _line_of(text, match.start())))
        return findings


def _emit(sig, rel: str, var: str, line: int) -> Finding:
    return Finding(
        signature_id=sig["id"], category=sig["category"],
        severity=Severity.parse(sig["severity"]), path=rel,
        description=sig["description"], remediation=sig.get("remediation", "manual"),
        evidence=f"{rel}:{line} — ${{{var}:…}} commits a credential default (value redacted)",
        vector=sig["category"], composed_evidence=True)
