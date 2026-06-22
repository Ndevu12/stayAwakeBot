#!/usr/bin/env python3
"""Detection strategies. Each matcher handles one detection *technique* and is
selected by a signature's `matcher` field, so new threats are added as data in
config/security_signatures.yml (Open/Closed: extend signatures, not code).

A Matcher implements `scan(target, signatures) -> list[Finding]`. `target` is any
object exposing the small surface defined in targets.Target (root, iter_files,
read_text, repo_root, display name).
"""
from __future__ import annotations

import json
import re
from fnmatch import fnmatch
from typing import Any, Iterable

from helpers.common import git as gitutil
from helpers.security.findings import Finding, Severity

# Font-format magic bytes; anything claiming to be a font but lacking these and
# carrying printable text is treated as a disguised payload.
_FONT_MAGIC = {
    ".woff2": b"wOF2",
    ".woff": b"wOFF",
    ".ttf": b"\x00\x01\x00\x00",
    ".otf": b"OTTO",
}


def _evidence(text: str, start: int, end: int, width: int = 80) -> str:
    """Short, redaction-safe snippet around a match."""
    s = max(0, start - 12)
    snippet = text[s:end + width].replace("\n", " ")
    return (snippet[:width] + "…") if len(snippet) > width else snippet


def _globs_ok(relpath: str, sig: dict[str, Any]) -> bool:
    globs = sig.get("file_globs")
    if not globs:
        return True
    base = relpath.rsplit("/", 1)[-1]
    return any(fnmatch(relpath, g) or fnmatch(base, g) for g in globs)


def _strip_jsonc(text: str) -> str:
    """Best-effort JSONC → JSON (drop // and /* */ comments and trailing commas)."""
    text = re.sub(r"/\*.*?\*/", "", text, flags=re.S)
    text = re.sub(r"(^|[^:])//.*$", r"\1", text, flags=re.M)
    text = re.sub(r",(\s*[}\]])", r"\1", text)
    return text


def _load_jsonc(text: str) -> Any:
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        try:
            return json.loads(_strip_jsonc(text))
        except json.JSONDecodeError:
            return None


class Matcher:
    """Base strategy. Subclasses set `handles` to the signature `matcher` value."""

    handles: str = ""

    def scan(self, target, signatures: list[dict[str, Any]]) -> list[Finding]:
        raise NotImplementedError


class ContentMatcher(Matcher):
    handles = "content"

    def scan(self, target, signatures):
        compiled = [(s, re.compile(s["pattern"])) for s in signatures if s.get("pattern")]
        findings: list[Finding] = []
        for rel in target.iter_files():
            sigs = [(s, rx) for s, rx in compiled if _globs_ok(rel, s)]
            if not sigs:
                continue
            text = target.read_text(rel)
            if text is None:
                continue
            for s, rx in sigs:
                m = rx.search(text)
                if m:
                    line = text.count("\n", 0, m.start()) + 1
                    findings.append(Finding(
                        signature_id=s["id"], category=s["category"],
                        severity=Severity.parse(s["severity"]), path=rel,
                        description=s["description"], remediation=s.get("remediation", "manual"),
                        line=line, evidence=_evidence(text, m.start(), m.end()),
                        vector=s["category"],
                    ))
        return findings


class FilenameMatcher(Matcher):
    handles = "filename"

    def scan(self, target, signatures):
        findings: list[Finding] = []
        for rel in target.iter_files():
            base = rel.rsplit("/", 1)[-1]
            for s in signatures:
                pat = s.get("pattern", "")
                if base == pat or fnmatch(base, pat) or fnmatch(rel, pat):
                    findings.append(Finding(
                        signature_id=s["id"], category=s["category"],
                        severity=Severity.parse(s["severity"]), path=rel,
                        description=s["description"], remediation=s.get("remediation", "manual"),
                        vector=s["category"],
                    ))
        return findings


class StructuralJsonMatcher(Matcher):
    """Parses VS Code JSON(C) to spot auto-run/exec configuration."""

    handles = "structural-json"

    def scan(self, target, signatures):
        by_kind = {s["kind"]: s for s in signatures if s.get("kind")}
        findings: list[Finding] = []
        for rel in target.iter_files():
            base = rel.rsplit("/", 1)[-1]
            if base not in ("tasks.json", "settings.json") or "/.vscode/" not in f"/{rel}":
                continue
            text = target.read_text(rel)
            if text is None:
                continue
            data = _load_jsonc(text)
            if not isinstance(data, dict):
                continue
            findings.extend(self._inspect(rel, base, data, by_kind))
        return findings

    def _emit(self, sig, rel, evidence):
        return Finding(
            signature_id=sig["id"], category=sig["category"],
            severity=Severity.parse(sig["severity"]), path=rel,
            description=sig["description"], remediation=sig.get("remediation", "manual"),
            evidence=evidence, vector=sig["category"],
        )

    @staticmethod
    def _tasks(data: dict) -> list[dict]:
        t = data.get("tasks")
        if isinstance(t, list):
            return [x for x in t if isinstance(x, dict)]
        if isinstance(t, dict):           # settings.json abuse: a task object under "tasks"
            return [t]
        return []

    def _inspect(self, rel, base, data, by_kind):
        out: list[Finding] = []
        for task in self._tasks(data):
            run_on = (task.get("runOptions", {}) or {}).get("runOn") or task.get("runOn")
            cmd = str(task.get("command", ""))
            if run_on == "folderOpen" and "vscode-task-autorun" in by_kind:
                out.append(self._emit(by_kind["vscode-task-autorun"], rel,
                                      f"task '{task.get('label','?')}' runOn=folderOpen"))
            if re.search(r"\.(woff2?|ttf|otf)\b", cmd) and "vscode-task-runs-font" in by_kind:
                out.append(self._emit(by_kind["vscode-task-runs-font"], rel, cmd[:90]))
        if base == "settings.json" and data.get("task.allowAutomaticTasks") is True \
                and "vscode-allow-automatic-tasks" in by_kind:
            out.append(self._emit(by_kind["vscode-allow-automatic-tasks"], rel,
                                  "task.allowAutomaticTasks: true"))
        return out


class HeuristicMatcher(Matcher):
    handles = "heuristic"

    def scan(self, target, signatures):
        findings: list[Finding] = []
        long_line = next((s for s in signatures if s.get("kind") == "long-line"), None)
        text_font = next((s for s in signatures if s.get("kind") == "text-in-fontfile"), None)
        for rel in target.iter_files():
            if long_line and _globs_ok(rel, long_line):
                text = target.read_text(rel)
                if text is not None:
                    th = int(long_line.get("threshold", 2000))
                    for i, ln in enumerate(text.splitlines(), 1):
                        if len(ln) > th:
                            findings.append(self._emit(long_line, rel,
                                            f"line {i}: {len(ln)} chars", line=i))
                            break
            if text_font and _globs_ok(rel, text_font):
                f = self._disguised_font(target, rel, text_font)
                if f:
                    findings.append(f)
        return findings

    @staticmethod
    def _emit(sig, rel, evidence, line=None):
        return Finding(
            signature_id=sig["id"], category=sig["category"],
            severity=Severity.parse(sig["severity"]), path=rel,
            description=sig["description"], remediation=sig.get("remediation", "manual"),
            line=line, evidence=evidence, vector=sig["category"],
        )

    def _disguised_font(self, target, rel, sig):
        ext = "." + rel.rsplit(".", 1)[-1].lower() if "." in rel else ""
        magic = _FONT_MAGIC.get(ext)
        raw = target.read_bytes(rel, limit=512)
        if raw is None or not raw:
            return None
        # SVG fonts are legitimately text; only flag binary-format fonts.
        if magic and not raw.startswith(magic):
            looks_texty = sum(1 for b in raw[:256] if 9 <= b <= 126) > 200
            has_js = any(tok in raw for tok in (b"function", b"var ", b"=>", b"require", b"global"))
            if looks_texty or has_js:
                return self._emit(sig, rel, f"{ext} without {magic!r} magic; content is text/JS")
        return None


class GitHistoryMatcher(Matcher):
    handles = "git-history"

    def scan(self, target, signatures):
        sig = next((s for s in signatures if s.get("kind") == "evil-merge"), None)
        if not sig or not gitutil.is_git_repo(target.repo_root):
            return []
        findings: list[Finding] = []
        for sha in gitutil.merge_commits(target.repo_root):
            evil = gitutil.evil_merge_paths(target.repo_root, sha)
            if evil:
                meta = gitutil.commit_meta(target.repo_root, sha)
                findings.append(Finding(
                    signature_id=sig["id"], category=sig["category"],
                    severity=Severity.parse(sig["severity"]), path=sha[:10],
                    description=sig["description"], remediation=sig.get("remediation", "manual"),
                    evidence=f"{len(evil)} path(s) in neither parent; e.g. {sorted(evil)[:3]}; "
                             f"by {meta.get('author_email','?')}",
                    vector="evil-merge",
                ))
        return findings


# Registry: matcher `handles` value -> instance. Adding a technique = add a class here.
REGISTRY: dict[str, Matcher] = {
    m.handles: m for m in (
        ContentMatcher(), FilenameMatcher(), StructuralJsonMatcher(),
        HeuristicMatcher(), GitHistoryMatcher(),
    )
}
