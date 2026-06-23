#!/usr/bin/env python3
"""VS Code JSON(C) structural matcher — detects auto-run/exec configuration."""
from __future__ import annotations

import re

from security.models import Finding, Severity
from security.matchers.base import Matcher, load_jsonc


class StructuralJsonMatcher(Matcher):
    handles = "structural-json"

    def scan(self, target, signatures):
        by_kind = {s["kind"]: s for s in signatures if s.get("kind")}
        findings: list[Finding] = []
        for rel in target.iter_files():
            base = rel.rsplit("/", 1)[-1]
            if base not in ("tasks.json", "settings.json") or "/.vscode/" not in f"/{rel}":
                continue
            data = load_jsonc(target.read_text(rel) or "")
            if isinstance(data, dict):
                findings.extend(self._inspect(rel, base, data, by_kind))
        return findings

    @staticmethod
    def _emit(sig, rel, ev):
        return Finding(signature_id=sig["id"], category=sig["category"],
                       severity=Severity.parse(sig["severity"]), path=rel,
                       description=sig["description"], remediation=sig.get("remediation", "manual"),
                       evidence=ev, vector=sig["category"])

    @staticmethod
    def _tasks(data):
        t = data.get("tasks")
        if isinstance(t, list):
            return [x for x in t if isinstance(x, dict)]
        return [t] if isinstance(t, dict) else []

    def _inspect(self, rel, base, data, by_kind):
        out = []
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
