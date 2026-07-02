#!/usr/bin/env python3
"""Structured-config auto-run matcher — VS Code tasks AND AI/agent (Claude Code) hooks.

Both are the same threat class (T1546 — a command that executes on an editor/agent lifecycle
event, so the operator runs nothing explicitly). VS Code: `tasks.json` `runOn: folderOpen` +
`settings.json` `task.allowAutomaticTasks`. Claude Code: `.claude/settings.json` `hooks` that
fire on a lifecycle event (SessionStart is the folderOpen analogue — it runs on project open).
"""
from __future__ import annotations

import re

from stayawake.bots.security.models import Finding, Severity
from stayawake.bots.security.matchers.base import Matcher, load_jsonc, build_content_sig

# Claude Code lifecycle events that fire WITHOUT the user invoking a specific tool — the agent
# analogue of runOn:folderOpen. (PreToolUse/PostToolUse/UserPromptSubmit fire only during active
# tool use and are commonly legit — formatters/linters — so a bare command hook there is NOT
# flagged, to avoid false positives; a hook there running a PAYLOAD is still caught, below.)
_CLAUDE_OPEN_EVENTS = {"SessionStart", "SessionEnd", "Notification", "PreCompact"}

# Unmistakable payload shapes in a hook command → confirmed (INFECTED). Remote-fetch reuses the
# shape shared with the npm/workflow matchers; font-exec mirrors the VS Code vscode-task-runs-font
# signal (a disguised font/binary run via node). Loader fingerprints are corroborated separately.
_REMOTE_FETCH = re.compile(
    r"\b(?:curl|wget)\b[^|]*\|\s*(?:sh|bash|node|bun|bunx|deno)\b", re.IGNORECASE)
_FONT_EXEC = re.compile(r"\.(?:woff2?|ttf|otf)\b", re.IGNORECASE)


class StructuralJsonMatcher(Matcher):
    handles = "structural-json"

    def scan(self, target, signatures, all_signatures=None):
        by_kind = {s["kind"]: s for s in signatures if s.get("kind")}
        # Corroborate a hook command against the shared code-loader fingerprints (one source of
        # truth, so the two never drift). Needs the cross-signature view; falls back gracefully.
        loader_check = build_content_sig(all_signatures or signatures)
        findings: list[Finding] = []
        for rel in target.iter_files():
            base = rel.rsplit("/", 1)[-1]
            slashed = f"/{rel}"
            if "/.vscode/" in slashed and base in ("tasks.json", "settings.json"):
                data = load_jsonc(target.read_text(rel) or "")
                if isinstance(data, dict):
                    findings.extend(self._inspect(rel, base, data, by_kind))
            elif "/.claude/" in slashed and base in ("settings.json", "settings.local.json"):
                data = load_jsonc(target.read_text(rel) or "")
                if isinstance(data, dict):
                    findings.extend(self._inspect_claude(rel, data, by_kind, loader_check))
        return findings

    @staticmethod
    def _emit(sig, rel, ev):
        return Finding(signature_id=sig["id"], category=sig["category"],
                       severity=Severity.parse(sig["severity"]), path=rel,
                       description=sig["description"], remediation=sig.get("remediation", "manual"),
                       evidence=ev, vector=sig["category"])

    # ── VS Code tasks (unchanged) ──────────────────────────────────────────────────
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

    # ── Claude Code hooks ──────────────────────────────────────────────────────────
    @staticmethod
    def _hook_payload(cmd, loader_check):
        """The command runs an unmistakable payload → a reason string, else None."""
        if _REMOTE_FETCH.search(cmd):
            return "remote fetch → interpreter"
        if _FONT_EXEC.search(cmd):
            return "executes a font/binary"
        if loader_check and loader_check(cmd):
            return "known loader fingerprint"
        return None

    def _inspect_claude(self, rel, data, by_kind, loader_check):
        # Schema: {"hooks": {"<Event>": [{"matcher"?: str, "hooks": [{"type":"command",
        # "command": str}]}]}}. Every field is attacker-shaped, so type-guard each level.
        out = []
        hooks = data.get("hooks")
        if not isinstance(hooks, dict):
            return out
        for event, groups in hooks.items():
            if not isinstance(groups, list):
                continue
            for group in groups:
                inner = group.get("hooks") if isinstance(group, dict) else None
                if not isinstance(inner, list):
                    continue
                for hook in inner:
                    if not isinstance(hook, dict) or hook.get("type") != "command":
                        continue
                    cmd = hook.get("command")
                    if not isinstance(cmd, str):
                        continue
                    payload = self._hook_payload(cmd, loader_check)
                    if payload and "claude-hook-runs-payload" in by_kind:
                        out.append(self._emit(by_kind["claude-hook-runs-payload"], rel,
                                              f"{event} hook — {payload}: {cmd[:70]}"))
                    elif event in _CLAUDE_OPEN_EVENTS and "claude-hook-autorun" in by_kind:
                        out.append(self._emit(by_kind["claude-hook-autorun"], rel,
                                              f"{event} hook auto-runs: {cmd[:70]}"))
        return out
