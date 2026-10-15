#!/usr/bin/env python3
"""Structured-config auto-run matcher — VS Code tasks AND AI/agent (Claude Code) hooks.

Both are the same threat class (T1546 — a command that executes on an editor/agent lifecycle
event, so the operator runs nothing explicitly). VS Code: `tasks.json` `runOn: folderOpen` +
`settings.json` `task.allowAutomaticTasks`. Claude Code: `.claude/settings.json` `hooks` that
fire on a lifecycle event (SessionStart is the folderOpen analogue — it runs on project open).
"""
from __future__ import annotations

import re

from stayawake.bots.security.models import CONFIRMED, Finding, Severity
from stayawake.bots.security.matchers.base import (
    Matcher, load_jsonc, build_confirmed_loader_check, REMOTE_FETCH_INTO_INTERPRETER)
from stayawake.bots.security.matchers.command_shape import not_plain
from stayawake.bots.security.matchers.editor_task import command_lines, command_text, named

_CLAUDE_OPEN_EVENTS = {"SessionStart", "SessionEnd", "Notification", "PreCompact"}

_REMOTE_FETCH = REMOTE_FETCH_INTO_INTERPRETER
_FONT_EXEC = re.compile(r"\.(?:woff2?|ttf|otf|eot)\b", re.IGNORECASE)
_EDITOR_VARIABLE = re.compile(r"\$\{[^${}\s]{1,200}\}")
_EXECUTABLE_SUFFIX = re.compile(r"\.(?:exe|cmd|bat)$", re.IGNORECASE)


def _one_call_of_a_font_tool(line: str, font_tools: frozenset[str]) -> bool:
    """Tell whether a command line is one plain call of a font tool named without a path. Takes the line
    and the font tools' names. Returns the answer."""
    plain = _EDITOR_VARIABLE.sub("variable", line)
    words = plain.split()
    if not words or not_plain(plain):
        return False
    return _EXECUTABLE_SUFFIX.sub("", words[0]).lower() in font_tools


def _changes_what_a_name_runs(task: dict, task_file: dict) -> bool:
    """Tell whether a task or its file sets the environment or the shell its commands run with, for any
    platform. Takes the task and the task file it sits in. Returns the answer."""
    for scope in (task, task_file):
        for part in (scope, *(scope.get(platform) for platform in ("osx", "linux", "windows"))):
            options = part.get("options") if isinstance(part, dict) else None
            if isinstance(options, dict) and ("env" in options or "shell" in options):
                return True
    return False


def _font_named_by(task: dict, task_file: dict, font_tools: frozenset[str]) -> str | None:
    """Return the first command line of a task that names a font file and is not one plain call of a font
    tool; the task's command as written counts as a line when the editor cannot read it. Takes the task,
    the task file it sits in and the font tools' names. Returns the line, or None."""
    lines = command_lines(task, task_file)
    written = task.get("command")
    if written is not None and command_text(written) is None:
        lines.append(str(written))
    if _changes_what_a_name_runs(task, task_file):
        font_tools = frozenset()
    return next((line for line in lines
                 if _FONT_EXEC.search(line) and not _one_call_of_a_font_tool(line, font_tools)), None)


_PANELS_HIDDEN = {"terminal.integrated.hideOnStartup": ("always", "whenempty"),
                  "debug.openDebug": ("neveropen",)}
_TASK_LIST = "tasks"


def _conceals_itself(task: dict) -> bool:
    """Tell whether a task keeps itself out of sight. Takes the task. Returns True when it is hidden
    from the task list, does not bring its terminal forward when it starts, or does not show the
    command it runs."""
    if task.get("hide") is True:
        return True
    presentation = task.get("presentation")
    if not isinstance(presentation, dict):
        return False
    return named(presentation.get("reveal")) in ("never", "silent") or presentation.get("echo") is False


def _hides_panels_or_holds_tasks(settings: dict) -> bool:
    """Tell whether an editor settings file hides the terminal or debug panel when the folder opens, or
    holds a list of tasks. Takes the settings. Returns the answer."""
    if _TASK_LIST in settings:
        return True
    return any(named(settings.get(key)) in values for key, values in _PANELS_HIDDEN.items())


class StructuralJsonMatcher(Matcher):
    handles = "structural-json"
    partitionable = True

    def scan(self, target, signatures, all_signatures=None):
        by_kind = {s["kind"]: s for s in signatures if s.get("kind")}
        loader_check = build_confirmed_loader_check(all_signatures or signatures)
        findings: list[Finding] = []
        for rel in target.iter_files():
            base = rel.rsplit("/", 1)[-1]
            slashed = f"/{rel}"
            if "/.vscode/" in slashed and base in ("tasks.json", "settings.json"):
                data = load_jsonc(target.read_text(rel) or "")
                if isinstance(data, dict):
                    findings.extend(self._inspect(target, rel, base, data, by_kind))
            elif "/.claude/" in slashed and base in ("settings.json", "settings.local.json"):
                data = load_jsonc(target.read_text(rel) or "")
                if isinstance(data, dict):
                    findings.extend(self._inspect_claude(rel, data, by_kind, loader_check))
        return findings

    @staticmethod
    def _emit(sig, rel, ev, *, composed=False):
        return Finding(signature_id=sig["id"], category=sig["category"],
                       severity=Severity.parse(sig["severity"]), path=rel,
                       description=sig["description"], remediation=sig.get("remediation", "manual"),
                       evidence=ev, vector=sig["category"], composed_evidence=composed)

    # ── VS Code tasks (unchanged) ──────────────────────────────────────────────────
    @staticmethod
    def _tasks(data):
        t = data.get("tasks")
        if isinstance(t, list):
            return [x for x in t if isinstance(x, dict)]
        return [t] if isinstance(t, dict) else []

    def _inspect(self, target, rel, base, data, by_kind):
        out = self._task_findings(rel, data, by_kind)
        if base == "settings.json":
            value = data.get("task.allowAutomaticTasks")
            if value is True or (isinstance(value, str) and value != "off"):
                armed = _hides_panels_or_holds_tasks(data) or self._launcher_beside(target, rel, by_kind)
                kind = "vscode-allow-automatic-tasks" if armed else "vscode-allow-automatic-tasks-alone"
                if kind in by_kind:
                    out.append(self._emit(by_kind[kind], rel, f"task.allowAutomaticTasks: {value!r}"))
        return out

    def _launcher_beside(self, target, rel, by_kind) -> bool:
        """Tell whether the tasks.json beside a settings file holds a task this matcher confirms. Takes
        the target, the settings file's path and the signatures by kind. Returns the answer."""
        confirmed = {s["id"] for s in by_kind.values() if s.get("confidence") == CONFIRMED}
        tasks_path = rel[:-len("settings.json")] + "tasks.json"
        tasks = load_jsonc(target.read_text(tasks_path) or "")
        beside = self._task_findings(tasks_path, tasks, by_kind) if isinstance(tasks, dict) else []
        return any(f.signature_id in confirmed for f in beside)

    def _task_findings(self, rel, data, by_kind):
        out = []
        runs_font_signature = by_kind.get("vscode-task-runs-font", {})
        font_tools = frozenset(str(name).lower() for name in runs_font_signature.get("font_tools", ()))
        for task in self._tasks(data):
            run_options = task.get("runOptions")
            run_on = run_options.get("runOn") if isinstance(run_options, dict) else None
            runs_on_open = (named(run_on) == "folderopen" if run_on
                            else task.get("runOn") == "folderOpen")
            if runs_on_open:
                # Auto-running is what the setting is FOR. Legitimate auto-run tasks are ordinary;
                # legitimate auto-run tasks that hide themselves are not, so the pair is the signal.
                kind = ("vscode-task-autorun" if _conceals_itself(task)
                        else "vscode-task-autorun-visible")
                if kind in by_kind:
                    out.append(self._emit(by_kind[kind], rel,
                                          f"task '{task.get('label','?')}' runOn=folderOpen"))
            runs_font = _font_named_by(task, data, font_tools)
            if runs_font is not None and "vscode-task-runs-font" in by_kind:
                out.append(self._emit(by_kind["vscode-task-runs-font"], rel, runs_font[:90]))
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
