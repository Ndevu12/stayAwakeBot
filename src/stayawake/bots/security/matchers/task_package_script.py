#!/usr/bin/env python3
"""Package scripts an editor task runs when its folder opens: each is read from every package.json in the
repository that defines it and checked as the task's own command is."""
from __future__ import annotations

import re

from stayawake.bots.security.matchers.base import Matcher, build_confirmed_loader_check, load_jsonc
from stayawake.bots.security.matchers.editor_task import command_lines, runs_when_the_folder_opens
from stayawake.bots.security.matchers.payload_command import runs_a_payload
from stayawake.bots.security.models import Finding, Severity

_KIND = "vscode-task-runs-payload-script"
_NPM_SCRIPT_COMMANDS = frozenset({"run", "run-script", "start", "test", "restart", "stop"})
_INSTALL_COMMANDS = frozenset({"install", "i", "ci"})
_INSTALL_SCRIPTS = ("install", "prepublish", "prepare")
_SCRIPT_RUNNERS = frozenset({"npm", "pnpm", "yarn", "bun"})
_SCRIPT_NAME_END = re.compile(r"[&|;()<>\"'`]")
_MOST_HOPS = 4


def _script_name(word: str) -> str:
    """Return a script name as written in a command, cut where shell syntax starts. Takes the word."""
    return _SCRIPT_NAME_END.split(word, 1)[0]


def _scripts_a_command_runs(command: str) -> list[str]:
    """Return the package scripts a package manager command runs by name: the install scripts for an
    install, else the script of that name. Takes the command. Returns the names."""
    return list(_INSTALL_SCRIPTS) if command in _INSTALL_COMMANDS else [command]


def scripts_a_line_runs(line: str) -> list[str]:
    """Return the names of the package scripts a command line runs through npm, pnpm, yarn or bun. Takes
    the line. Returns the names, in order."""
    words = [word.strip("\"'(") for word in line.split()]
    names = []
    for i, word in enumerate(words):
        runner = word.rsplit("/", 1)[-1].lower()
        if runner not in _SCRIPT_RUNNERS or i + 1 >= len(words):
            continue
        following = [w for w in words[i + 1:] if not w.startswith("-")]
        if not following:
            continue
        command = _script_name(following[0])
        if command in ("run", "run-script"):
            if len(following) > 1:
                names.append(_script_name(following[1]))
        elif command == "restart":
            names += ["restart", "stop", "start"]
        elif command in _INSTALL_COMMANDS:
            names += _scripts_a_command_runs(command)
        elif command in _NPM_SCRIPT_COMMANDS or runner != "npm":
            names.append(command)
    return [name for name in names if name]


def _task_scripts(task: dict, task_file: dict, tasks: list[dict], hops: int = 0) -> list[str]:
    """Return the package scripts a task runs, through its own command lines, the npm script an editor
    task names, and the tasks it depends on. Takes the task, its file, the file's tasks and how many
    dependencies deep it sits. Returns the script names."""
    names = []
    if task.get("type") == "npm" and isinstance(task.get("script"), str):
        names += _scripts_a_command_runs(task["script"])
    for line in command_lines(task, task_file):
        names += scripts_a_line_runs(line)
    depends = task.get("dependsOn")
    depends = [depends] if isinstance(depends, (str, dict)) else depends if isinstance(depends, list) else []
    for dependency in depends:
        if isinstance(dependency, dict):
            if dependency.get("type") == "npm" and isinstance(dependency.get("script"), str):
                names += _scripts_a_command_runs(dependency["script"])
            continue
        if not isinstance(dependency, str):
            continue
        if dependency.startswith("npm: "):
            names += _scripts_a_command_runs(dependency[len("npm: "):].strip())
        if hops < _MOST_HOPS:
            for other in tasks:
                if other is not task and other.get("label") == dependency:
                    names += _task_scripts(other, task_file, tasks, hops + 1)
    return names


def _package_scripts(target, files: list[str]) -> list[tuple[str, dict]]:
    """Return each package.json in the repository outside installed packages with its scripts. Takes the
    target and its files. Returns (path, scripts) pairs."""
    found = []
    for rel in files:
        if rel.rsplit("/", 1)[-1] != "package.json" or "node_modules/" in f"/{rel}":
            continue
        data = load_jsonc(target.read_text(rel) or "")
        scripts = data.get("scripts") if isinstance(data, dict) else None
        if isinstance(scripts, dict):
            found.append((rel, scripts))
    return found


class TaskPackageScriptMatcher(Matcher):
    handles = "task-package-script"
    partitionable = False

    def scan(self, target, signatures, all_signatures=None):
        signature = next((s for s in signatures if s.get("kind") == _KIND), None)
        if signature is None:
            return []
        every = all_signatures or signatures
        loader_check = build_confirmed_loader_check(every)
        font_tools = frozenset(str(name).lower() for s in every for name in s.get("font_tools", ()))
        files = list(target.iter_files())
        task_files = [rel for rel in files if "/.vscode/" in f"/{rel}" and rel.endswith("/tasks.json")
                      or rel == ".vscode/tasks.json"]
        if not task_files:
            return []
        packages = _package_scripts(target, files)
        findings: list[Finding] = []
        for tasks_rel in task_files:
            data = load_jsonc(target.read_text(tasks_rel) or "")
            if not isinstance(data, dict):
                continue
            tasks = data.get("tasks")
            tasks = [t for t in tasks if isinstance(t, dict)] if isinstance(tasks, list) else (
                [tasks] if isinstance(tasks, dict) else [])
            for task in tasks:
                if not runs_when_the_folder_opens(task):
                    continue
                findings += self._judge(task, data, tasks, tasks_rel, packages, loader_check, font_tools,
                                        signature)
        return findings

    @staticmethod
    def _judge(task, task_file, tasks, tasks_rel, packages, loader_check, font_tools, signature):
        """Return a finding for each package script a folder-open task runs whose command runs a payload,
        following the scripts it runs in turn and npm's pre and post scripts. Takes the task, its file, the
        file's tasks, the file's path, the repository's package scripts, the known-loader check, the font
        tools' names and the signature. Returns the findings."""
        out, seen = [], set()
        pending = [(name, 0) for name in _task_scripts(task, task_file, tasks)]
        while pending:
            name, hops = pending.pop(0)
            for script in (f"pre{name}", name, f"post{name}"):
                for package_rel, scripts in packages:
                    command = scripts.get(script)
                    if not isinstance(command, str) or (package_rel, script) in seen:
                        continue
                    seen.add((package_rel, script))
                    if runs_a_payload(command, loader_check, font_tools):
                        out.append(Finding(
                            signature_id=signature["id"], category=signature["category"],
                            severity=Severity.parse(signature["severity"]), path=package_rel,
                            description=signature["description"],
                            remediation=signature.get("remediation", "manual"),
                            evidence=f"task '{task.get('label', '?')}' in {tasks_rel} runs '{script}': "
                                     f"{command[:90]}",
                            vector=signature["category"]))
                    if hops < _MOST_HOPS:
                        pending += [(nested, hops + 1) for nested in scripts_a_line_runs(command)]
        return out
