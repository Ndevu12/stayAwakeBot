#!/usr/bin/env python3
"""Ask the operator, once per run, which known-malicious packages to remove from the project's
manifests. Nothing is removed without a yes."""
from __future__ import annotations

from pathlib import Path

from stayawake.bots.security.dependencies.remediation import (MALICIOUS, DependencyAction,
                                                              dependency_actions)
from stayawake.bots.security.pr.resolve import TAKE_OUT, DependencyAnswer, DependencyQuestion
from stayawake.bots.security.remediation import manifest


class Chooser:
    """The known-malicious packages a run removes from the project's manifests: each one asked
    about once, and removed only on the operator's yes."""

    def __init__(self, resolver=None, root: Path | None = None):
        self._resolver = resolver
        self._root = root
        self._answers: dict[str, bool] = {}
        self._actions: dict[str, dict[str, DependencyAction]] = {}

    def __call__(self, findings) -> set[str]:
        """Choose the packages to remove. Takes the findings. Returns the names the operator said
        to remove; empty when nobody can be asked."""
        declared = manifest.declared_malicious(findings)
        for name, (versions, paths) in declared.items():
            if name not in self._answers:
                self._answers[name] = self._said_yes(self._question(name, versions, paths))
            mine = [f for f in findings if getattr(f, "package_name", None) == name
                    and getattr(f, "dependency_state", None) == MALICIOUS]
            for action in dependency_actions(mine).malicious:
                self._actions.setdefault(name, {}).setdefault(action.package, action)
        return {name for name in declared if self._answers[name]}

    def kept(self) -> tuple[DependencyAction, ...]:
        """List the packages the operator kept or was not asked about. Returns each one with the
        command to remove it."""
        return tuple(action for name, actions in sorted(self._actions.items())
                     if not self._answers.get(name) for action in actions.values())

    def _question(self, name: str, versions, paths) -> DependencyQuestion:
        """Build one package question, with the rewritten manifest text where it can be computed.
        Takes the package name, the versions and the manifests. Returns the question."""
        proposed = []
        if self._root is not None:
            for path in paths:
                text = manifest.proposed_text(self._root, path, {name})
                if text is not None:
                    proposed.append((path, text))
        return DependencyQuestion(name, versions, paths, tuple(proposed))

    def _said_yes(self, question: DependencyQuestion) -> bool:
        """Put one question to the operator. Takes the question. Returns True only on a yes."""
        if self._resolver is None:
            return False
        try:
            answer = self._resolver(question)
        except Exception:
            return False
        return isinstance(answer, DependencyAnswer) and answer.action == TAKE_OUT
