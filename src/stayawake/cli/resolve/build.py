#!/usr/bin/env python3
"""Build the interactive resolver, or None when asking the operator is not appropriate.

Asking is built only when both streams are a real terminal and the run is not CI, unless
`--ask=jsonl` is set, in which case a program answers on those streams. The run-shape half
of the gate — a single local repository, never a remote or parallel run — lives with the remediator.
"""
from __future__ import annotations

import sys
from typing import TextIO

from stayawake.bots.security.pr.resolve import (UNANSWERED, DeliveryAnswer, DeliveryQuestion,
                                                DependencyAnswer, DependencyQuestion, Resolution)
from stayawake.cli.resolve.ask import ask_delivery, ask_dependency, ask_resolution
from stayawake.cli.resolve.jsonl import ask_json
from stayawake.utils import prompt


def _remember(decisions, question, answer) -> None:
    """Record one accepted choice. Takes the list, or None, the question and the answer."""
    if decisions is None:
        return
    if isinstance(question, DeliveryQuestion):
        if not isinstance(answer, DeliveryAnswer) or answer.action == UNANSWERED:
            return
        decisions.append({"kind": "delivery", "action": answer.action,
                          "chosen": list(answer.chosen)})
        return
    if isinstance(question, DependencyQuestion):
        if not isinstance(answer, DependencyAnswer) or answer.action == UNANSWERED:
            return
        decisions.append({"kind": "package", "name": question.name, "action": answer.action})
        return
    if isinstance(answer, Resolution):
        decisions.append({"kind": "file", "path": question.path, "action": answer.action})


def build_resolver(stdin: TextIO | None = None,
                   stderr: TextIO | None = None, *,
                   ask: str | None = None,
                   decisions: list | None = None):
    """Build a resolver that asks about each uncertain file, each delivery and each known-malicious
    package. Takes the input and prompt streams, the process's own by default, `ask` (`jsonl` to
    let a program answer), and a list that receives each choice that was made. Returns the resolver,
    or None when nobody is asked."""
    stdin = sys.stdin if stdin is None else stdin
    stderr = sys.stderr if stderr is None else stderr
    jsonl = ask == "jsonl"
    if not jsonl and not prompt.attended(stdin, stderr):
        return None

    def resolve(question):
        if jsonl:
            answer = ask_json(question, stdin=stdin, stderr=stderr)
        elif isinstance(question, DeliveryQuestion):
            answer = ask_delivery(question, stdin=stdin, stderr=stderr)
        elif isinstance(question, DependencyQuestion):
            answer = ask_dependency(question, stdin=stdin, stderr=stderr)
        else:
            answer = ask_resolution(question, stdin=stdin, stderr=stderr)
        _remember(decisions, question, answer)
        return answer

    return resolve
