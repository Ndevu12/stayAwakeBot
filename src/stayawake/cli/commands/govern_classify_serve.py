#!/usr/bin/env python3
"""`saw govern classify --serve` — answer one classify request per line of a stream, each exactly as
`saw govern classify --json` answers that command run in the request's environment."""
from __future__ import annotations

import json
import os
import sys
from dataclasses import dataclass
from typing import BinaryIO, Callable

from stayawake.utils import env, textsafe
from stayawake.utils.json_documents import versioned

Answer = Callable[[str, str, list[str]], dict]
"""Answers one command: takes the folder, the tool and the arguments, and returns the document
`saw govern classify --json` prints, read in this process's environment."""


@dataclass(frozen=True)
class Request:
    """One command to classify: the tool, the folder it runs in, its arguments without the program
    name and the whole environment it runs with."""

    tool: str
    repo: str
    argv: tuple[str, ...]
    environment: dict[str, str]


def run(answer: Answer, tools: tuple[str, ...]) -> None:
    """Answer the requests on this process's stdin on its stdout until stdin ends. Commands the
    answers run read no stdin and write no stdout. Takes the classify answer and the tools it
    reads."""
    sys.stdout.flush()
    requests = os.fdopen(os.dup(sys.stdin.fileno()), "rb")
    answers = os.fdopen(os.dup(sys.stdout.fileno()), "wb")
    nothing = os.open(os.devnull, os.O_RDONLY)
    os.dup2(nothing, sys.stdin.fileno())
    os.close(nothing)
    os.dup2(sys.stderr.fileno(), sys.stdout.fileno())
    with requests, answers:
        serve(answer, tools, requests, answers)


def serve(answer: Answer, tools: tuple[str, ...], requests: BinaryIO, answers: BinaryIO) -> None:
    """Write one answer line for each request line, flushed, until the requests end. Takes the
    classify answer, the tools it reads, the request stream and the answer stream."""
    for line in iter(requests.readline, b""):
        answers.write(json.dumps(answered(line, answer, tools)).encode("ascii") + b"\n")
        answers.flush()


def answered(line: bytes, answer: Answer, tools: tuple[str, ...]) -> dict:
    """Answer one request line. Takes the line, the classify answer and the tools it reads. Returns
    the classify document, or a document with the reason the request was not answered, carrying
    the request's `id` when it has one."""
    try:
        raw = json.loads(line)
    except ValueError as error:
        return versioned("govern", {"reason": f"the request is not JSON: {error}"})
    request = read_request(raw, tools)
    if isinstance(request, str):
        return _echoing_id(versioned("govern", {"reason": request}), raw)
    try:
        with env.running_in(request.environment):
            document = answer(request.repo, request.tool, list(request.argv))
    except Exception as error:                    # noqa: BLE001 — one request never ends the others
        reason = textsafe.plain(f"{type(error).__name__}: {error}", limit=300)
        document = versioned("govern", {"reason": f"the command did not complete. {reason}"})
    return _echoing_id(document, raw)


def read_request(raw: object, tools: tuple[str, ...]) -> Request | str:
    """Read a parsed request line. Takes it and the tools classify reads. Returns the request, or
    the reason it cannot be answered."""
    if not isinstance(raw, dict):
        return "a request is a JSON object with tool, repo, argv and environment"
    tool, repo, argv, environment = (raw.get(name) for name in ("tool", "repo", "argv", "environment"))
    if tool not in tools:
        return f"tool must be one of: {', '.join(tools)}"
    if not isinstance(repo, str) or not os.path.isabs(repo):
        return "repo must name the folder the command runs in by its full path"
    if not isinstance(argv, list) or not all(isinstance(arg, str) for arg in argv):
        return "argv must list the command's arguments, without the program name, as text"
    if not isinstance(environment, dict) or not all(isinstance(value, str) for value in environment.values()):
        return "environment must map each variable the command runs with to its value as text"
    if any(not name or "=" in name for name in environment):
        return "an environment variable's name is empty or holds ="
    if any("\0" in text for text in (repo, *argv, *environment, *environment.values())):
        return "a request holds a NUL character, which no command line or environment carries"
    return Request(tool, repo, tuple(argv), dict(environment))


def _echoing_id(document: dict, raw: object) -> dict:
    """Put the request's `id`, when it has one, right after the schema version. Takes the document
    and the parsed request. Returns the document."""
    if not isinstance(raw, dict) or "id" not in raw:
        return document
    version, *rest = document.items()
    return dict([version, ("id", raw["id"]), *rest])
