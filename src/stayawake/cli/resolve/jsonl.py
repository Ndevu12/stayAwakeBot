#!/usr/bin/env python3
"""Ask one question as a JSON object on stderr and read one answer from stdin.

A wrong id, an illegal action, or an unreadable replacement path is not an answer. The question is
repeated up to three times, then given up the way end of input is. End of input gives up at once.
"""
from __future__ import annotations

import hashlib
import json
import uuid
from typing import Callable, TextIO

from stayawake.bots.security.pr.resolve import (KEEP, REMOVE, RESTORE, SUPPLY, TAKE_OUT,
                                                UNANSWERED, DeliveryAnswer, DeliveryQuestion,
                                                DependencyAnswer, DependencyQuestion, Resolution,
                                                UncertainItem)
from stayawake.cli.resolve.ask import read_supplied_file
from stayawake.cli.resolve.render import content_withheld
from stayawake.utils.json_documents import FIX_ASK_SCHEMA_VERSION

_TRIES = 3


def _emit(stderr: TextIO, payload: dict) -> None:
    """Write one question and flush it. Takes the stream and the object."""
    stderr.write(json.dumps(payload, ensure_ascii=False) + "\n")
    stderr.flush()


def _object(line: str, expected: str) -> dict | None:
    """Read one answer line. Takes the line and the question id. Returns the object when it names
    that id and an action, or None when it is not an answer."""
    try:
        obj = json.loads(line)
    except ValueError:
        return None
    if not isinstance(obj, dict) or obj.get("id") != expected or not isinstance(obj.get("action"), str):
        return None
    return obj


def _read(stdin: TextIO, stderr: TextIO, payload: dict,
          accept: Callable[[dict], dict | None]) -> dict | None:
    """Write `payload` and read one accepted answer. Takes the streams, the question and `accept`,
    which returns the answer or None when it is not one. Returns the answer, or None when giving up."""
    for _ in range(_TRIES):
        _emit(stderr, payload)
        try:
            line = stdin.readline()
        except (OSError, ValueError):
            return None
        if line == "":
            return None
        obj = _object(line, payload["id"])
        if obj is None:
            continue
        accepted = accept(obj)
        if accepted is not None:
            return accepted
    return None


def _file_payload(item: UncertainItem, question_id: str) -> dict:
    """One file question. Takes the item and its id. Returns the object, without the file's bytes."""
    payload = {
        "schema_version": FIX_ASK_SCHEMA_VERSION,
        "id": question_id,
        "kind": "file",
        "path": item.path,
        "category": item.category,
        "signature_id": item.signature_id,
        "description": item.description,
        "confirmed": bool(item.confirmed),
        "introduced_by": item.commit or item.introduced_by,
        "arrived_with_removed": list(item.arrived_with_removed),
        "origin_unread": bool(item.origin_unread),
        "supply": bool(item.keep_content),
        "sha256": hashlib.sha256(item.preview).hexdigest(),
        "withheld": content_withheld(item),
    }
    if item.restore_candidate is not None:
        payload["restore"] = {"commit": item.restore_commit or item.restore_source,
                              "blob": item.restore_candidate[1]}
    return payload


def _ask_file(item: UncertainItem, stdin: TextIO, stderr: TextIO) -> Resolution:
    """Ask about one file. Takes the item and the streams. Returns the resolution; giving up keeps it."""
    payload = _file_payload(item, uuid.uuid4().hex)

    def accept(obj: dict) -> dict | None:
        action = obj["action"]
        if action in (REMOVE, KEEP):
            return obj
        if action == RESTORE and item.restore_candidate is not None:
            return obj
        if action == SUPPLY and item.keep_content and isinstance(obj.get("path"), str):
            content = read_supplied_file(obj["path"])
            if content is None:
                return None
            return {**obj, "_bytes": content}
        return None

    answer = _read(stdin, stderr, payload, accept)
    if answer is None:
        return Resolution(KEEP)
    if answer["action"] == RESTORE:
        return Resolution(RESTORE, restore=item.restore_candidate)
    if answer["action"] == SUPPLY:
        return Resolution(SUPPLY, supply=answer["_bytes"])
    if answer["action"] == REMOVE:
        return Resolution(REMOVE)
    return Resolution(KEEP)


def _delivery_payload(question: DeliveryQuestion, question_id: str) -> dict:
    """One delivery question. Takes the question and its id. Returns the object."""
    counts = dict(question.named_by)
    files = []
    for arrived in question.files:
        entry = {"path": arrived.path, "blob": arrived.blob}
        if arrived.path in counts:
            entry["named_by"] = counts[arrived.path]
        files.append(entry)
    return {
        "schema_version": FIX_ASK_SCHEMA_VERSION,
        "id": question_id,
        "kind": "delivery",
        "commit": question.commit,
        "known_as": list(question.known_as),
        "date": question.date,
        "subject": question.subject,
        "recorded": bool(question.recorded),
        "removing": list(question.removing),
        "files": files,
        "changed": list(question.changed),
    }


def _ask_delivery(question: DeliveryQuestion, stdin: TextIO, stderr: TextIO) -> DeliveryAnswer:
    """Ask about one delivery. Takes the question and the streams. Returns the answer; giving up
    leaves it unanswered."""
    offered = {arrived.path for arrived in question.files}
    payload = _delivery_payload(question, uuid.uuid4().hex)

    def accept(obj: dict) -> dict | None:
        if obj["action"] == KEEP:
            return obj
        if obj["action"] != TAKE_OUT:
            return None
        chosen = obj.get("chosen")
        if (not isinstance(chosen, list) or not chosen
                or not all(isinstance(path, str) and path in offered for path in chosen)):
            return None
        return obj

    answer = _read(stdin, stderr, payload, accept)
    if answer is None or answer["action"] == KEEP:
        return DeliveryAnswer(UNANSWERED if answer is None else KEEP)
    return DeliveryAnswer(TAKE_OUT, tuple(dict.fromkeys(answer["chosen"])))


def _package_payload(question: DependencyQuestion, question_id: str) -> dict:
    """One package question. Takes the question and its id. Returns the object."""
    proposed = dict(question.proposed)
    manifests = []
    for path in question.declared_in:
        entry = {"path": path}
        if path in proposed:
            entry["proposed"] = proposed[path]
        manifests.append(entry)
    return {
        "schema_version": FIX_ASK_SCHEMA_VERSION,
        "id": question_id,
        "kind": "package",
        "name": question.name,
        "versions": list(question.versions),
        "manifests": manifests,
    }


def _ask_package(question: DependencyQuestion, stdin: TextIO, stderr: TextIO) -> DependencyAnswer:
    """Ask about one package. Takes the question and the streams. Returns the answer; giving up
    leaves it unanswered."""
    payload = _package_payload(question, uuid.uuid4().hex)

    def accept(obj: dict) -> dict | None:
        if obj["action"] in (KEEP, TAKE_OUT):
            return obj
        return None

    answer = _read(stdin, stderr, payload, accept)
    if answer is None:
        return DependencyAnswer(UNANSWERED)
    return DependencyAnswer(answer["action"])


def ask_json(question, *, stdin: TextIO, stderr: TextIO):
    """Ask `question` on the JSON channel. Takes the question and the streams. Returns the same
    answer the terminal would."""
    if isinstance(question, DeliveryQuestion):
        return _ask_delivery(question, stdin, stderr)
    if isinstance(question, DependencyQuestion):
        return _ask_package(question, stdin, stderr)
    return _ask_file(question, stdin, stderr)
