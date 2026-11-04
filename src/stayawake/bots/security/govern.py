#!/usr/bin/env python3
"""`saw govern` orchestration — check an incoming git or GitHub update in a holding directory before
the open folder changes.

`prepare` materialises the update outside the open folder (via `lib.git.incoming`), scans only what
arrived with the operator's allowlist, and records the result so `apply` can act on it later. `apply`
makes the open folder match a checked tree, without fetching again. Both return `(payload, exit)`;
the payload is stamped with the schema by the CLI.
"""
from __future__ import annotations

import json
from pathlib import Path

from stayawake.bots.security.hook_policy import operator_policy
from stayawake.bots.security.models import CLEAN, RESIDUE_VERDICT, ScanReport
from stayawake.bots.security.scanner import scan_target
from stayawake.bots.security.sinks.json_sink import _in_plain_words
from stayawake.bots.security.targets.local import LocalRepoTarget
from stayawake.lib.git import incoming
from stayawake.utils import exitcodes
from stayawake.utils.timeutil import now_iso

SCHEMA = 1
_STATE = "state.json"

TOOLS = ("gh", "git")


def is_recognised(tool: str, args: list[str]) -> bool:
    """Whether `(tool, args)` is an incoming command saw governs. Takes the tool and the operator's
    arguments without the program name. Returns the answer."""
    return incoming.classify(tool, list(args)) is not None


def prepare(repo: str, into: str, tool: str, args: list[str], config: str | None = None) -> tuple[dict, int]:
    """Materialise the update outside the open folder and scan what arrived. Returns `(payload,
    exit)`: `{"scan": <document>}` with the scan's own exit, or `{"reason": <sentence>}` and
    INCOMPLETE, in which case nothing is recorded and the update must be held."""
    arrived = incoming.prepare(Path(repo), Path(into), tool, list(args))
    if isinstance(arrived, str):
        return {"reason": arrived}, exitcodes.INCOMPLETE
    try:
        payload, code = _scan_arrived(arrived.root, arrived.paths, config)
    except ValueError as exc:
        return {"reason": str(exc) or "the check could not use your config"}, exitcodes.INCOMPLETE
    except OSError:
        return {"reason": "the check could not finish"}, exitcodes.INCOMPLETE
    releasable = code == exitcodes.CLEAN and _verdict(payload) in {CLEAN, RESIDUE_VERDICT}
    _write_state(Path(into), arrived, releasable)
    return {"scan": payload}, code


def apply(repo: str, into: str) -> tuple[dict, int]:
    """Make the open folder match the checked tree recorded by `prepare`, without fetching again.
    Returns `(payload, exit)`: `{"applied": true}`, or `{"applied": false, "reason": <sentence>}`
    with the open folder unchanged."""
    state = _read_state(Path(into))
    if state is None:
        return _applied(False, "there is no checked update to apply")
    if not state.get("releasable"):
        return _applied(False, "the check cannot be applied")
    try:
        arrived = incoming.Arrived(
            root=Path(state["root"]), paths=tuple(state["paths"]), mode=state["mode"],
            commit=state["commit"], base=state["base"], head=state["head"],
            refs=tuple(tuple(item) for item in state["refs"]))
    except (KeyError, TypeError):
        return _applied(False, "the checked update could not be read")
    reason = incoming.apply(Path(repo), Path(into), arrived)
    return _applied(not reason, reason)


def _scan_arrived(root: Path, paths: tuple[str, ...], config: str | None) -> tuple[dict, int]:
    policy = operator_policy(config)
    with LocalRepoTarget(str(root), str(root), policy.opts, include_only=paths) as target:
        result = scan_target(target, policy.signatures, policy.allowlist)
    report = ScanReport(generated_at=now_iso(), results=[result])
    if report.any_infected:
        code = exitcodes.FINDINGS
    elif report.any_error:
        code = exitcodes.INCOMPLETE
    else:
        code = exitcodes.CLEAN
    return _in_plain_words(report.to_payload()), code


def _verdict(payload: dict) -> str:
    results = payload.get("results") or []
    if results and isinstance(results[0], dict) and isinstance(results[0].get("verdict"), str):
        return results[0]["verdict"]
    return ""


def _applied(done: bool, sentence: str) -> tuple[dict, int]:
    body: dict = {"applied": done}
    if sentence:
        body["reason"] = sentence
    return body, exitcodes.CLEAN if done else exitcodes.INCOMPLETE


def _write_state(into: Path, arrived: "incoming.Arrived", releasable: bool) -> None:
    body = {"schema": SCHEMA, "releasable": releasable, "root": str(arrived.root),
            "paths": list(arrived.paths), "mode": arrived.mode, "commit": arrived.commit,
            "base": arrived.base, "head": arrived.head, "refs": [list(i) for i in arrived.refs]}
    path = Path(into) / _STATE
    temporary = path.with_suffix(".json.tmp")
    temporary.write_text(json.dumps(body), encoding="utf-8")
    temporary.replace(path)


def _read_state(into: Path) -> dict | None:
    try:
        loaded = json.loads((Path(into) / _STATE).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    return loaded if isinstance(loaded, dict) else None
