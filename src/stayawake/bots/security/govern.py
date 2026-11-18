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
import shutil
from pathlib import Path

from stayawake.bots.security import clean_ledger, govern_status
from stayawake.bots.security.hook_policy import operator_policy
from stayawake.bots.security.models import CLEAN, RESIDUE_VERDICT, ScanReport
from stayawake.bots.security.scanner import scan_target
from stayawake.bots.security.sinks.json_sink import _in_plain_words
from stayawake.bots.security.targets.local import LocalRepoTarget
from stayawake.lib.git import incoming
from stayawake.lib.git.run import UNTRUSTED, stdout
from stayawake.lib.git.write.working_tree import uncommitted_paths
from stayawake.utils import exitcodes, pathsafe, scratch
from stayawake.utils.pace import DeadlineReached, Pace
from stayawake.utils.progress_events import current
from stayawake.utils.timeutil import now_iso

SCHEMA = 1
_STATE = "state.json"

TOOLS = ("gh", "git")


DECISION_CHOICES = ("run-as-typed", "leave-unchanged")

def is_recognised(tool: str, args: list[str]) -> bool:
    """Whether `(tool, args)` is an incoming command saw governs. Takes the tool and the operator's
    arguments without the program name. Returns the answer."""
    return incoming.classify(tool, list(args)) is not None


def prepare(repo: str, into: str, tool: str, args: list[str], config: str | None = None, *,
            deadline: float | None = None) -> tuple[dict, int]:
    """Materialise the update outside the open folder and scan what arrived. Returns `(payload,
    exit)`: `{"scan": <document>}` with the scan's own exit, or, when the update could not be
    checked, `{"reason": <sentence>, "decision": ...}` and INCOMPLETE, leaving the user to run the
    command as typed or leave the folder unchanged."""
    govern_status.write(repo, "checking", step="checking the incoming update")
    current().step("materialise", "checking the incoming update")
    arrived = incoming.prepare(Path(repo), Path(into), tool, list(args))
    if isinstance(arrived, str):
        return _unchecked(repo, arrived)
    current().step("scan", "scanning what arrived")
    govern_status.write(repo, "checking", step="scanning what arrived")
    try:
        payload, code = _scan_arrived(arrived.root, arrived.paths, config, deadline)
    except DeadlineReached:
        return _unchecked(repo, "the check did not finish before its deadline")
    except ValueError as exc:
        return _unchecked(repo, str(exc) or "the check could not use your config")
    except OSError:
        return _unchecked(repo, "the check could not finish")
    verdict = _verdict(payload) or "incomplete"
    current().step("verdict", "verdict: %s" % verdict)
    releasable = code == exitcodes.CLEAN and _verdict(payload) in {CLEAN, RESIDUE_VERDICT}
    strictly_clean = code == exitcodes.CLEAN and _verdict(payload) == CLEAN
    applied_mark = clean_ledger.clean_key(arrived.commit, config) if releasable else None
    clean_mark = applied_mark if strictly_clean else None
    if releasable:
        govern_status.write(repo, "checking", verdict=verdict, step="checked; ready to apply")
    else:
        govern_status.write(repo, "held", verdict=verdict,
                            reasons=["the update was not applied; the open folder is unchanged"])
    _write_state(Path(into), arrived, releasable, clean_mark, applied_mark, verdict)
    return {"scan": payload}, code


def _unchecked(repo: str, reason: str) -> tuple[dict, int]:
    """Answer an update saw could not check, leaving the decision to the user. Takes the open folder
    and the reason. Returns the payload and INCOMPLETE."""
    govern_status.write(repo, "finished", reasons=[reason])
    decision = {"choices": list(DECISION_CHOICES), "scan_after": ["saw", "scan", str(repo)]}
    return {"reason": reason, "decision": decision}, exitcodes.INCOMPLETE


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
    current().step("apply", "applying the checked update")
    govern_status.write(repo, "checking", step="applying the checked update")
    reason = incoming.apply(Path(repo), Path(into), arrived)
    if not reason:
        if state.get("clean_mark"):
            clean_ledger.remember(Path(repo), state["clean_mark"])  # strictly-clean scan cache
        if state.get("applied_mark"):
            clean_ledger.remember_applied(Path(repo), state["applied_mark"])  # clean or residue
        govern_status.write(repo, "applied", verdict=state.get("verdict"))
    else:
        govern_status.write(repo, "finished", reasons=[reason])
    return _applied(not reason, reason)


def verdict(repo: str, config: str | None = None) -> tuple[dict, int]:
    """Answer whether the open folder's current tree is one saw let in. Takes the open folder and the
    operator config. Returns `(payload, exit)`; `governed` is `let-in` (scanned clean by a hook, or
    applied by govern, clean or residue, with the tree still matching), `not-let-in` (an unknown
    commit, or a working tree changed on top of one saw let in), or `could-not-answer`."""
    root = Path(repo)
    head = stdout(root, ["rev-parse", "--verify", "--quiet", "HEAD"], context=UNTRUSTED).strip() or None
    let_in = clean_ledger.let_in_commit(root, config)
    if not head:
        return _governed("could-not-answer", "could-not-answer", "the open folder has no commit yet",
                         head, let_in), exitcodes.INCOMPLETE
    if not clean_ledger.governed(root, clean_ledger.clean_key(head, config)):
        return _governed("not-let-in", "unknown-commit", "this tree is not one saw let in",
                         head, let_in), exitcodes.FINDINGS
    changed = uncommitted_paths(root)
    if changed is None:
        return _governed("could-not-answer", "could-not-answer", "the working tree could not be read",
                         head, let_in), exitcodes.INCOMPLETE
    if changed:
        return _governed("not-let-in", "tree-changed",
                         "the working tree changed on top of a tree saw let in",
                         head, let_in), exitcodes.FINDINGS
    return _governed("let-in", "let-in", "this tree is one saw let in", head, let_in), exitcodes.CLEAN


def _governed(verdict: str, code: str, sentence: str,
              head: str | None = None, let_in: str | None = None) -> dict:
    body = {"governed": verdict, "code": code, "reason": sentence}
    if head:
        body["head"] = head
    if let_in:
        body["let_in"] = let_in
    return body


def restore(repo: str, config: str | None = None) -> tuple[dict, int]:
    """Put the open folder back on the commit saw let in, keeping uncommitted work. Takes the open
    folder and the operator config. Returns `(payload, exit)`: `{"restored": true, "commit": <id>}`,
    or `{"restored": false, "reason": <sentence>}` with the open folder unchanged. Writes the same
    record as a check: putting back, then applied or finished."""
    let_in = clean_ledger.let_in_commit(Path(repo), config)
    if not let_in:
        reason = "saw has not let a tree into this folder, so there is nothing to put back"
        govern_status.write(repo, "finished", reasons=[reason])
        return {"restored": False, "reason": reason}, exitcodes.INCOMPLETE
    govern_status.write(repo, "checking", step="putting the folder back")
    reason = incoming.restore(Path(repo), let_in)
    if reason:
        govern_status.write(repo, "finished", reasons=[reason])
        return {"restored": False, "reason": reason}, exitcodes.INCOMPLETE
    govern_status.write(repo, "applied", verdict="clean")
    return {"restored": True, "commit": let_in}, exitcodes.CLEAN


def _scan_arrived(root: Path, paths: tuple[str, ...], config: str | None,
                  deadline: float | None = None) -> tuple[dict, int]:
    policy = operator_policy(config)
    files = _plain_copy(Path(root), paths)
    with Pace(current(), deadline) as pace:
        pace.plan(str(root), files=len(paths), size=pathsafe.regular_size(files, paths), commits=0, workers=1)
        pace.begin(str(root), "files", len(paths), counted=False)
        try:
            with LocalRepoTarget(str(files), str(files), policy.opts, include_only=paths) as target:
                result = scan_target(target, policy.signatures, policy.allowlist)
        except KeyboardInterrupt:
            if pace.expired:
                raise DeadlineReached from None
            raise
    report = ScanReport(generated_at=now_iso(), results=[result])
    if report.any_infected:
        code = exitcodes.FINDINGS
    elif report.any_error:
        code = exitcodes.INCOMPLETE
    else:
        code = exitcodes.CLEAN
    return _in_plain_words(report.to_payload()), code


def _plain_copy(root: Path, paths: tuple[str, ...]) -> Path:
    """Copy the arrived files into a directory of their own, so they are scanned as content and not
    as the borrowed repository they were produced in. Takes the work tree and the arrived paths;
    returns the directory."""
    where = scratch.new_dir("the files an update brought in")
    for rel in paths:
        destination = where / rel
        destination.parent.mkdir(parents=True, exist_ok=True)
        try:
            shutil.copyfile(root / rel, destination)
        except OSError:
            pass
    return where


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


def _write_state(into: Path, arrived: "incoming.Arrived", releasable: bool,
                 clean_mark: str | None = None, applied_mark: str | None = None,
                 verdict: str | None = None) -> None:
    body = {"schema": SCHEMA, "releasable": releasable, "root": str(arrived.root),
            "paths": list(arrived.paths), "mode": arrived.mode, "commit": arrived.commit,
            "base": arrived.base, "head": arrived.head, "refs": [list(i) for i in arrived.refs],
            "clean_mark": clean_mark, "applied_mark": applied_mark, "verdict": verdict}
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
