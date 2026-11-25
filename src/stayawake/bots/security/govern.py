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

from stayawake.bots.security import clean_ledger, govern_held, govern_status
from stayawake.bots.security.hook_policy import operator_policy
from stayawake.bots.security.models import CLEAN, INFECTED, RESIDUE_VERDICT, ScanReport, ScanResult
from stayawake.bots.security.scanner import joined, scan_target, unreadable
from stayawake.bots.security.found import described
from stayawake.bots.security.sinks.json_sink import _in_plain_words
from stayawake.bots.security.targets.local import LocalRepoTarget
from stayawake.lib.git import blob_copies, incoming, query
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
    """Materialise the update outside the open folder and scan what arrived. Takes the open folder,
    the holding directory, the tool, the arguments, the config and the deadline. Returns the answer
    and its exit: a passthrough, a scan, or a reason with a decision."""
    if incoming.brings_nothing(tool, args):
        return {"passthrough": True, "reason": "the command brings no files in"}, exitcodes.CLEAN
    govern_status.write(repo, "checking", step="checking the incoming update")
    current().step("materialise", "checking the incoming update")
    arrived = incoming.prepare(Path(repo), Path(into), tool, list(args))
    if isinstance(arrived, str):
        return _unchecked(repo, arrived)
    current().step("scan", "scanning what arrived")
    govern_status.write(repo, "checking", step="scanning what arrived")
    try:
        landing = blob_copies.copy_out_as_written(Path(repo).resolve(), arrived.root, arrived.commit,
                                                  arrived.paths, "the files an update brought in")
        payload, code, already_there = _scan_arrived(arrived.root, landing, arrived.paths, config,
                                                     arrived.base, deadline)
    except DeadlineReached:
        return _unchecked(repo, "the check did not finish before its deadline")
    except ValueError as exc:
        return _unchecked(repo, str(exc) or "the check could not use your config")
    except OSError:
        return _unchecked(repo, "the check could not finish")
    verdict = _verdict(payload) or "incomplete"
    current().step("verdict", "verdict: %s" % verdict)
    scanned_clean = code == exitcodes.CLEAN and _verdict(payload) in {CLEAN, RESIDUE_VERDICT}
    strictly_clean = code == exitcodes.CLEAN and _verdict(payload) == CLEAN and not already_there
    applied_mark = clean_ledger.clean_key(arrived.commit, config) if scanned_clean else None
    clean_mark = applied_mark if strictly_clean else None
    hooks = query.hook_files(Path(repo), arrived.paths)
    asks = scanned_clean and (hooks is None or bool(hooks))
    releasable = scanned_clean and not asks
    if releasable:
        govern_status.write(repo, "checking", verdict=verdict, step="checked; ready to apply")
    else:
        govern_status.write(repo, "held", verdict=verdict,
                            reasons=["the update was not applied; the open folder is unchanged"])
    _write_state(Path(into), arrived, releasable, clean_mark, applied_mark, verdict, dict(landing.digests), asks)
    answer: dict = {"scan": payload}
    if already_there:
        answer["pre_existing"] = already_there
    findings = (payload.get("results") or [{}])[0].get("findings") or []
    steps = govern_held.next_steps(verdict, findings, already_there, arrived.commit)
    if asks:
        steps.append(f"The update changes {', '.join(hooks or ('the folder git runs hooks from',))}, which "
                     f"git runs as a hook in this folder. Check it, then let {arrived.commit[:12]} in.")
    if steps:
        answer["next_steps"] = steps
    if not releasable and (asks or verdict in govern_held.HELD_VERDICTS):
        answer["decision"] = govern_held.decision(repo, into, arrived.commit, verdict)
    elif not releasable:
        answer["decision"] = _unchecked(repo, "")[0]["decision"]
    return answer, code


def _unchecked(repo: str, reason: str) -> tuple[dict, int]:
    """Answer an update saw could not check, leaving the decision to the user. Takes the open folder
    and the reason. Returns the payload and INCOMPLETE."""
    govern_status.write(repo, "finished", reasons=[reason])
    decision = {"choices": list(DECISION_CHOICES), "scan_after": ["saw", "scan", str(repo)]}
    return {"reason": reason, "decision": decision}, exitcodes.INCOMPLETE


def apply(repo: str, into: str, accept: str | None = None, confirm: str | None = None) -> tuple[dict, int]:
    """Make the open folder match the checked tree, without fetching again. Takes the open folder,
    the holding directory, the accepted commit and the typed confirmation. Returns whether it was
    applied, the reason when not, and the exit."""
    state = _read_state(Path(into))
    if state is None:
        return _applied(False, "there is no checked update to apply")
    accepted_verdict = None
    if not state.get("releasable"):
        refused = _refuse_let_in(repo, state, accept, confirm)
        if refused:
            return _applied(False, refused)
        accepted_verdict = state.get("verdict") if state.get("verdict") in govern_held.HELD_VERDICTS else None
    try:
        arrived = incoming.Arrived(
            root=Path(state["root"]), paths=tuple(state["paths"]), mode=state["mode"],
            commit=state["commit"], base=state["base"], head=state["head"],
            refs=tuple(tuple(item) for item in state["refs"]),
            written=tuple((state.get("written") or {}).items()))
    except (KeyError, TypeError):
        return _applied(False, "the checked update could not be read")
    current().step("apply", "applying the checked update")
    govern_status.write(repo, "checking", step="applying the checked update")
    reason = incoming.apply(Path(repo), Path(into), arrived)
    if not reason and accepted_verdict:
        clean_ledger.remember_accepted(Path(repo), state["commit"], accepted_verdict)
        govern_status.write(repo, "applied", verdict=accepted_verdict,
                            reasons=[f"you let in an update saw found {accepted_verdict}"])
    elif not reason:
        if state.get("clean_mark"):
            clean_ledger.remember(Path(repo), state["clean_mark"])  # strictly-clean scan cache
        if state.get("applied_mark"):
            clean_ledger.remember_applied(Path(repo), state["applied_mark"])  # clean or residue
        govern_status.write(repo, "applied", verdict=state.get("verdict"))
    else:
        govern_status.write(repo, "finished", reasons=[reason])
    return _applied(not reason, reason)


def _refuse_let_in(repo: str, state: dict, accept: str | None, confirm: str | None) -> str:
    """Return why a held update cannot be let in, or an empty string when it can. Takes the open
    folder, the recorded check, the accepted commit and the typed confirmation."""
    if state.get("verdict") not in govern_held.HELD_VERDICTS and not state.get("asks"):
        return "the check did not finish, so there is nothing checked to let in"
    if not accept:
        return "saw held this update; review it, then let it in with --accept and its commit"
    if accept != state.get("commit"):
        return "this is not the update saw checked; check it again"
    if state.get("verdict") == INFECTED and confirm != govern_held.folder_name(repo):
        return "to let in an infected update, type the folder's name with --confirm"
    return ""


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
    accepted = clean_ledger.accepted_verdict(root, head)
    if accepted:
        return _governed("not-let-in", "let-in-by-you",
                         f"you let this tree in although saw found it {accepted}",
                         head, let_in), exitcodes.FINDINGS
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


def _scan_files(files: Path, paths: tuple[str, ...], policy) -> ScanResult:
    with LocalRepoTarget(str(files), str(files), policy.opts, include_only=paths) as target:
        return scan_target(target, policy.signatures, policy.allowlist)


def _scan_arrived(root: Path, landing: "blob_copies.BlobCopies", paths: tuple[str, ...], config: str | None,
                  base: str | None = None, deadline: float | None = None) -> tuple[dict, int, list[dict]]:
    """Scan the files an update brought, as they will be written, within `deadline` seconds when
    given. Takes the holding work tree, the copies of what lands, the arrived paths, the operator
    config, the commit the folder had before and the deadline. Returns the scan document, its exit,
    and the findings the folder already had before the update, which do not count toward the
    verdict. Raises DeadlineReached at the deadline."""
    policy = operator_policy(config)
    size = sum(pathsafe.regular_size(folder, names) for folder, names in landing.folders)
    already = []
    with Pace(current(), deadline) as pace:
        pace.plan(str(root), files=len(paths), size=size, commits=0, workers=1)
        pace.begin(str(root), "files", len(paths), counted=False)
        try:
            result = _scan_copies(landing, policy)
            if base and result.findings:
                before = blob_copies.copy_out(Path(root), base, paths,
                                              "the files an update changed, as they were before")
                already = govern_held.set_aside_already_there(result, _scan_copies(before, policy))
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
    already_there = []
    for finding in already:
        body = finding.to_dict()
        body["description"] = described(body.get("signature_id", ""), body.get("category", ""),
                                        body.get("description"))
        body["pre_existing"] = True
        already_there.append(body)
    return _in_plain_words(report.to_payload()), code, already_there


def _scan_copies(copies: "blob_copies.BlobCopies", policy) -> ScanResult:
    """Scan each folder of copied files and join the results. Takes the copies and the operator's
    policy. Returns one result, errored when a file could not be copied."""
    result = None
    for folder, names in copies.folders:
        found = _scan_files(folder, names, policy)
        result = found if result is None else joined(result, found)
    if result is None:
        result = _scan_files(scratch.new_dir("the files an update brought in"), (), policy)
    if copies.not_copied:
        result.error = result.error or unreadable(copies.not_copied)
    return result


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
                 verdict: str | None = None, written: dict | None = None, asks: bool = False) -> None:
    body = {"schema": SCHEMA, "releasable": releasable, "root": str(arrived.root),
            "paths": list(arrived.paths), "mode": arrived.mode, "commit": arrived.commit,
            "base": arrived.base, "head": arrived.head, "refs": [list(i) for i in arrived.refs],
            "clean_mark": clean_mark, "applied_mark": applied_mark, "verdict": verdict,
            "written": written or {}, "asks": asks}
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
