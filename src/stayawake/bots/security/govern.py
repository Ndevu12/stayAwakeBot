#!/usr/bin/env python3
"""`saw govern` orchestration — check an incoming git or GitHub update in a holding directory before
the open folder changes.

`prepare` materialises the update outside the open folder (via `lib.git.incoming`), scans only what
arrived with the operator's allowlist, and records the result so `apply` can act on it later. `apply`
makes the open folder match a checked tree, without fetching again. Both return `(payload, exit)`;
the payload is stamped with the schema by the CLI.
"""
from __future__ import annotations

import dataclasses
import json
from pathlib import Path

from stayawake.bots.security import clean_ledger, govern_carried, govern_held, govern_status
from stayawake.bots.security.hook_policy import operator_policy
from stayawake.bots.security.models import CLEAN, INFECTED, RESIDUE_VERDICT, ScanReport, ScanResult
from stayawake.bots.security.scanner import joined, scan_target, unreadable
from stayawake.bots.security.found import described
from stayawake.bots.security.sinks.json_sink import _in_plain_words
from stayawake.bots.security.targets.local import LocalRepoTarget
from stayawake.lib.git import blob_copies, conflicted, incoming, query
from stayawake.lib.git.run import UNTRUSTED, stdout
from stayawake.lib.git.write.working_tree import uncommitted_paths
from stayawake.utils import exitcodes, pathsafe, scratch
from stayawake.utils.pace import DeadlineReached, Pace
from stayawake.utils.progress_events import current
from stayawake.utils.timeutil import now_iso

SCHEMA = 1
_STATE = "state.json"

TOOLS = ("gh", "git")


LEAVE_UNCHANGED = "leave-unchanged"
DECISION_CHOICES = ("run-as-typed", LEAVE_UNCHANGED)

def is_recognised(tool: str, args: list[str]) -> bool:
    """Whether `(tool, args)` is an incoming command saw governs. Takes the tool and the operator's
    arguments without the program name. Returns the answer."""
    return incoming.classify(tool, list(args)) is not None


def prepare(repo: str, into: str, tool: str, args: list[str], config: str | None = None, *,
            deadline: float | None = None) -> tuple[dict, int]:
    """Materialise the update outside the open folder and scan what arrived. Takes the open folder,
    the holding directory, the tool, the arguments, the config and the deadline. Returns the answer
    and its exit: a passthrough, a scan, or a reason with a decision."""
    if incoming.brings_nothing(tool, args, Path(repo)):
        return {"passthrough": True, "reason": "the command brings no files in"}, exitcodes.CLEAN
    if incoming.continues_a_rebase(tool, args):
        return _continuing_a_rebase(repo, config, deadline)
    staged = incoming.what_it_stages(Path(repo), tool, list(args))
    if staged is not None:
        return _check_what_it_stages(repo, staged, config, deadline)
    govern_status.write(repo, "checking", step="checking the incoming update")
    current().step("materialise", "checking the incoming update")
    arrived = incoming.prepare(Path(repo), Path(into), tool, list(args))
    if isinstance(arrived, str):
        return _unchecked(repo, arrived, incoming.folder_it_creates(tool, list(args)))
    current().step("scan", "scanning what arrived")
    govern_status.write(repo, "checking", step="scanning what arrived")
    try:
        landing = blob_copies.copy_out_as_written(Path(repo).resolve(), arrived.root, _files_at(arrived),
                                                  arrived.paths, "the files an update brought in")
        sides = tuple((blob_copies.copy_out_as_written(Path(repo).resolve(), arrived.root, commit, names,
                                                       "the files an update brings, as one side has them"), names)
                      for commit, names in arrived.versions)
        payload, code, already_there = _scan_arrived(arrived.root, landing, arrived.paths, config,
                                                     arrived.base, deadline, sides)
    except DeadlineReached:
        return _unchecked(repo, "the check did not finish before its deadline")
    except ValueError as exc:
        return _unchecked(repo, str(exc) or "the check could not use your config")
    except OSError:
        return _unchecked(repo, "the check could not finish")
    verdict = _verdict(payload) or "incomplete"
    current().step("verdict", "verdict: %s" % verdict)
    scanned_clean = code == exitcodes.CLEAN and _verdict(payload) in {CLEAN, RESIDUE_VERDICT}
    if arrived.mode == incoming.UNCARRIED_CONFLICTS or (arrived.stopped and code == exitcodes.INCOMPLETE):
        left_out = dataclasses.replace(arrived, mode=incoming.UNCARRIED_CONFLICTS, stopped=None)
        return _checked_and_left_out(repo, into, left_out, payload, code, already_there, scanned_clean)
    strictly_clean = code == exitcodes.CLEAN and _verdict(payload) == CLEAN and not already_there
    lands_whole = arrived.stopped is None
    applied_mark = clean_ledger.clean_key(arrived.commit, config) if scanned_clean and lands_whole else None
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
    if arrived.stopped:
        answer["conflicts"] = list(arrived.stopped.conflicts)
        steps.append(f"The update stops for conflicts in {_listed(arrived.stopped.conflicts)}. Once it is "
                     f"in the folder, resolve them, then run `{_finish(arrived.stopped)}`.")
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


def _checked_and_left_out(repo: str, into: str, arrived: "incoming.Arrived", payload: dict, code: int,
                          already_there: list[dict], clean: bool) -> tuple[dict, int]:
    """Answer a checked update whose conflicts cannot be brought into the folder: a clean one with
    the decision of an update that cannot be checked, or for a pull the command that brings in the
    checked commit with no other choice than leaving the folder, and any other held with no way to
    let it in. Takes the open folder, the holding directory, what arrived, the scan, its exit, the
    findings the folder already had and whether the scan was clean. Returns the answer and an exit
    that is never a success."""
    verdict = _verdict(payload) or "incomplete"
    _write_state(Path(into), arrived, False, verdict=verdict)
    if clean and arrived.bring_in:
        answer, unchecked_code = _unchecked(repo, conflicted.CANNOT_CARRY)
        answer["decision"] = {"choices": [LEAVE_UNCHANGED]}
        step = f"To bring in exactly the commit saw checked, run `git {' '.join(arrived.bring_in)}`."
        return {"scan": payload, **answer, "next_steps": [step]}, unchecked_code
    if clean:
        answer, unchecked_code = _unchecked(repo, conflicted.CANNOT_CARRY)
        return {"scan": payload, **answer}, unchecked_code
    govern_status.write(repo, "held", verdict=verdict,
                        reasons=["the update was not applied; the open folder is unchanged"])
    findings = (payload.get("results") or [{}])[0].get("findings") or []
    steps = govern_held.next_steps(verdict, findings, already_there, arrived.commit, can_let_in=False)
    steps.append("The update stops for conflicts that cannot be brought into the folder.")
    answer: dict = {"scan": payload, "next_steps": steps}
    if already_there:
        answer["pre_existing"] = already_there
    return answer, exitcodes.INCOMPLETE if code == exitcodes.CLEAN else code


def _unchecked(repo: str, reason: str, created: str | None = None) -> tuple[dict, int]:
    """Answer an update saw could not check, leaving the decision to the user. Takes the open folder,
    the reason and the folder the command creates, when it creates one. Returns the payload, whose
    scan afterwards covers the created folder or else the open one, and INCOMPLETE."""
    govern_status.write(repo, "finished", reasons=[reason])
    scanned = Path(repo) / created if created else Path(repo)
    decision = {"choices": list(DECISION_CHOICES), "scan_after": ["saw", "scan", str(scanned)]}
    return {"reason": reason, "decision": decision}, exitcodes.INCOMPLETE


def _check_what_it_stages(repo: str, staged: "incoming.Staged | str", config: str | None,
                          deadline: float | None) -> tuple[dict, int]:
    """Scan the files a command would stage, and let it run as typed when they are clean. Takes the
    open folder, what the command stages, the operator config and the deadline. Returns a
    passthrough carrying the scan, the scan of a held command, or a reason with a decision."""
    if isinstance(staged, str):
        return _unchecked(repo, staged)
    purpose = "the files a command stages"
    try:
        landing = (blob_copies.copy_out(Path(repo), staged.commit, staged.paths, purpose) if staged.commit
                   else blob_copies.copy_out_blobs(Path(repo), staged.blobs, purpose))
        payload, code, already_there = _scan_arrived(Path(repo), landing, staged.paths, config, staged.base,
                                                     deadline)
    except DeadlineReached:
        return _unchecked(repo, "the check did not finish before its deadline")
    except ValueError as exc:
        return _unchecked(repo, str(exc) or "the check could not use your config")
    except OSError:
        return _unchecked(repo, "the check could not finish")
    verdict = _verdict(payload)
    if code == exitcodes.CLEAN and verdict in {CLEAN, RESIDUE_VERDICT}:
        return {"passthrough": True, "reason": "what the command stages was checked", "scan": payload}, code
    if verdict not in govern_held.HELD_VERDICTS:
        return _unchecked(repo, "the check could not finish")
    govern_status.write(repo, "held", verdict=verdict, reasons=["the command did not run; the folder is unchanged"])
    answer: dict = {"scan": payload}
    findings = (payload.get("results") or [{}])[0].get("findings") or []
    steps = govern_held.next_steps(verdict, findings, already_there, staged.commit, can_let_in=False)
    if steps:
        answer["next_steps"] = steps
    return answer, code


def apply(repo: str, into: str, accept: str | None = None, confirm: str | None = None) -> tuple[dict, int]:
    """Make the open folder match the checked tree, without fetching again. Takes the open folder,
    the holding directory, the accepted commit and the typed confirmation. Returns whether it was
    applied, the reason when not, and the exit."""
    state = _read_state(Path(into))
    if state is None:
        return _applied(False, "there is no checked update to apply")
    if state.get("mode") == incoming.UNCARRIED_CONFLICTS:
        return _applied(False, conflicted.CANNOT_CARRY)
    accepted_verdict = None
    if not state.get("releasable"):
        refused = _refuse_let_in(repo, state, accept, confirm)
        if refused:
            return _applied(False, refused)
        accepted_verdict = state.get("verdict") if state.get("verdict") in govern_held.HELD_VERDICTS else None
    try:
        stopped = state.get("stopped")
        arrived = incoming.Arrived(
            root=Path(state["root"]), paths=tuple(state["paths"]), mode=state["mode"],
            commit=state["commit"], base=state["base"], head=state["head"],
            refs=tuple(tuple(item) for item in state["refs"]),
            written=tuple((state.get("written") or {}).items()),
            stopped=conflicted.Stopped.from_record(stopped) if stopped else None)
    except (KeyError, TypeError):
        return _applied(False, "the checked update could not be read")
    current().step("apply", "applying the checked update")
    govern_status.write(repo, "checking", step="applying the checked update")
    reason = incoming.apply(Path(repo), Path(into), arrived)
    if not reason and arrived.stopped:
        return _left_to_resolve(repo, state, arrived.stopped, accepted_verdict)
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


def _files_at(arrived: "incoming.Arrived") -> str:
    """Name the commit or tree that holds the files an update leaves in the folder. Takes what
    arrived. Returns the landed tree of a stop for conflicts, else the commit the update brought."""
    return arrived.stopped.landed if arrived.stopped else arrived.commit


def _left_to_resolve(repo: str, state: dict, stopped: "conflicted.Stopped",
                     accepted_verdict: str | None) -> tuple[dict, int]:
    """Answer an update now in the folder that stops for conflicts. Takes the open folder, the
    recorded check, the stop and the verdict the user let in, if any. Returns the answer and
    INCOMPLETE."""
    step = (f"The update is in the folder and stops for conflicts in {_listed(stopped.conflicts)}. "
            f"Resolve them, then run `{_finish(stopped)}`.")
    reasons = [step]
    if stopped.operation == conflicted.REBASE and not govern_carried.remember(repo, stopped.incoming, stopped.picks):
        reasons.append("the rebase brought in could not be recorded")
    if accepted_verdict:
        clean_ledger.remember_accepted(Path(repo), state["commit"], accepted_verdict)
        reasons.append(f"you let in an update saw found {accepted_verdict}")
    govern_status.write(repo, "applied", verdict=state.get("verdict"), reasons=reasons)
    return {"applied": True, "conflicts": list(stopped.conflicts), "next_steps": [step]}, exitcodes.INCOMPLETE


def _continuing_a_rebase(repo: str, config: str | None, deadline: float | None) -> tuple[dict, int]:
    """Answer continuing a rebase in progress in the open folder. A rebase saw carried in runs as
    typed when what is left is what saw checked, or when a check of each commit left finds nothing,
    and any other rest is held with leaving the folder the one choice. A rebase saw did not carry
    in gets the answer starting it would get. Takes the open folder, the operator config and the
    deadline. Returns the answer and its exit."""
    left = incoming.rebase_left(Path(repo))
    if left is None:
        return {"passthrough": True, "reason": "the command brings no files in"}, exitcodes.CLEAN
    if isinstance(left, str):
        return _unchecked(repo, left)
    onto, picks, only_picks = left
    carried_here = govern_carried.carried_onto(repo) == onto
    if not only_picks:
        if not carried_here:
            return _unchecked(repo, incoming.RUNS_OTHER_COMMANDS)
        return _rebase_held(repo, "the rest of this rebase cannot be checked", {}, exitcodes.INCOMPLETE, [])
    if carried_here and govern_carried.carried(repo, onto, picks):
        return {"passthrough": True, "reason": "the rest of the rebase is what saw checked"}, exitcodes.CLEAN
    cannot = "the rest of this rebase could not be checked"
    sides = []
    for pick in picks:
        changed = conflicted.changed_by(Path(repo), pick)
        if changed is None:
            return _rebase_held(repo, cannot, {}, exitcodes.INCOMPLETE, []) if carried_here else _unchecked(repo, cannot)
        sides.append((blob_copies.copy_out_as_written(Path(repo).resolve(), Path(repo), pick, changed,
                                                      "the commits a rebase has left"), changed))
    try:
        payload, code, _already = _scan_arrived(Path(repo), blob_copies.BlobCopies((), ()), (), config, None,
                                                deadline, tuple(sides))
    except (DeadlineReached, ValueError, OSError):
        return _rebase_held(repo, cannot, {}, exitcodes.INCOMPLETE, []) if carried_here else _unchecked(repo, cannot)
    if code == exitcodes.CLEAN and _verdict(payload) in {CLEAN, RESIDUE_VERDICT}:
        return {"passthrough": True, "reason": "the rest of the rebase was checked"}, exitcodes.CLEAN
    if code == exitcodes.INCOMPLETE and not carried_here:
        answer, unchecked_code = _unchecked(repo, cannot)
        return {"scan": payload, **answer}, unchecked_code
    findings = (payload.get("results") or [{}])[0].get("findings") or []
    steps = govern_held.next_steps(_verdict(payload) or "incomplete", findings, [], onto, can_let_in=False)
    return _rebase_held(repo, "the rest of this rebase brings what the check held", payload, code, steps)


def _rebase_held(repo: str, reason: str, payload: dict, code: int, steps: list[str]) -> tuple[dict, int]:
    """Answer a rebase whose rest is held, offering only to leave the folder. Takes the open folder,
    the reason, the scan when there is one, its exit and the steps to show. Returns the answer and
    an exit that is never a success."""
    govern_status.write(repo, "held", reasons=[reason])
    answer: dict = {"reason": reason, "decision": {"choices": [LEAVE_UNCHANGED]},
                    "next_steps": [*steps, "To leave the rebase, run `git rebase --abort`."]}
    if payload:
        answer["scan"] = payload
    return answer, exitcodes.INCOMPLETE if code == exitcodes.CLEAN else code


def _listed(paths: tuple[str, ...]) -> str:
    """Name up to three paths and count the rest. Takes the paths. Returns the words."""
    shown = ", ".join(paths[:3])
    return shown if len(paths) <= 3 else f"{shown} and {len(paths) - 3} more"


def _finish(stopped: "conflicted.Stopped") -> str:
    """Return the git command that finishes the stopped operation. Takes the stop."""
    return conflicted.FINISH_COMMAND[stopped.operation]


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
                  base: str | None = None, deadline: float | None = None,
                  versions: tuple = ()) -> tuple[dict, int, list[dict]]:
    """Scan the files an update brought, as they will be written, and each other version of files
    it brings, within `deadline` seconds when given. Takes the holding work tree, the copies of what
    lands, the arrived paths, the operator config, the commit the folder had before, the deadline
    and the copies of the other versions as (copies, paths). Returns the scan document, its exit,
    and the findings the folder already had before the update, which do not count toward the
    verdict. Raises DeadlineReached at the deadline."""
    policy = operator_policy(config)
    sides = [(landing, paths), *versions]
    counted = sum(len(names) for _, names in sides)
    size = sum(pathsafe.regular_size(folder, names) for copied, _ in sides for folder, names in copied.folders)
    already: list = []
    result = None
    with Pace(current(), deadline) as pace:
        pace.plan(str(root), files=counted, size=size, commits=0, workers=1)
        pace.begin(str(root), "files", counted, counted=False)
        try:
            for copied, names in sides:
                found = _scan_copies(copied, policy)
                if base and found.findings:
                    before = blob_copies.copy_out(Path(root), base, names,
                                                  "the files an update changed, as they were before")
                    already += govern_held.set_aside_already_there(found, _scan_copies(before, policy))
                result = found if result is None else joined(result, found)
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
        if body not in already_there:
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
            "stopped": arrived.stopped.record() if arrived.stopped else None,
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
