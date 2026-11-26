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
import hashlib
import json
import os
from pathlib import Path

from stayawake.bots.security import clean_ledger, govern_carried, govern_command, govern_held, govern_status
from stayawake.bots.security.hook_policy import operator_policy
from stayawake.bots.security.models import CLEAN, INFECTED, RESIDUE_VERDICT, ScanReport, ScanResult
from stayawake.bots.security.scanner import joined, scan_target, unreadable
from stayawake.bots.security.found import described
from stayawake.bots.security.sinks.json_sink import _in_plain_words
from stayawake.bots.security.targets.local import LocalRepoTarget
from stayawake.lib.git import blob_copies, conflicted, incoming, query, replay, runs_from_the_folder, typed_command
from stayawake.lib.git.run import SAW_OWNED, UNTRUSTED, stdout, stdout_bytes
from stayawake.lib.git.write import replayed as replayed_writer
from stayawake.lib.git.write.working_tree import bytes_as_written, uncommitted_paths
from stayawake.lib.signing.commits.git_command import fix_commit_signing
from stayawake.utils import exitcodes, pathsafe, scratch
from stayawake.utils.pace import DeadlineReached, Pace
from stayawake.utils.progress_events import current
from stayawake.utils.timeutil import now_iso

SCHEMA = 1
_STATE = "state.json"
REPLAYED = "replayed"
GIT_STOPPED = "git stopped when saw ran the command"
_GITLINK = b"160000"

TOOLS = ("gh", "git")


LEAVE_UNCHANGED = "leave-unchanged"
DECISION_CHOICES = ("run-as-typed", LEAVE_UNCHANGED)

def take_command_environment() -> dict:
    """Move the variables that name a command's repository, give it settings or name its template
    out of this process's environment. Returns them, for `prepare`."""
    return typed_command.take_environment(os.environ)


def prepare(repo: str, into: str, tool: str, args: list[str], config: str | None = None, *,
            deadline: float | None = None, environment: dict | None = None,
            brings_no_files: bool = False) -> tuple[dict, int]:
    """Replay a command in a holding copy saw owns and judge what it would write into the open
    folder. Takes the open folder, the holding directory, the tool, the arguments, the config, the
    deadline, the command's environment and whether the stand-in reads the command as one that
    brings no files. Returns the answer and its exit: a passthrough, a scan, or a reason with a
    decision."""
    _forget_state(Path(into))
    command = typed_command.TypedCommand("", ())
    if tool == "gh":
        if not incoming.gh_brings_files(list(args)):
            return _unchecked(repo, replay.NOT_REPLAYED)
    else:
        read = typed_command.read(list(args), environment)
        if isinstance(read, str):
            return _unchecked(repo, read)
        command = read
        before = govern_command.before_replay(Path(repo), command, brings_no_files)
        if before is not None:
            return _answered_before_replay(repo, before, config, deadline)
    govern_status.write(repo, "checking", step="checking the incoming update")
    current().step("materialise", "checking the incoming update")
    location = replay.locate(Path(repo), command)
    if isinstance(location, str):
        return _unchecked(repo, location)
    holding = replay.reproduce(location, Path(into), command, with_files=command.sub != "fetch")
    if isinstance(holding, str):
        return _unchecked(repo, holding)
    signing = fix_commit_signing(location.folder_repository or Path(repo))
    result = replay.replay(holding, command, signing, list(args) if tool == "gh" else None)
    stopped = _stop_to_carry(result, command)
    if stopped is not None:
        return _judge_arrived(repo, into, stopped, config, deadline)
    if not result.finished and result.changes_nothing_but_refs and not result.refs:
        return _unchecked(repo, GIT_STOPPED + (f": {result.said}" if result.said else ""))
    return _judge_replayed(repo, into, result, config, deadline)


def _answered_before_replay(repo: str, before: "govern_command.Answer", config: str | None,
                            deadline: float | None) -> tuple[dict, int]:
    """Turn an answer given before a replay into prepare's answer. Takes the open folder, the
    answer, the config and the deadline. Returns the answer and its exit."""
    if before.kind == govern_command.PASSTHROUGH:
        return {"passthrough": True, "reason": before.reason}, exitcodes.CLEAN
    if before.kind == govern_command.CONTINUES_A_REBASE:
        return _continuing_a_rebase(repo, config, deadline)
    if before.kind == govern_command.ASKS:
        answer, code = _unchecked(repo, before.reason)
        return {**answer, "checked": True}, code
    return _unchecked(repo, before.reason, before.created)


def _stop_to_carry(result: "replay.Replayed", command: "typed_command.TypedCommand"
                   ) -> "incoming.Arrived | str | None":
    """Describe a merge or rebase the replay stopped for conflicts, to carry into the folder. Takes
    what the replay changed and the command. Returns what arrived, a sentence when it cannot be
    described, or None when the replay did not stop for conflicts it started."""
    holding = result.holding
    if result.finished or not holding.location.writable:
        return None
    if not {"MERGE_HEAD", "rebase-merge", "rebase-apply"} & set(result.state_left):
        return None
    if not conflicted.stopped_for_conflicts(holding.work, holding.bare):
        return None
    return incoming.arrived_with_conflicts(holding.work, holding.bare, holding.base, command.sub or "gh")


def _folder_holds(holding: "replay.Holding", paths: list[str]) -> dict[str, set[str]]:
    """Read the blob the folder holds at each path, in its files now and in its current commit.
    Takes the holding copy and the paths. Returns each path's blob ids."""
    holds: dict[str, set[str]] = {}
    sources = [(holding.bare, holding.files_before, SAW_OWNED)]
    own = holding.location.folder_repository
    if own is not None:
        sources.append((own, "HEAD", UNTRUSTED))
    for where, tree, context in sources:
        listed = stdout_bytes(where, ["ls-tree", "-r", "-z", tree, "--", *paths], context=context) or b""
        for record in listed.split(b"\0"):
            info, _, path = record.partition(b"\t")
            parts = info.split(b" ")
            if path and len(parts) == 3:
                holds.setdefault(os.fsdecode(path), set()).add(parts[2].decode())
    return holds


def _new_staged(result: "replay.Replayed", let_in: set) -> list[tuple[str, str]]:
    """List the index entries a replayed command stages whose content the folder does not hold and
    saw has not let in. Takes what the replay changed and the contents saw let in. Returns each
    (path, blob)."""
    holds = _folder_holds(result.holding, [rel for rel, _before, _after in result.index])
    written = {rel: oid for rel, _mode, oid in result.files}
    staged = []
    for rel, before, after in result.index:
        for mode, oid, stage in after:
            blob = oid.decode()
            if ((mode, oid, stage) in before or mode == _GITLINK or blob in holds.get(rel, set())
                    or written.get(rel) == blob or (rel, blob) in let_in):
                continue
            staged.append((rel, blob))
    return list(dict.fromkeys(staged))


def _judge_replayed(repo: str, into: str, result: "replay.Replayed", config: str | None,
                    deadline: float | None) -> tuple[dict, int]:
    """Scan what a replayed command writes and stages, in the form it will be written, and answer: ready to
    write, held, or a reason with a decision. Takes the open folder, the holding directory, what
    the replay changed, the config and the deadline. Returns the answer and its exit."""
    holding = result.holding
    location = holding.location
    own = location.folder_repository
    writer = own or holding.work
    written_files = [(rel, mode, oid) for rel, mode, oid in result.files if mode]
    let_in = clean_ledger.blobs_let_in(own, config) if own is not None else set()
    judged = tuple(rel for rel, _mode, oid in written_files if (rel, oid) not in let_in)
    staged = _new_staged(result, let_in)
    current().step("scan", "scanning what arrived")
    govern_status.write(repo, "checking", step="scanning what arrived")
    try:
        as_written = bytes_as_written(writer, result.files_after,
                                      [os.fsencode(rel) for rel, _mode, _oid in written_files],
                                      holding.bare / "objects") if written_files else {}
        if as_written is None:
            return _unchecked(repo, "the files the command writes could not be read")
        landing = blob_copies.copy_out_as_written(writer, holding.work, result.files_after, judged,
                                                  "the files an update brought in")
        sides = ((blob_copies.copy_out_blobs(holding.work, tuple(staged), "the files a command stages"),
                  tuple(rel for rel, _oid in staged)),) if staged else ()
        payload, code, already_there = _scan_arrived(holding.work, landing, judged, config,
                                                     _folder_commit(own), deadline, sides)
    except DeadlineReached:
        return _unchecked(repo, "the check did not finish before its deadline")
    except ValueError as exc:
        return _unchecked(repo, str(exc) or "the check could not use your config")
    except OSError:
        return _unchecked(repo, "the check could not finish")
    verdict = _verdict(payload) or "incomplete"
    current().step("verdict", "verdict: %s" % verdict)
    scanned_clean = code == exitcodes.CLEAN and verdict in {CLEAN, RESIDUE_VERDICT}
    top = location.work_tree or holding.work
    runs = runs_from_the_folder.run_on_arrival(
        writer, tuple(rel for rel, _mode, _oid in written_files),
        lambda rel: pathsafe.read_regular_no_follow(top / rel, 1 << 20),
        lambda rel: as_written.get(os.fsencode(rel)))
    asks = scanned_clean and (runs is None or bool(runs))
    writable = location.writable and result.finished and not result.state_left
    moved_to = _moved_to(result)
    answer: dict = {"scan": payload}
    if already_there:
        answer["pre_existing"] = already_there
    findings = (payload.get("results") or [{}])[0].get("findings") or []
    steps = govern_held.next_steps(verdict, findings, already_there, moved_to, can_let_in=writable)
    if asks:
        steps.append(f"The update changes {', '.join(runs or ('the folder git runs hooks from',))}, which git "
                     "or a hook manager runs as a hook in this folder. Check it, then let it in.")
    if steps:
        answer["next_steps"] = steps
    if not writable:
        return _checked_and_not_written(repo, result, answer, code, verdict, scanned_clean)
    releasable = scanned_clean and not asks
    strictly_clean = code == exitcodes.CLEAN and verdict == CLEAN and not already_there
    applied_mark = clean_ledger.clean_key(moved_to, config) if scanned_clean and moved_to else None
    blobs = {rel: oid for rel, _mode, oid in written_files} | dict(staged)
    _write_replayed_state(Path(into), result, releasable, verdict, asks, {
        "clean_mark": applied_mark if strictly_clean else None, "applied_mark": applied_mark,
        "written": {os.fsdecode(name): hashlib.sha256(data).hexdigest() for name, data in as_written.items()},
        "let_in": blobs, "policy": clean_ledger.policy_digest(config), "moved_to": moved_to})
    if releasable:
        govern_status.write(repo, "checking", verdict=verdict, step="checked; ready to apply")
        return {**answer, "output": {"stdout": result.output[0], "stderr": result.output[1]}}, code
    govern_status.write(repo, "held", verdict=verdict,
                        reasons=["the update was not applied; the open folder is unchanged"])
    if asks or verdict in govern_held.HELD_VERDICTS:
        answer["decision"] = govern_held.decision(repo, into, moved_to or result.files_after, verdict)
    else:
        answer["decision"] = _unchecked(repo, "")[0]["decision"]
    return answer, code


def _checked_and_not_written(repo: str, result: "replay.Replayed", answer: dict, code: int, verdict: str,
                             clean: bool) -> tuple[dict, int]:
    """Answer a judged command saw does not write into the folder itself: held with no way to let it
    in when the check found something, else the decision to run it as typed. Takes the open folder, what the replay
    changed, the answer this far, the scan's exit, the verdict and whether the scan was clean.
    Returns the answer and an exit that is never a success."""
    if verdict in govern_held.HELD_VERDICTS:
        govern_status.write(repo, "held", verdict=verdict,
                            reasons=["the command did not run; the folder is unchanged"])
        return answer, code
    if not result.finished:
        reason = GIT_STOPPED + (f": {result.said}" if result.said else "")
    elif clean:
        reason = "saw checked what the command writes, but cannot write it into this folder itself"
    else:
        reason = "the check could not finish"
    unchecked, unchecked_code = _unchecked(repo, reason)
    return {**answer, **unchecked}, unchecked_code


def _moved_to(result: "replay.Replayed") -> str:
    """Name the commit HEAD moves to, when the command moves it. Takes what the replay changed.
    Returns the commit, or ""."""
    holding = result.holding
    after = stdout(holding.bare, ["rev-parse", "--verify", "--quiet", "HEAD^{commit}"], context=SAW_OWNED).strip()
    return after if after and after != holding.base else ""


def _folder_commit(own: "Path | None") -> str:
    """Name the folder's own current commit. Takes its repository top, None when it has none.
    Returns the commit, or ""."""
    if own is None:
        return ""
    return stdout(own, ["rev-parse", "--verify", "--quiet", "HEAD^{commit}"], context=UNTRUSTED).strip()


def _write_replayed_state(into: Path, result: "replay.Replayed", releasable: bool, verdict: str, asks: bool,
                          judged: dict) -> None:
    """Record a judged replay for `apply` to write. Takes the holding directory, what the replay
    changed, whether it may be written, the verdict, whether it asks first, and what the judgement
    adds. Returns nothing."""
    holding = result.holding
    top = holding.location.work_tree or holding.work

    def entries(found) -> list:
        return [[part.decode() for part in entry] for entry in found]
    body = {"schema": SCHEMA, "mode": REPLAYED, "releasable": releasable,
            "commit": judged.get("moved_to") or result.files_after,
            "paths": [rel for rel, mode, _oid in result.files if mode],
            "verdict": verdict, "asks": asks, "top": str(top), "git_dir": str(holding.location.git_dir),
            "holding": str(holding.bare), "files_after": result.files_after,
            "files": [list(entry) for entry in result.files],
            "before": {rel: replayed_writer.state_of(top / rel) for rel, _mode, _oid in result.files},
            "index": [[rel, entries(before), entries(after)] for rel, before, after in result.index],
            "refs": [list(entry) for entry in result.refs], "head_before": holding.head,
            "head_after": result.head, "state_removed": list(result.state_removed),
            "stash_log": result.stash_log.hex() if result.stash_log is not None else None,
            "base": holding.base, "pseudo_refs": [list(entry) for entry in result.pseudo_refs],
            "fetch_head": result.fetch_head.hex() if result.fetch_head is not None else None, **judged}
    path = Path(into) / _STATE
    temporary = path.with_suffix(".json.tmp")
    temporary.write_text(json.dumps(body), encoding="utf-8")
    temporary.replace(path)


def _judge_arrived(repo: str, into: str, arrived: "incoming.Arrived | str", config: str | None,
                   deadline: float | None) -> tuple[dict, int]:
    """Scan what an update that stopped for conflicts brings and answer the way a carried stop is
    answered. Takes the open folder, the holding directory, what arrived, the config and the
    deadline. Returns the answer and its exit."""
    if isinstance(arrived, str):
        return _unchecked(repo, arrived)
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
    if state.get("mode") == REPLAYED:
        return _apply_replayed(repo, into, state, accepted_verdict)
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


def _apply_replayed(repo: str, into: str, state: dict, accepted_verdict: str | None) -> tuple[dict, int]:
    """Write a judged replay into the folder with saw's writers. Takes the open folder, the holding
    directory, the recorded judgement and the verdict the user let in, if any. Returns whether it
    was written, the reason when not, and the exit."""
    try:
        def entries(found) -> tuple:
            return tuple(tuple(entry) for entry in found)
        written = replayed_writer.Written(
            top=Path(state["top"]), git_dir=Path(state["git_dir"]), holding=Path(state["holding"]),
            files_after=state["files_after"], files=tuple(tuple(entry) for entry in state["files"]),
            before=dict(state["before"]), digests=dict(state["written"]),
            index=tuple((rel, entries(before), entries(after)) for rel, before, after in state["index"]),
            refs=tuple(tuple(entry) for entry in state["refs"]), head_before=state["head_before"],
            head_after=state["head_after"], state_removed=tuple(state["state_removed"]),
            stash_log=bytes.fromhex(state["stash_log"]) if state.get("stash_log") else None, base=state["base"],
            pseudo_refs=tuple(tuple(entry) for entry in state.get("pseudo_refs") or ()),
            fetch_head=bytes.fromhex(state["fetch_head"]) if state.get("fetch_head") is not None else None)
    except (KeyError, TypeError, ValueError):
        return _applied(False, "the checked update could not be read")
    incoming.claim(into)
    current().step("apply", "applying the checked update")
    govern_status.write(repo, "checking", step="applying the checked update")
    reason = replayed_writer.write(written)
    if reason:
        govern_status.write(repo, "finished", reasons=[reason])
    elif accepted_verdict:
        clean_ledger.remember_accepted(written.top, state.get("moved_to") or state["commit"], accepted_verdict)
        govern_status.write(repo, "applied", verdict=accepted_verdict,
                            reasons=[f"you let in an update saw found {accepted_verdict}"])
    else:
        if state.get("clean_mark"):
            clean_ledger.remember(written.top, state["clean_mark"])
        if state.get("applied_mark"):
            clean_ledger.remember_applied(written.top, state["applied_mark"])
        clean_ledger.remember_blobs(written.top, dict(state.get("let_in") or {}), state.get("policy") or "")
        govern_status.write(repo, "applied", verdict=state.get("verdict"))
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
            return _unchecked(repo, replay.RUNS_OTHER_COMMANDS)
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


def _forget_state(into: Path) -> None:
    """Remove what an earlier check recorded in the holding directory. Takes the holding
    directory. Returns nothing."""
    try:
        (Path(into) / _STATE).unlink()
    except FileNotFoundError:
        pass
    except OSError:
        if (Path(into) / _STATE).exists():
            raise


def _read_state(into: Path) -> dict | None:
    try:
        loaded = json.loads((Path(into) / _STATE).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    return loaded if isinstance(loaded, dict) else None
