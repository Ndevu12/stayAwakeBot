#!/usr/bin/env python3
"""The outbound git hook: judge what a `git push` would publish, and report it. The push always goes
through; the report is what saw adds."""
from __future__ import annotations

import os
import sys
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path

from stayawake.utils import env, textsafe
from stayawake.utils.render import LINK, MARKER, SEVERITY, block, marked_list, paint, term_width
from stayawake.utils.streaming import busy, say
from stayawake.utils.terminal import supports_color
from stayawake.lib import git as gitutil
from stayawake.lib.git import pushed
from stayawake.lib.git.run import one_pass
from stayawake.bots.security import push_record
from stayawake.bots.security.hook_policy import HookPolicy, operator_policy
from stayawake.bots.security.hook_report import BRAND
from stayawake.bots.security.models import CONFIRMED
from stayawake.bots.security import version_scan

EVENT = "pre-push"
_EARLIER_CHECK_SECONDS = 3.0
_HISTORY_CHUNK = 2_000
_EARLIER_WORK = "earlier new work"
_EARLIER_HISTORY = "earlier history"
_SHOWN = 5


@dataclass
class _Progress:
    """What a push check has established so far. Written by the checking thread, read after it."""

    lock: threading.Lock = field(default_factory=threading.Lock)
    stop: bool = False
    scope: pushed.PushScope | None = None
    queue: list[pushed.Introduced] = field(default_factory=list)
    earlier: list[pushed.Introduced] = field(default_factory=list)
    from_history: set[tuple[str, str]] = field(default_factory=set)
    listed: set[str] = field(default_factory=set)
    unlisted_now: list[tuple[str, list[str], str]] = field(default_factory=list)
    unlisted_earlier: list[tuple[str, list[str], str]] = field(default_factory=list)
    push_read: bool = False
    done: set[tuple[str, str]] = field(default_factory=set)
    unread: set[tuple[str, str]] = field(default_factory=set)
    verified: list[tuple[str, str]] = field(default_factory=list)
    confirmed: list[tuple[object, str]] = field(default_factory=list)
    suspicious: list[str] = field(default_factory=list)
    read_in_part: int = 0
    outside_git: int = 0
    crashed: str = ""
    finished: bool = False


def check_push(argv: list[str], refs_text: str, config_path: str | None, *,
               no_stream: bool = False) -> int:
    """Judge what a push would publish and report it on stderr. Takes the hook's arguments (remote
    name and URL), git's ref lines, the operator's config path and whether to stream. Returns 1
    when a confirmed payload is in the push, 2 when the push could not be verified, 0 otherwise."""
    err = sys.stderr
    started = time.monotonic()
    try:
        return _check(argv, refs_text, config_path, no_stream, err, started)
    except Exception:                       # noqa: BLE001
        return _unverified("", "", err, no_stream)


def _check(argv: list[str], refs_text: str, config_path: str | None, no_stream: bool,
           err, started: float) -> int:
    """Run the push check. Takes what `check_push` takes, the stream and when the check began.
    Returns its result."""
    remote = argv[0] if argv else ""
    to = f" to {textsafe.plain(remote)}" if remote else ""
    where = _repository()
    if where is None:
        return _unverified("", to, err, no_stream)
    git_dir, common_dir, display = where
    updates = pushed.read_push_updates(refs_text)
    if updates is None:
        return _unverified(display, to, err, no_stream)
    if not any(u.publishes for u in updates):
        return 0
    named = (remote if remote and (len(argv) < 2 or remote != argv[1])
             else pushed.remote_for_url(git_dir, argv[1]) if len(argv) > 1 else None)
    policy = operator_policy(config_path)
    record = push_record.load(common_dir, push_record.policy_digest(
        policy.signatures, policy.allowlist, getattr(policy.opts, "max_file_bytes", 0)))
    progress = _Progress()
    budget = env.hook_timeout(EVENT)
    worker = threading.Thread(target=_judge, daemon=True,
                              args=(progress, git_dir, display, updates, named, policy, record))
    with busy(f"{BRAND}: checking what this push would publish…", no_stream=no_stream, out=err):
        worker.start()
        worker.join(max(budget - (time.monotonic() - started), 0.0) if budget > 0 else None)
    with progress.lock:
        progress.stop = True
        return _report(progress, record, display, remote, err, no_stream)


def _repository() -> tuple[Path, Path, str] | None:
    """Find the repository git runs the hook in, bare or not. Returns its git directory, its common
    git directory and how it is shown, or None when git could not say."""
    here = Path.cwd()
    git_dir = gitutil.stdout(here, ["rev-parse", "--absolute-git-dir"]).strip()
    common = gitutil.stdout(here, ["rev-parse", "--path-format=absolute", "--git-common-dir"]).strip()
    if not git_dir or not common:
        return None
    top = gitutil.stdout(here, ["rev-parse", "--show-toplevel"]).strip()
    shown, home = top or git_dir, os.path.expanduser("~")
    if shown == home or shown.startswith(home.rstrip(os.sep) + os.sep):
        shown = "~" + shown[len(home.rstrip(os.sep)):]
    return Path(git_dir), Path(common), shown


def _judge(progress: _Progress, git_dir: Path, display: str, updates, remote: str | None,
           policy: HookPolicy, record: push_record.PushRecord) -> None:
    """Establish and scan what the push would publish, recording progress as it goes. Takes the
    shared progress, the repository, how it is shown, the updates, the remote the push goes to (None
    for a push to a URL), the policy and the record."""
    try:
        with one_pass():
            _judge_in_one_pass(progress, git_dir, display, updates, remote, policy, record)
    except Exception as exc:                # noqa: BLE001
        with progress.lock:
            progress.crashed = f"{type(exc).__name__}: {exc}"


def _judge_in_one_pass(progress: _Progress, git_dir: Path, display: str, updates,
                       remote: str | None, policy: HookPolicy,
                       record: push_record.PushRecord) -> None:
    """`_judge`'s body, run inside one pass so the repository's configuration is read once. Reads
    this push's new work and what its refs will serve, then the history it carries, then, for a
    short while, what an earlier check left."""
    scope = pushed.introduced(git_dir, updates, remote=remote)
    if scope is None:
        return
    unnamed = [pushed.Introduced(oid, oid, False, "", pushed.NEW_WORK) for oid in scope.unnamed]
    seen: set[tuple[str, str]] = set()
    first = _unseen([e for e in scope.entries if e.role == pushed.NEW_WORK] + unnamed
                    + [e for e in scope.entries if e.role == pushed.SERVED], record, seen)
    carried = [(c["commit"], c["parents"], _earlier(c["role"])) for c in record.unlisted]
    earlier = [pushed.Introduced(p["path"], p["oid"], bool(p.get("link")), p["commit"],
                                 _earlier(p.get("role", pushed.NEW_WORK)))
               for p in record.pending if not record.is_verified(p["path"], p["oid"])]
    with progress.lock:
        progress.scope = scope
        progress.queue = list(first)
        progress.earlier = earlier
        progress.unlisted_now = [(c, parents, scope.history_role) for c, parents in scope.history]
        progress.unlisted_earlier = carried
    fresh = {(e.path, e.oid) for e in scope.entries if e.role == pushed.NEW_WORK} | {
        (e.path, e.oid) for e in unnamed}
    if not _scan_all(progress, git_dir, display, first, scope.merges, fresh, policy):
        return
    if not _read_history(progress, git_dir, display, scope, scope.history_merges, record, seen,
                         fresh, policy, now=True):
        return
    with progress.lock:
        progress.push_read = True
        progress.unlisted_earlier = [item for item in progress.unlisted_earlier
                                     if item[0] not in progress.listed]
    until = time.monotonic() + _EARLIER_CHECK_SECONDS
    if _scan_all(progress, git_dir, display, _unseen(earlier, record, seen), [], fresh, policy,
                 until=until):
        _read_history(progress, git_dir, display, scope, [], record, seen, fresh, policy,
                      now=False, until=until)
    with progress.lock:
        progress.finished = True


def _earlier(role: str) -> str:
    """Name the role a version from an earlier check plays now. Takes the role it was kept with.
    Returns the earlier-check role for history or for new work."""
    return _EARLIER_HISTORY if role in (pushed.HISTORY, _EARLIER_HISTORY) else _EARLIER_WORK


def _kept_role(role: str) -> str:
    """Name the role a version is kept with for a later check. Takes its role now. Returns history
    or new work."""
    return pushed.HISTORY if role in (pushed.HISTORY, _EARLIER_HISTORY) else pushed.NEW_WORK


def _read_history(progress: _Progress, git_dir: Path, display: str, scope: pushed.PushScope,
                  merges: list[str], record: push_record.PushRecord,
                  seen: set[tuple[str, str]], fresh: set[tuple[str, str]], policy: HookPolicy, *,
                  now: bool, until: float | None = None) -> bool:
    """List and scan history a chunk of commits at a time, from the commits still to list for this
    push (`now`) or for an earlier one, taking each chunk off that list once its versions are
    queued. Each chunk holds commits whose versions take one role. Takes the progress, the
    repository, how it is shown, the scope, the merges to judge, the record, the keys already
    queued, the versions this push newly adds, the policy, which list to work from and an optional
    time to stop. Returns False when the check was stopped or git could not answer."""
    first = True
    while True:
        with progress.lock:
            waiting = progress.unlisted_now if now else progress.unlisted_earlier
            if not waiting:
                return True
            if progress.stop or (until is not None and time.monotonic() > until):
                return not progress.stop and not now
            role = waiting[0][2]
            chunk = []
            for commit, parents, kind in waiting[:_HISTORY_CHUNK]:
                if kind != role:
                    break
                chunk.append((commit, parents))
        listed = pushed.history_entries(git_dir, chunk, role=role)
        if listed is None:
            with progress.lock:
                scope.complete = scope.complete and not now
            return False
        history, submodules, complete = listed
        later = _unseen(history, record, seen)
        with progress.lock:
            if progress.stop:
                return False
            scope.submodules += submodules
            scope.complete = scope.complete and complete
            (progress.queue if now else progress.earlier).extend(later)
            progress.from_history.update((e.path, e.oid) for e in later)
            progress.listed.update(commit for commit, _parents in chunk)
            if now:
                progress.unlisted_now = progress.unlisted_now[len(chunk):]
            else:
                progress.unlisted_earlier = [item for item in progress.unlisted_earlier[len(chunk):]
                                             if item[0] not in progress.listed]
        if not _scan_all(progress, git_dir, display, later, merges if first else [], fresh, policy,
                         until=until):
            return False
        first = False


def _unseen(entries: list, record: push_record.PushRecord, seen: set[tuple[str, str]]) -> list:
    """Keep the versions not yet queued and not verified under this policy. Takes the versions, the
    record and the keys already queued, which it extends. Returns the versions to read."""
    kept = []
    for entry in entries:
        key = (entry.path, entry.oid)
        if key in seen or record.is_verified(*key):
            continue
        seen.add(key)
        kept.append(entry)
    return kept


def _scan_all(progress: _Progress, git_dir: Path, display: str, entries: list, merges: list[str],
              fresh: set[tuple[str, str]], policy: HookPolicy, until: float | None = None) -> bool:
    """Scan versions batch by batch until they are done, the check is stopped, or `until` passes.
    Takes the progress, the repository, how it is shown, the versions, the merges to judge, the
    versions this push newly adds, the policy and an optional time to stop. Returns False when the
    check was stopped."""
    batches = version_scan.batches(entries)
    if not batches and merges:
        batches = [[]]
    for index, batch in enumerate(batches):
        with progress.lock:
            if progress.stop:
                return False
        if until is not None and time.monotonic() > until:
            return True
        _scan_batch(progress, git_dir, display, batch, merges if index == 0 else [], fresh, policy)
    return True


def _scan_batch(progress: _Progress, git_dir: Path, display: str, batch: list, merges: list[str],
                fresh: set[tuple[str, str]], policy: HookPolicy) -> None:
    """Scan one batch and record what it established. Takes the progress, the repository, how it is
    shown, the batch, the merges to judge with it, the versions this push newly adds, and the
    policy."""
    scanned = version_scan.scan_batch(git_dir, display, batch, merges, policy.signatures,
                                      policy.allowlist, policy.opts)
    in_part, outside_git, unread = scanned.in_part, scanned.outside_git, scanned.unread
    confirmed_paths: set[str] = set()
    confirmed, suspicious = [], []
    for finding, entry in scanned.findings:
        commit = entry.commit if entry else (getattr(finding, "commit_sha", "") or "")
        role = entry.role if entry else pushed.NEW_WORK
        if finding.confidence == CONFIRMED:
            confirmed.append((finding, commit, role))
            confirmed_paths.add(finding.path)
        elif entry is None or (entry.path, entry.oid) in fresh:
            suspicious.append(finding.path)
    with progress.lock:
        if progress.stop:
            return
        progress.confirmed += confirmed
        progress.outside_git += len(outside_git)
        progress.suspicious += suspicious
        for entry in batch:
            key = (entry.path, entry.oid)
            progress.done.add(key)
            if entry.path in unread:
                progress.unread.add(key)
            elif entry.path in in_part:
                progress.read_in_part += entry.path not in confirmed_paths
            elif entry.path not in confirmed_paths:
                progress.verified.append(key)


def _report(progress: _Progress, record: push_record.PushRecord, display: str, remote: str,
            err, no_stream: bool) -> int:
    """Write the push check's report and keep the record. Takes the progress, the record, how the
    repository is shown, the remote name, the stream and whether to stream. Returns the check's
    result."""
    to = f" to {textsafe.plain(remote)}" if remote else ""
    if progress.crashed or progress.scope is None:
        return _unverified(display, to, err, no_stream)
    scope = progress.scope
    left = [e for e in progress.queue if (e.path, e.oid) not in progress.done]
    unread = [e for e in progress.queue if (e.path, e.oid) in progress.unread]
    still = [e for e in progress.earlier
             if (e.path, e.oid) not in progress.done or (e.path, e.oid) in progress.unread]
    for key in progress.verified:
        record.mark_verified(*key)
    carry = list({(e.path, e.oid): e for e in left + unread + still}.values())
    record.pending = [{"path": e.path, "oid": e.oid, "commit": e.commit, "link": e.link,
                       "role": pushed.HISTORY if (e.path, e.oid) in progress.from_history
                       else _kept_role(e.role)} for e in carry[:push_record.MAX_PENDING]]
    waiting: dict[str, tuple[list[str], str]] = {}
    for commit, parents, role in progress.unlisted_earlier:
        if commit not in progress.listed:
            waiting.setdefault(commit, (parents, _kept_role(role)))
    for commit, parents, _role in progress.unlisted_now:
        waiting.setdefault(commit, (parents, pushed.HISTORY))
    unlisted = list(waiting.items())
    record.unlisted = [{"commit": commit, "parents": parents, "role": role}
                       for commit, (parents, role) in unlisted[:push_record.MAX_PENDING]]
    dropped = (max(len(carry) - push_record.MAX_PENDING, 0)
               + max(len(unlisted) - push_record.MAX_PENDING, 0))
    kept = record.save()
    page = _Page.of(err)
    lines: list[str] = []
    found = {role: [(f, c) for f, c, r in progress.confirmed if r == role]
             for role in (pushed.NEW_WORK, pushed.SERVED, pushed.HISTORY, _EARLIER_WORK,
                          _EARLIER_HISTORY)}
    pushing = found[pushed.NEW_WORK] + found[pushed.SERVED]
    live = pushing + found[_EARLIER_WORK]
    made_here = found[_EARLIER_WORK] + [(f, c) for f, c in found[pushed.NEW_WORK]
                                        if not _came_from_history(f, progress)]
    where = _destination(to)
    if pushing:
        lines += page.headline("critical", f"{BRAND}: WORM DETECTED in this push{to} — {display}")
        lines += page.items(_named(pushing))
        lines += page.note(f"The push is still going through, so {where} will have it.")
    if found[_EARLIER_WORK]:
        lines += page.headline("critical", f"{BRAND}: an earlier push from this repository contained "
                                           f"a known worm — {display}")
        lines += page.items(_named(found[_EARLIER_WORK]))
    older = found[pushed.HISTORY] + found[_EARLIER_HISTORY]
    if older:
        if found[pushed.HISTORY]:
            lines += page.headline("warning", f"{BRAND}: an older commit in this push{to} contains "
                                              f"a known worm — {display}")
            lines += page.items(_named(found[pushed.HISTORY]))
            lines += page.note(f"{where} may already have it. If it was cleaned there, this push "
                               "brings it back.")
        if found[_EARLIER_HISTORY]:
            lines += page.headline("warning", f"{BRAND}: a commit in an earlier push from this "
                                              f"repository contains a known worm — {display}")
            lines += page.items(_named(found[_EARLIER_HISTORY]))
    if live:
        lines += page.note("saw fix cleans your working folder and prepares a clean branch. "
                           "saw fix amend also removes it from your history; that rewrites commits "
                           "others may already have.")
        lines += page.fix(f"saw fix --path {display}")
        lines += page.fix(f"saw fix amend {display}")
        if made_here:
            lines += page.note("This machine may be infected too.")
            lines += page.fix("saw audit", label="check")
    elif older:
        lines += page.note("saw fix amend removes it from your history so it cannot be pushed "
                           "again; that rewrites commits others may already have.")
        lines += page.fix(f"saw fix amend {display}")
    if progress.suspicious and not progress.confirmed:
        files = list(dict.fromkeys(progress.suspicious))
        lines += page.headline("medium", f"{BRAND}: {_count(len(files), 'file', 'files')} in this "
                                         f"push{to} {'looks' if len(files) == 1 else 'look'} "
                                         "suspicious, but not confirmed as a worm. Review before "
                                         "anyone runs this code:")
        lines += page.items([textsafe.plain(p) for p in files])
    missing = len(left) + len(unread)
    if missing or not scope.complete or not progress.push_read:
        later = (" saw will finish the check the next time you push from this repository."
                 if kept and (missing or unlisted) and not dropped
                 else " Part of it could not be kept for a later push." if dropped or not kept else "")
        own = [e for e in progress.queue if e.role in (pushed.NEW_WORK, pushed.SERVED)]
        own_waiting = any(role == pushed.NEW_WORK for _c, _p, role in progress.unlisted_now)
        own_clean = (own and not own_waiting and not pushing and not progress.suspicious
                     and all((e.path, e.oid) in progress.done and (e.path, e.oid) not in progress.unread
                             for e in own))
        if own_clean:
            lines += page.headline("unknown", f"{BRAND}: your new changes in this push{to} were "
                                              "checked and no worm was found, but saw did not "
                                              "finish checking the older history the push "
                                              f"carries, so it is NOT verified.{later}")
        else:
            lines += page.headline("unknown", f"{BRAND}: saw did not finish checking this "
                                              f"push{to}, so it is NOT verified.{later}")
        lines += page.fix(f"saw scan --history {display}", label="check")
        code = 1 if progress.confirmed else 2
    elif progress.confirmed:
        code = 1
    else:
        code = 0
        checked = sum(1 for e in progress.queue if (e.path, e.oid) in progress.done)
        skipped = [s for s in (_count(progress.read_in_part, "file too large to read in full",
                                      "files too large to read in full"),
                               _count(progress.outside_git, "Git LFS file", "Git LFS files"),
                               _count(scope.submodules, "submodule", "submodules")) if s]
        if skipped and not progress.suspicious:
            lines += page.headline("info", f"{BRAND}: no worm found in the "
                                           f"{_count(checked, 'file', 'files')} checked in this "
                                           f"push{to}. Not fully checked: {', '.join(skipped)}.")
        elif (checked or scope.merges) and not progress.suspicious:
            lines += page.headline("ok", f"{BRAND}: no worm found in this push{to} "
                                         f"({_count(checked, 'file', 'files')} checked).")
    if (still or progress.unlisted_earlier) and code == 0:
        lines += page.headline("info", f"{BRAND}: saw is still finishing the check of an earlier push"
                                       "; it continues the next time you push.")
    if code == 0 and (dropped or ((still or unlisted) and not kept)):
        lines += page.headline("unknown", f"{BRAND}: part of the check of an earlier push could not "
                                          "be kept for later.")
        lines += page.fix(f"saw scan --history {display}", label="check")
    _emit(lines, err, no_stream)
    return code


@dataclass(frozen=True)
class _Page:
    """How the report is laid out on one stream: its colour and its width."""

    color: bool
    width: int

    @classmethod
    def of(cls, stream) -> "_Page":
        """Read the layout of a stream. Takes the stream. Returns its page."""
        return cls(supports_color(stream), term_width(stream=stream))

    def headline(self, meaning: str, text: str) -> list[str]:
        """A wrapped line led by the marker for its meaning, coloured by it. Takes the meaning
        (ok, info, medium, warning, critical or unknown) and the text. Returns the lines."""
        marker = MARKER["warning" if meaning == "medium" else meaning]
        return [paint(line, SEVERITY[meaning], on=self.color)
                for line in block(text, width=self.width, marker=f"{marker}  ")]

    def items(self, entries: list[str]) -> list[str]:
        """Up to five entries as a list, and how many more there are. Takes the entries. Returns
        the lines."""
        more = [f"and {len(entries) - _SHOWN} more"] if len(entries) > _SHOWN else []
        return marked_list(entries[:_SHOWN] + more, indent=5, width=self.width,
                           code=SEVERITY["warning"], color=self.color)

    def note(self, text: str) -> list[str]:
        """A wrapped follow-on sentence under a headline. Takes the text. Returns the lines."""
        return block(text, indent=3, width=self.width)

    def fix(self, command: str, label: str = "fix") -> list[str]:
        """The command that deals with it, as a labelled follow-on line. Takes the command and the
        label. Returns the line."""
        return [f"   {paint(MARKER['detail'] + ' ' + label + ' ', SEVERITY['info'], on=self.color)} "
                f"{paint(command, LINK, on=self.color)}"]


def _emit(lines: list[str], err, no_stream: bool) -> None:
    """Write the finished report. Takes its lines, the stream and whether to stream."""
    if lines:
        say("\n".join(lines), no_stream=no_stream, out=err)


def _destination(to: str) -> str:
    """Name where the push goes, for a sentence. Takes the destination text. Returns the remote's
    name, or "the remote"."""
    return to[len(" to "):] if to else "the remote"


def _count(n: int, one: str, many: str) -> str:
    """Say a count in words. Takes the count and the singular and plural nouns. Returns the phrase,
    empty for none."""
    return "" if not n else f"{n} {one if n == 1 else many}"


def _came_from_history(finding, progress: _Progress) -> bool:
    """Whether a finding was in history this push carries rather than in its new work. Takes the
    finding and the progress. Returns the answer."""
    return any(path == finding.path for path, _oid in progress.from_history)


def _named(findings: list) -> list[str]:
    """Name each found file once, with the line and the commit it was found at. Takes the findings
    with their commits. Returns one entry per file."""
    lines: dict[str, str] = {}
    for finding, commit in findings:
        where = f"{finding.path}, line {finding.line}" if finding.line else finding.path
        at = f" (commit {commit[:10]})" if commit else ""
        lines.setdefault(finding.path, textsafe.plain(where) + at)
    return list(lines.values())


def _unverified(display: str, to: str, err, no_stream: bool) -> int:
    """Report a push saw could not check. Takes how the repository is shown, the destination text,
    the stream and whether to stream. Returns 2."""
    page = _Page.of(err)
    lines = page.headline("unknown", f"{BRAND}: saw could not check this push{to}, so it is NOT "
                                     "verified.")
    if display:
        lines += page.fix(f"saw scan --history {display}", label="check")
    _emit(lines, err, no_stream)
    return 2
