#!/usr/bin/env python3
"""Apply the remediation plan to the checkout the operator is standing in."""
from __future__ import annotations

import hashlib
import os
import unicodedata

from dataclasses import dataclass, field, replace
from pathlib import Path, PurePosixPath

from stayawake.bots.security.models import CONFIRMED, SAW_DIR
from stayawake.bots.security.remediation import changes as ch, installed, preserve
from stayawake.bots.security.remediation.oracle import (ABSENT, REFUSED, UNREADABLE,
                                                        content_confirms, payload_matchers,
                                                        still_condemned)
from stayawake.lib.git.write.working_tree import rewrite_index, uncommitted_paths
from stayawake.lib.git.run import run, stdout, stdout_bytes, stdout_bytes_fed


@dataclass
class LiveResult:
    """What a run did to the live checkout."""

    removed: list[str] = field(default_factory=list)
    stripped: list[str] = field(default_factory=list)
    absent: list[str] = field(default_factory=list)
    unread: list[str] = field(default_factory=list)
    refused: list[str] = field(default_factory=list)

    @property
    def named(self) -> list[str]:
        """Every path the plan condemned, whatever became of it."""
        return self.removed + self.stripped + self.absent + self.unread + self.refused

    @property
    def unfinished(self) -> list[str]:
        """The paths still to account for."""
        return self.unread + self.refused

    @property
    def complete(self) -> bool:
        """Whether every condemned path was accounted for."""
        return not self.unfinished


def clean(root: Path, findings, signatures, allowlist, opts) -> LiveResult:
    """Remove from `root` what the findings condemn.

    Takes the checkout, the findings, the by-matcher signatures, the allowlist and the scan
    options. Returns what was removed and what was not.
    """
    plan = ch.plan(findings)
    if not plan:
        return LiveResult()
    result = LiveResult()
    bucket = {ABSENT: result.absent, UNREADABLE: result.unread, REFUSED: result.refused}

    def skipped(path: str, reason: str) -> None:
        bucket.get(reason, result.unread).append(path)

    applied = ch.apply(root, plan, None,
                       condemned=still_condemned(root, signatures, allowlist, opts),
                       on_skip=skipped)
    for change in applied:
        if change.action == "remove":
            result.removed.append(change.path)
        else:
            result.stripped.append(change.path)
    return result


@dataclass
class CheckoutResult:
    """What a run found in the operator's checkout and what it did about it.

    `cleared` names the confirmed paths the run took out of the checkout, or found already gone;
    what the history still stores at them is a separate question. `index_unread` names why git
    could not say what its index holds, "" when it could.
    """

    confirmed: int = 0
    left_alone: list[str] = field(default_factory=list)
    report: object = None
    removed: LiveResult = field(default_factory=LiveResult)
    kept: preserve.Preserved = field(default_factory=preserve.Preserved)
    scan_error: str = ""
    failure: str = ""
    staged: list[str] = field(default_factory=list)
    unstaged: list[str] = field(default_factory=list)
    cleared: list[str] = field(default_factory=list)
    index_unread: str = ""

    @property
    def infected(self) -> bool:
        """Whether the checkout carried a confirmed payload."""
        return self.confirmed > 0

    @property
    def unread(self) -> bool:
        """Whether part of the checkout, or of git's index, could not be read."""
        return bool(self.scan_error or self.removed.unread or self.index_unread)

    @property
    def not_removed(self) -> list:
        """What the installed-tree pass could not remove."""
        return list(getattr(self.report, "not_removed", None) or ())

    @property
    def still_in(self) -> list[str]:
        """The confirmed paths still in the checkout, staged ones among them."""
        return list(dict.fromkeys([*self.left_alone, *self.removed.refused, *self.staged]))

    @property
    def complete(self) -> bool:
        """Whether the checkout can be called clean."""
        return (not self.unread and not self.still_in and not self.failure
                and not self.kept.blocked and not self.not_removed)


def clean_checkout(repo: Path, opts, signatures, allowlist, *, scan=None, keep=(),
                   lockfile_root: Path | None = None, base_confirmed: bool = False,
                   remove_lockfiles: bool = True) -> CheckoutResult:
    """Scan the checkout the operator is standing in and clear what it confirms.

    Takes the checkout, the scan options, the by-matcher signatures, the allowlist, the scan to
    run, the directories to keep, the tree the lockfiles are read from, whether the branch this
    fix is prepared against is confirmed too, and whether the lockfile goes. Returns what was found
    and what was done. The staged changes are read as well as the files on disk, and on a
    confirmed infection every directory the scan leaves out is read once the installed trees are
    gone. Once the checkout has been changed, what the operator had not committed is put on a
    branch of its own, as it stands after the change.
    """
    from stayawake.bots.security.targets import LocalRepoTarget
    if scan is None:
        from stayawake.bots.security.scanner import scan_target
        scan = scan_target
    kept_dirs = _kept_within(repo, keep)
    first = _skipped_within(repo, opts, kept_dirs, leave_out={installed.INSTALLED_DIR})
    payload = payload_matchers(signatures)
    reads = [scan(LocalRepoTarget(repo, str(repo), opts), signatures, allowlist)]
    reads += [scan(_directory(repo, opts, d), payload, allowlist) for d in [*kept_dirs, *first]]
    scan_error = ("your checkout was not read in full, so it is not clean"
                  if any(read.error for read in reads) else "")
    findings = list({(f.path, getattr(f, "signature_id", None)): f
                     for read in reads for f in read.findings
                     if getattr(f, "confidence", None) == CONFIRMED}.values())
    stored = StoredContent(repo, signatures, allowlist, opts)
    staged_payloads, committed_payloads, index_unread = _index_payloads(repo, stored)
    on_disk = {f.path for f in findings}
    staged_only = [p for p in staged_payloads if p not in on_disk]
    if not findings and not staged_only and not base_confirmed:
        return CheckoutResult(scan_error=scan_error, index_unread=index_unread,
                              cleared=committed_payloads)
    limit = getattr(opts, "max_file_bytes", preserve.MAX_SAVED_BYTES)
    payload_digests = _digests(repo, findings, limit) | stored.confirmed_digests
    report, failure, theirs, present = None, "", [], []
    blocker = preserve.can_hold(repo)
    if not blocker:
        try:
            theirs = preserve.uncommitted(repo)
        except preserve.WorkingTreeUnlisted as exc:
            blocker = f"git could not list it ({exc})"
    if blocker:
        failure = ("the installed tree was left, because your uncommitted work could not be "
                   f"held: {blocker}")
    elif scan_error:
        present = [p for p in theirs if os.path.lexists(Path(repo) / p)]
        failure = "the installed tree was left, because your checkout was not read in full"
    else:
        present = [p for p in theirs if os.path.lexists(Path(repo) / p)]
        try:
            report = installed.remove_installed(repo, confirmed=True, keep=keep,
                                                remove_lockfiles=remove_lockfiles,
                                                lockfile_root=lockfile_root)
        except OSError as exc:
            failure = f"could not remove the installed tree ({exc})"
    skipped = ([d for d in _skipped_within(repo, opts, kept_dirs) if d not in first]
               if report is not None and not failure else [])
    later = [scan(_directory(repo, opts, d), payload, allowlist) for d in skipped]
    if any(read.error for read in later):
        scan_error = "your checkout was not read in full, so it is not clean"
    findings += [f for f in {(f.path, getattr(f, "signature_id", None)): f
                             for read in later for f in read.findings
                             if getattr(f, "confidence", None) == CONFIRMED}.values()
                 if f.path not in {g.path for g in findings}]
    payload_digests |= _digests(repo, findings, limit)
    removed = clean(repo, findings, signatures, allowlist, opts)
    removed_committed = _removed_committed_payloads(repo, stored, {*theirs, *committed_payloads})
    committed_payloads = [*committed_payloads, *removed_committed]
    read_whole = [*kept_dirs, *first, *skipped]
    unread = [p for p in theirs if _unread(p, opts, read_whole)
              and os.path.lexists(Path(repo) / p)]
    named = sorted({f.path for f in findings} | set(removed.named))
    acted = bool(removed.removed or removed.stripped or (report is not None and report.acted))
    taken = [p for p in (present if not blocker else ()) if not os.path.lexists(Path(repo) / p)]
    kept = preserve.Preserved()
    if acted and not blocker:
        try:
            kept = preserve.preserve(
                repo, theirs, condemned=[*named, *committed_payloads], removed=taken,
                cleaned=removed.stripped,
                unread=unread,
                confirms=lambda data, path, is_symlink: (
                    hashlib.sha256(data).digest() in payload_digests
                    or bool(content_confirms(data, path, payload, allowlist, opts,
                                             is_symlink=is_symlink))),
                limit=limit)
        except preserve.WorkingTreeUnlisted as exc:
            kept = preserve.Preserved(reason=f"git could not list your uncommitted work ({exc})",
                                      blocked=True)
    dealt = {*removed.removed, *removed.stripped, *removed.absent, *removed.unfinished}
    cleared = {*removed.removed, *removed.stripped, *removed.absent}
    gone = list(dict.fromkeys([*(p for p in named if p in cleared), *staged_only]))
    history_only = [p for p in committed_payloads if p not in gone]
    unstaged, untouched = _unstage_confirmed(repo, gone, stored)
    if untouched:
        failure = "; ".join(p for p in (failure, "your staged changes could not be rewritten") if p)
    staged, unasked = _still_staged(repo, gone, signatures, allowlist, opts)
    return CheckoutResult(confirmed=len(findings) + len(staged_only), report=report,
                          removed=removed,
                          left_alone=[p for p in named if p not in dealt],
                          kept=kept, failure=failure, staged=staged,
                          cleared=[*gone, *history_only],
                          scan_error=scan_error,
                          unstaged=unstaged,
                          index_unread=unasked or index_unread)


def _index_payloads(repo: Path, stored) -> tuple[list[str], list[str], str]:
    """The payloads git's index holds that the files on disk do not show.

    Takes the repository and a `StoredContent`. Returns the paths whose staged content carries a
    payload the current commit does not hold; the paths where the current commit holds a payload
    while the index or the file on disk differs from it; and the reason git's index could not be
    read in full, "" when it could. A directory git does not take for a repository has none.
    """
    repository = run(repo, ["rev-parse", "--git-dir"])
    has_head = run(repo, ["rev-parse", "--verify", "-q", "HEAD^{commit}"])
    if repository is None or has_head is None:
        return [], [], "git could not run"
    if repository.returncode != 0:
        return [], [], ""
    index = entries(repo, ["ls-files", "-s", "-z"], {}, staged=True)
    tree = (entries(repo, ["ls-tree", "-r", "-z", "--full-tree", "HEAD"], {}, staged=False)
            if has_head.returncode == 0 else {})
    differs = uncommitted_paths(repo)
    if index is None or tree is None or differs is None:
        return [], [], "the index or the current commit could not be read"
    changed = {os.fsdecode(path) for path in differs}
    found, committed, unreadable = [], [], False
    for path in sorted(changed & set(tree)):
        held = [stored.confirms(path, entry) for entry in tree[path]]
        if any(held):
            committed.append(path)
        unreadable = unreadable or None in held
    for path, staged in index.items():
        verdicts = [stored.confirms(path, entry) for entry in staged
                    if entry not in tree.get(path, ())]
        if any(verdicts):
            found.append(path)
        elif None in verdicts:
            unreadable = True
    return sorted(found), sorted(committed), ("a staged file could not be read" if unreadable
                                              else "")


def _removed_committed_payloads(repo: Path, stored, known: set[str]) -> list[str]:
    """The paths the current commit holds a payload at that the run's removals took off the disk.

    Takes the repository, a `StoredContent` and the paths already accounted for. Returns each path
    whose committed content confirms, or could not be read.
    """
    has_head = run(repo, ["rev-parse", "--verify", "-q", "HEAD^{commit}"])
    if has_head is None or has_head.returncode != 0:
        return []
    tree = entries(repo, ["ls-tree", "-r", "-z", "--full-tree", "HEAD"], {}, staged=False) or {}
    return sorted(path for path, held in tree.items()
                  if path not in known and not os.path.lexists(Path(repo) / path)
                  and any(stored.confirms(path, entry) is not False for entry in held))


def _unstage_confirmed(repo: Path, paths: list[str], stored) -> tuple[list[str], bool]:
    """Take confirmed content out of the operator's staged changes. A path staged once goes back
    to what HEAD holds when that is clean, and otherwise leaves the index; a path in conflict
    loses only its confirmed stages, so it stays unresolved.

    Takes the repository, the paths and a `StoredContent`. Returns the paths taken out, and whether
    the index could not be rewritten.
    """
    if not paths:
        return [], False
    key = path_key(repo)
    wanted = {key(p) for p in paths}
    listed = stdout_bytes_fed(repo, ["ls-files", "-s", "-z"], b"")
    has_head = run(repo, ["rev-parse", "--verify", "-q", "HEAD^{commit}"])
    head = (entries(repo, ["ls-tree", "-r", "-z", "--full-tree", "HEAD"], {}, staged=False)
            if has_head is not None and has_head.returncode == 0 else {})
    if listed is None or head is None:
        return [], True
    staged: dict[str, list[tuple[str, str, str]]] = {}
    for meta, path in _records(listed):
        fields = meta.split()
        if path and len(fields) == 3 and key(path) in wanted:
            staged.setdefault(path, []).append((fields[0], fields[1], fields[2]))
    zero = "0" * (len(stdout(repo, ["rev-parse", "HEAD"]).strip()) or 40)
    lines, taken = [], []
    for path, found in staged.items():
        confirmed = [e for e in found if stored.confirms(path, (e[0], e[1])) is not False]
        committed = head.get(path, [])
        if not confirmed or (committed and all(e[2] == "0" for e in found)
                             and (found[0][0], found[0][1]) in committed):
            continue
        lines.append(f"0 {zero}\t{path}")
        if all(e[2] == "0" for e in found):
            if committed and stored.confirms(path, committed[0]) is False:
                lines.append(f"{committed[0][0]} {committed[0][1]}\t{path}")
        else:
            lines += [f"{mode} {oid} {stage}\t{path}" for mode, oid, stage in found
                      if (mode, oid, stage) not in confirmed]
        taken.append(path)
    if not lines:
        return [], False
    feed = "\0".join(lines).encode("utf-8", "surrogateescape") + b"\0"
    if not rewrite_index(repo, feed):
        return [], True
    return taken, False


def _still_staged(repo: Path, paths: list[str], signatures, allowlist, opts):
    """Which paths git's index still holds with confirmed content that HEAD does not.

    Takes the repository, the paths, the by-matcher signatures, the allowlist and the scan options.
    Returns the paths still staged and the reason git could not be asked, "" when it could. A blob
    that cannot be read counts as confirmed.
    """
    if not paths:
        return [], ""
    env = literal_pathspecs()
    has_head = run(repo, ["rev-parse", "--verify", "-q", "HEAD^{commit}"])
    if has_head is None:
        return [], "git could not run"
    key = path_key(repo)
    index = entries(repo, ["ls-files", "-s", "-z"], env, staged=True)
    head = (entries(repo, ["ls-tree", "-r", "-z", "--full-tree", "HEAD"], env, staged=False)
            if has_head.returncode == 0 else {})
    if index is None or head is None:
        return [], "the index or the current commit could not be read"
    stored = StoredContent(repo, signatures, allowlist, opts)
    held = {key(path) for path, staged in index.items()
            if any(entry not in head.get(path, ()) and stored.confirms(path, entry) is not False
                   for entry in staged)}
    return [p for p in paths if key(p) in held], ""


def literal_pathspecs() -> dict:
    """The environment a git listing of exact paths runs in."""
    return dict(os.environ, GIT_LITERAL_PATHSPECS="1")


class StoredContent:
    """Whether a blob git stores carries confirmed content at a path, each pair judged once."""

    def __init__(self, repo: Path, signatures, allowlist, opts):
        self._repo, self._allowlist, self._opts = repo, allowlist, opts
        self._payload = payload_matchers(signatures)
        self._verdicts: dict[tuple[str, str, str], bool | None] = {}
        self.confirmed_digests: set[bytes] = set()

    def confirms(self, path: str, entry: tuple[str, str]) -> bool | None:
        """Takes the path and its `(mode, object)` entry. Returns whether the blob confirms, or
        None when it could not be read. A directory or a submodule never confirms."""
        mode, oid = entry
        if mode.startswith(("040", "160")):
            return False
        judged = (path, mode, oid)
        if judged not in self._verdicts:
            blob = stdout_bytes(self._repo, ["cat-file", "blob", oid])
            self._verdicts[judged] = (None if blob is None else
                                      bool(content_confirms(blob, path, self._payload,
                                                            self._allowlist, self._opts,
                                                            is_symlink=mode == "120000")))
            if self._verdicts[judged]:
                self.confirmed_digests.add(hashlib.sha256(blob).digest())
        return self._verdicts[judged]


def path_key(repo: Path):
    """`key(path) -> str` under which two spellings of one path the repository stores meet: the
    Unicode composed form, case-folded when the repository ignores case. Takes the repository."""
    folds = stdout(repo, ["config", "--get", "--type=bool", "core.ignorecase"]).strip() == "true"

    def key(path: str) -> str:
        composed = unicodedata.normalize("NFC", path)
        return composed.casefold() if folds else composed
    return key


def entries(repo: Path, args: list[str], env: dict, *, staged: bool, key=None):
    """Every `(mode, object)` git lists for each path, a conflict's stages among them. Takes the
    repository, the listing command, its environment, whether it lists the index, and
    `key(path)` the entries are filed under (the path itself when not given). Returns the entries,
    or None when git failed."""
    listed = stdout_bytes_fed(repo, args, b"", env=env or None)
    if listed is None:
        return None
    found: dict[str, list[tuple[str, str]]] = {}
    for meta, path in _records(listed):
        fields = meta.split()
        if not path or len(fields) < 3:
            continue
        found.setdefault(key(path) if key else path, []).append(
            (fields[0], fields[1] if staged else fields[2]))
    return found


def _records(listed: bytes) -> list[tuple[str, str]]:
    """The records of a NUL-separated git listing. Takes its bytes. Returns each record's fields and
    its path, the path spelled as the file system spells it."""
    out = []
    for record in listed.split(b"\0"):
        meta, _, path = record.partition(b"\t")
        out.append((meta.decode("ascii", "replace"), os.fsdecode(path)))
    return out


def _unread(path: str, opts, kept: list[str]) -> bool:
    """Whether the scan leaves a path unread. Takes the path, the scan options and the kept
    directories, which are read whole. Returns the answer."""
    parts = PurePosixPath(path).parts
    if any(path == k or path.startswith(f"{k}/") for k in kept):
        return False
    return any(part in (getattr(opts, "exclude_dirs", None) or ()) for part in parts[:-1])


def _skipped_within(repo: Path, opts, read_whole: list[str], leave_out=()) -> list[str]:
    """The directories on disk the scan leaves out by name, other than git's store and saw's own
    at the root.

    Takes the repository, the scan options, the directories already read whole, and the names to
    leave out of the answer. Returns each outermost one, relative to the repository.
    """
    names = set(getattr(opts, "exclude_dirs", None) or ()) - {".git"}
    found: list[str] = []
    for top, dirs, _ in os.walk(repo):
        rel_top = Path(top).relative_to(repo).as_posix()
        for name in list(dirs):
            rel = name if rel_top == "." else f"{rel_top}/{name}"
            if name == ".git" or rel == SAW_DIR or rel in read_whole:
                dirs.remove(name)
            elif name in names:
                dirs.remove(name)
                if name not in leave_out and not os.path.islink(os.path.join(top, name)):
                    found.append(rel)
    return sorted(found)


def _digests(repo: Path, findings, limit: int) -> set[bytes]:
    """The SHA-256 digests of the bytes each confirmed path reads as, through a link too. Takes the
    repository, the findings and the largest file to read. Returns the digests of those that are
    files within `limit` it could read."""
    digests: set[bytes] = set()
    for path in {f.path for f in findings}:
        target = Path(repo) / path
        try:
            if target.is_file() and target.stat().st_size <= limit:
                digests.add(hashlib.sha256(target.read_bytes()).digest())
        except OSError:
            continue
    return digests


def _kept_within(repo: Path, keep) -> list[str]:
    """The kept directories, as paths under the repository. Takes the repository and the
    directories to keep. Returns each one that is there, written relative to the repository."""
    root = Path(repo)
    return sorted({k.relative_to(root).as_posix() for k in installed.kept_paths(root, keep)
                   if k.is_dir() and not k.is_symlink()})


def _directory(repo: Path, opts, within: str):
    """A target reading one directory of the checkout whole, as files rather than as the repository.
    Takes the repository, the scan options and the directory. Returns the target."""
    from stayawake.bots.security.targets import LocalRepoTarget
    target = LocalRepoTarget(repo, str(repo), _reading_everything(opts), within=within)
    target.is_repo = False
    return target


def _reading_everything(opts):
    """The scan options with nothing left out but git's own store. Takes the options. Returns the
    options a directory read whole is read with."""
    excluded = getattr(opts, "exclude_dirs", None)
    if not isinstance(excluded, set):
        return opts
    return replace(opts, exclude_dirs=excluded & {".git"})
