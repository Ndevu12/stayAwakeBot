#!/usr/bin/env python3
"""What a `git push` would publish: the file versions its commits introduce, read from the objects
the repository holds."""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

from stayawake.lib.git.objects import own_view, own_view_fed

_OBJECT_ID = re.compile(r"[0-9a-f]{40}(?:[0-9a-f]{24})?")
_FILE_MODES = frozenset({b"100644", b"100755"})
_LINK_MODE = b"120000"
_SUBMODULE_MODE = b"160000"
_INTRODUCING = frozenset({b"A", b"M", b"T"})

NEW_WORK = "new work"
SERVED = "served"
HISTORY = "history"


def is_absent(oid: str) -> bool:
    """Whether an object name is git's all-zero placeholder. Takes the name. Returns the answer."""
    return not oid.strip("0")


@dataclass(frozen=True)
class PushUpdate:
    """One line git gives a pre-push hook: a ref being pushed and what the remote holds for it."""

    local_ref: str
    local_oid: str
    remote_ref: str
    remote_oid: str

    @property
    def publishes(self) -> bool:
        """Whether this line sends anything: a deletion or an unchanged ref does not."""
        return not is_absent(self.local_oid) and self.local_oid != self.remote_oid


def read_push_updates(text: str) -> list[PushUpdate] | None:
    """Read the lines git gives a pre-push hook. Takes the text. Returns one update per line, or
    None when a line is not in git's four-field form."""
    updates = []
    for line in text.splitlines():
        if not line.strip():
            continue
        fields = line.split(" ")
        if (len(fields) != 4 or not _OBJECT_ID.fullmatch(fields[1])
                or not _OBJECT_ID.fullmatch(fields[3])):
            return None
        updates.append(PushUpdate(*fields))
    return updates


@dataclass(frozen=True)
class Introduced:
    """A file version a push would publish."""

    path: str
    oid: str
    link: bool
    commit: str
    role: str


@dataclass
class PushScope:
    """Everything a push would publish, as far as it was established."""

    entries: list[Introduced] = field(default_factory=list)
    history: list[tuple[str, list[str]]] = field(default_factory=list)
    history_role: str = HISTORY
    merges: list[str] = field(default_factory=list)
    history_merges: list[str] = field(default_factory=list)
    tips: dict[str, str] = field(default_factory=dict)
    unnamed: list[str] = field(default_factory=list)
    submodules: int = 0
    complete: bool = True


def introduced(repo: str | Path, updates: list[PushUpdate], *, remote: str | None = None,
               limit: int = 200_000) -> PushScope | None:
    """Establish what a push would publish: what its new work adds, what each pushed ref will serve
    that it did not serve before, and the commits the remote is not shown to hold but was last seen
    to hold, whose versions `history_entries` lists. Takes the repo, the pushed updates, the remote
    the push goes to, and a bound on the versions collected. Returns the scope, or None when git
    could not answer."""
    live = [u for u in updates if u.publishes]
    scope = PushScope()
    if not live:
        return scope
    kinds = _peeled(repo, [u.local_oid for u in live])
    held = _held(repo, [u.remote_oid for u in live if not is_absent(u.remote_oid)])
    if kinds is None or held is None:
        return None
    for update in live:
        oid, kind = kinds[update.local_oid]
        if kind == "commit":
            scope.tips.setdefault(oid, update.local_ref)
        elif kind == "blob":
            scope.unnamed.append(oid)
    found: list[tuple[str, str, bytes, str]] = []
    if scope.tips:
        commits = _commits(repo, list(scope.tips), sorted(held))
        if commits is None:
            return None
        believed = _believed(repo, remote, live)
        newer = _commits(repo, list(scope.tips), sorted(held), extra=believed) if believed else None
        if newer is None:
            work, scope.history, scope.history_role = [], commits, NEW_WORK
            scope.history_merges = [c for c, parents in commits if len(parents) > 1]
        else:
            fresh = {c for c, _parents in newer}
            work = [(c, parents) for c, parents in commits if c in fresh]
            scope.history = [(c, parents) for c, parents in commits if c not in fresh]
        scope.merges = [c for c, parents in work if len(parents) > 1]
        raw = _introduced_by(repo, work)
        if raw is None:
            return None
        found += [(commit, path, meta, NEW_WORK) for commit, meta, path in _diff_entries(raw)]
    for update in live:
        tip, kind = kinds[update.local_oid]
        if kind == "blob":
            continue
        if not is_absent(update.remote_oid) and update.remote_oid in held:
            raw = own_view_fed(repo, ["diff-tree", "-r", "-z", "--raw", "--no-renames",
                                      update.remote_oid, tip], b"")
            served = None if raw is None else [(m, p) for _c, m, p in _diff_entries(raw)]
        else:
            served = _whole_tree(repo, tip)
        if served is None:
            return None
        found += [(tip if kind == "commit" else "", path, meta, SERVED) for meta, path in served]
    order = {NEW_WORK: 0, SERVED: 1}
    scope.entries, scope.submodules, scope.complete = _collect(
        sorted(found, key=lambda f: order[f[3]]), limit)
    return scope


def history_entries(repo: str | Path, commits: list[tuple[str, list[str]]], *, role: str = HISTORY,
                    limit: int = 200_000) -> tuple[list[Introduced], int, bool] | None:
    """List what the history a push carries adds. Takes the repo, the commits with their parents,
    the role to give each version and a bound on the versions collected. Returns the versions, the
    submodule commits among them and whether every one was listed, or None when git could not
    answer."""
    if not commits:
        return [], 0, True
    raw = _introduced_by(repo, commits)
    if raw is None:
        return None
    return _collect([(commit, path, meta, role) for commit, meta, path in _diff_entries(raw)], limit)


def _introduced_by(repo: str | Path, commits: list[tuple[str, list[str]]]) -> bytes | None:
    """Ask git what each commit adds against its first parent. Takes the repo and the commits with
    their parents. Returns the raw listing, or None when git could not answer."""
    if not commits:
        return b""
    feed = "".join(f"{c} {parents[0]}\n" if parents else f"{c}\n" for c, parents in commits)
    return own_view_fed(repo, ["diff-tree", "--stdin", "-r", "-z", "--raw", "--no-renames",
                               "--root"], feed.encode())


def _collect(found, limit: int) -> tuple[list[Introduced], int, bool]:
    """Keep each file version once, in order, and count submodule commits. Takes the listed
    entries and the bound. Returns the versions, the submodule count and whether all were kept."""
    seen: set[tuple[str, str]] = set()
    entries: list[Introduced] = []
    submodules = 0
    for commit, path, (mode, oid, status), role in found:
        if status not in _INTRODUCING or (path, oid) in seen:
            continue
        seen.add((path, oid))
        if mode == _SUBMODULE_MODE:
            submodules += 1
        elif mode in _FILE_MODES or mode == _LINK_MODE:
            entries.append(Introduced(path, oid, mode == _LINK_MODE, commit, role))
            if len(entries) > limit:
                return entries, submodules, False
    return entries, submodules, True


_REMOTE_NAME = re.compile(r"[A-Za-z0-9._/-]{1,255}")


def _believed(repo: str | Path, remote: str | None, live: list[PushUpdate]) -> list[str]:
    """Decide whether the remote's tracking refs may stand for what it was last seen to hold. Takes
    the repo, the remote and the pushed updates. Returns the revision arguments naming them, or none
    when the remote is unnamed or a pushed branch it holds does not match its tracking ref."""
    if not remote or not _REMOTE_NAME.fullmatch(remote):
        return []
    out = own_view_fed(repo, ["for-each-ref", "--format=%(refname) %(objectname)",
                              f"refs/remotes/{remote}/"], b"")
    if out is None:
        return []
    tracked = dict(line.split(" ", 1) for line in out.decode("utf-8", "replace").splitlines()
                   if " " in line)
    if not tracked:
        return []
    for update in live:
        if is_absent(update.remote_oid) or not update.remote_ref.startswith("refs/heads/"):
            continue
        name = f"refs/remotes/{remote}/{update.remote_ref[len('refs/heads/'):]}"
        if tracked.get(name) != update.remote_oid:
            return []
    return [f"--remotes={remote}"]


def _peeled(repo: str | Path, oids: list[str]) -> dict[str, tuple[str, str]] | None:
    """Peel each pushed object to what it names. Takes the repo and the ids. Returns each id mapped
    to `(peeled id, type)`, or None when git could not answer for all of them."""
    wanted = list(dict.fromkeys(oids))
    out = own_view_fed(repo, ["cat-file", "--batch-check"],
                       "".join(f"{oid}^{{}}\n" for oid in wanted).encode())
    if out is None:
        return None
    lines = out.decode("utf-8", "replace").splitlines()
    if len(lines) != len(wanted):
        return None
    found = {}
    for oid, line in zip(wanted, lines):
        parts = line.split()
        if len(parts) != 3 or parts[1] not in ("commit", "tree", "blob"):
            return None
        found[oid] = (parts[0], parts[1])
    return found


def _held(repo: str | Path, oids: list[str]) -> set[str] | None:
    """Ask which objects the repository holds. Takes the repo and the ids. Returns the ones held, or
    None when git could not answer."""
    wanted = list(dict.fromkeys(oids))
    if not wanted:
        return set()
    out = own_view_fed(repo, ["cat-file", "--batch-check"], "\n".join(wanted).encode())
    if out is None:
        return None
    lines = out.decode("utf-8", "replace").splitlines()
    if len(lines) != len(wanted):
        return None
    return {oid for oid, line in zip(wanted, lines)
            if len(line.split()) == 3 and line.split()[0] == oid}


def _commits(repo: str | Path, tips: list[str], exclude: list[str], *,
             extra: list[str] | None = None) -> list[tuple[str, list[str]]] | None:
    """List the commits reachable from the tips and not from what is excluded. Takes the repo, the
    tips, the ids to exclude and any further revisions to exclude. Returns each commit with its
    parents, or None when git could not answer."""
    args = ["rev-list", "--parents", *tips]
    if exclude or extra:
        args += ["--not", *exclude, *(extra or [])]
    out = own_view_fed(repo, args, b"")
    if out is None:
        return None
    commits = []
    for line in out.decode("ascii", "replace").splitlines():
        ids = line.split()
        if ids:
            commits.append((ids[0], ids[1:]))
    return commits


def _diff_entries(raw: bytes):
    """Read a `diff-tree --stdin -z --raw` stream. Takes the stream. Yields
    `(commit, (new mode, new id, status), path)` per entry."""
    commit = ""
    fields = raw.split(b"\0")
    at = 0
    while at < len(fields):
        token = fields[at]
        if token.startswith(b":") and at + 1 < len(fields):
            meta = token[1:].split(b" ")
            if len(meta) == 5:
                yield (commit, (meta[1], meta[3].decode("ascii", "replace"), meta[4][:1]),
                       fields[at + 1].decode("utf-8", "surrogateescape"))
            at += 2
            continue
        if token.strip():
            commit = token.split()[0].decode("ascii", "replace")
        at += 1


def _whole_tree(repo: str | Path, tree_ish: str) -> list[tuple[tuple[bytes, str, bytes], str]] | None:
    """List every entry a tree holds, as an addition. Takes the repo and the tree or commit. Returns
    `((mode, id, status), path)` per entry, or None when git could not answer."""
    raw = own_view_fed(repo, ["ls-tree", "-r", "-z", "--full-tree", tree_ish], b"")
    if raw is None:
        return None
    entries = []
    for record in raw.split(b"\0"):
        head, tab, name = record.partition(b"\t")
        parts = head.split(b" ")
        if tab and len(parts) == 3:
            entries.append(((parts[0], parts[2].decode("ascii", "replace"), b"A"),
                            name.decode("utf-8", "surrogateescape")))
    return entries


def remote_for_url(repo: str | Path, url: str) -> str | None:
    """Name the configured remote a URL belongs to. Takes the repo and the URL. Returns the remote's
    name, or None when no remote, or more than one, uses that URL."""
    out = own_view(repo, ["config", "--get-regexp", r"^remote\..*\.(url|pushurl)$"])
    if out is None or out.returncode not in (0, 1):
        return None
    names = set()
    wanted = _same_url(url)
    for line in out.stdout.splitlines():
        key, _sep, value = line.partition(" ")
        if _same_url(value) == wanted and key.startswith("remote.") and key.count(".") >= 2:
            names.add(key[len("remote."):key.rindex(".")])
    return names.pop() if len(names) == 1 else None


def _same_url(url: str) -> str:
    """Spell a remote URL one way, so two spellings of one address compare equal. Takes the URL.
    Returns it without a `file://` prefix, trailing slashes or a trailing `.git`."""
    url = url.strip()
    if url.startswith("file://"):
        url = url[len("file://"):]
    url = url.rstrip("/")
    return url[:-len(".git")] if url.endswith(".git") else url
