#!/usr/bin/env python3
"""Read-only git queries — answer questions about a repository's history and trees WITHOUT
ever executing repository code. The evil-merge detector and the recovery walks build on these.

`fetch_refs` is the one helper here that writes: it refreshes the remote-tracking refs the
other queries read, because a query can only answer for refs the clone actually has."""
from __future__ import annotations

import os
import re
from dataclasses import dataclass
from pathlib import Path

from stayawake.lib.git import remote as gitremote
from stayawake.lib.git.objects import (batch_objects, blob_text, link_targets, own_env, own_view,
                                       own_view_fed)
from stayawake.lib.git.run import run, stdout, stdout_bytes, stdout_bytes_fed


def is_git_repo(repo: str | Path) -> bool:
    return stdout(repo, ["rev-parse", "--is-inside-work-tree"]).strip() == "true"


def slug_from_url(url: str) -> str | None:
    """Parse 'owner/name' from a GitHub SSH or HTTPS remote URL (pure — no git call).
    Returns None for a non-GitHub URL, so callers can tell 'not GitHub' from a parse error."""
    m = re.search(r"github\.com[:/]([^/]+/[^/]+?)(?:\.git)?/?$", url.strip())
    return m.group(1) if m else None


def origin_slug(repo: str | Path) -> str | None:
    """'owner/name' for the repo's `origin` remote (SSH or HTTPS), else None (no origin,
    or a non-GitHub origin)."""
    return slug_from_url(stdout(repo, ["remote", "get-url", "origin"]))


def default_branch(repo: str | Path) -> str:
    """The remote's default branch (via `origin/HEAD`), falling back to 'main' when there is
    no origin / it isn't resolvable — so `saw fix` still has a base branch to build on offline."""
    out = stdout(repo, ["symbolic-ref", "refs/remotes/origin/HEAD"]).strip()
    return out.rsplit("/", 1)[-1] if out else "main"


def names_a_commit(repo: str | Path, ref: str) -> bool:
    """Whether a ref resolves to a commit. Takes the repo and the ref. Returns False when it names
    none. Raises `Unread` naming the ref when git could not tell."""
    res = run(repo, ["rev-parse", "--verify", "--quiet", f"{ref}^{{commit}}"])
    if res is None or res.returncode not in (0, 1):
        raise Unread(ref)
    return res.returncode == 0


def ref_exists(repo: str | Path, ref: str) -> bool:
    """True if `ref` resolves in `repo` (a branch, tag, or `origin/<branch>`). Used to prefer a
    fresh `origin/<base>` but fall back to the local base so remediation works offline."""
    res = run(repo, ["rev-parse", "--verify", "--quiet", ref])
    return res is not None and res.returncode == 0


def ancestry(repo: str | Path, ancestor: str, descendant: str) -> bool | None:
    """Ask whether one commit is an ancestor of another. Takes the repo and the two commits. Returns
    the answer, or None when git could not give one."""
    res = own_view(repo, ["merge-base", "--is-ancestor", ancestor, descendant])
    if res is None or res.returncode not in (0, 1):
        return None
    return res.returncode == 0


def tracked_under(repo: str | Path, pathspec: str | Path) -> list[str]:
    """Tracked paths under `pathspec` (empty if none). Distinct from `tracked` (one exact path):
    this answers 'is ANYTHING under this directory still tracked?' — the rollback-store-clean check."""
    out = stdout(repo, ["ls-files", "--", str(pathspec)])
    return [ln for ln in out.splitlines() if ln.strip()]


def remote_has_branch(remote: str, branch: str, *, repo: str | Path | None = None,
                      env: dict | None = None) -> bool:
    """True if `branch` exists on `remote` (a remote name like 'origin', or an explicit URL).
    `repo=None` runs `ls-remote` against an explicit URL with no local clone (the by-slug
    discard path); `env` carries credential-safe auth (see `github_https_auth`)."""
    url = gitremote.resolve(remote, repo)
    res = None if url is None else gitremote.ls_remote(url, ["--heads", branch], env=env)
    return res is not None and res.returncode == 0 and bool(res.stdout.strip())


def ref_counts(repo: str | Path) -> tuple[int, int]:
    """(branches, tags) in `repo`. Zero for either when they cannot be listed."""
    def _n(pattern: str) -> int:
        out = stdout(repo, ["for-each-ref", "--format=%(refname)", pattern])
        return len([l for l in out.splitlines() if l.strip()])
    return _n("refs/heads"), _n("refs/tags")


def commit_count(repo: str | Path, ref: str = "HEAD") -> int | None:
    """Commits reachable from `ref`, or None when it cannot be counted (no commits, unreadable)."""
    out = stdout(repo, ["rev-list", "--count", ref]).strip()
    return int(out) if out.isdigit() else None


_TYPE_MASK, _LINK_TYPE, _TREE_TYPE, _FILE_TYPE = 0o170000, 0o120000, 0o040000, 0o100000
_ENTRY_TYPES = (_FILE_TYPE, _LINK_TYPE, _TREE_TYPE, 0o160000)
_OBJECT_ID_BYTES = 20


def holds_its_history(repo: str | Path) -> bool:
    """Ask whether a repository holds its whole history: not a shallow clone, and not one that
    fetches objects on demand. Takes the repo. Returns False when it does not, or when that could not
    be told."""
    res = own_view(repo, ["rev-parse", "--is-shallow-repository"])
    return (res is not None and res.returncode == 0 and (res.stdout or "").strip() == "false"
            and holds_its_objects(repo))


def holds_its_objects(repo: str | Path) -> bool:
    """Ask whether a repository holds the objects it names. Takes the repo. Returns False when it
    would reach a remote for them, or when the question could not be answered."""
    res = run(repo, ["config", "--get-regexp",
                     r"^(remote\..*\.promisor|extensions\.partialclone)$"], env=own_env())
    return res is not None and not (res.stdout or "").strip()


def _entry_type(mode: bytes) -> int | None:
    """Read a tree entry's mode as the object type git gives it. Takes the mode field. Returns the
    type bits, or None for a mode that names no type git records."""
    try:
        bits = int(mode, 8) & _TYPE_MASK
    except ValueError:
        return None
    return bits if bits in _ENTRY_TYPES else None


def _tree_entries(body: bytes) -> tuple[list, bool]:
    """Split a tree object into its entries. Takes the object's body. Returns `(mode, name, id)`
    per entry, and whether they parsed to the end."""
    entries, pos = [], 0
    while pos < len(body):
        space = body.find(b" ", pos)
        nul = body.find(b"\0", space + 1)
        if space == -1 or nul == -1 or nul + 1 + _OBJECT_ID_BYTES > len(body):
            break
        entries.append((body[pos:space], body[space + 1:nul],
                        body[nul + 1:nul + 1 + _OBJECT_ID_BYTES].hex()))
        pos = nul + 1 + _OBJECT_ID_BYTES
    return entries, pos == len(body)


def _read_trees(repo: str | Path, ids: list[str]) -> tuple[dict[str, list], bool]:
    """Read tree objects in one batch. Takes the repo and the ids. Returns each one's entries, and
    whether every id asked for was read whole."""
    if not ids:
        return {}, True
    raw = own_view_fed(repo, ["cat-file", "--batch"], "\n".join(ids).encode())
    if raw is None:
        return {}, False
    out: dict[str, list] = {}
    complete = True
    for oid, kind, body, whole in batch_objects(raw):
        if not whole or kind != "tree":
            complete = False
            continue
        out[oid], ended = _tree_entries(body)
        complete = complete and ended
    return out, complete and len(out) == len(ids)


def stored_entries(repo: str | Path, *, limit: int = 200_000,
                   offline: bool = True) -> tuple[dict[str, list[tuple[str, int]]], bool]:
    """Walk a repository's reachable history and collect what it stores at every path. Takes the
    repo, a bound on the paths visited and whether the read must stay local. Returns each path
    mapped to the `(object id, entry type)` pairs stored there, and whether the whole history was
    read."""
    if offline and not holds_its_objects(repo):
        return {}, False
    roots = own_view(repo, ["rev-list", "--all", "--format=%T"])
    refs = own_view(repo, ["for-each-ref", "--format=%(refname)"])
    if roots is None or roots.returncode != 0 or refs is None or refs.returncode != 0:
        return {}, False
    complete = not roots.stderr.strip()
    named = [ln.strip() for ln in roots.stdout.splitlines() if not ln.startswith("commit ")]
    wanted = [ln.strip() for ln in refs.stdout.splitlines() if ln.strip()]
    peeled = own_view_fed(repo, ["cat-file", "--batch-check"],
                           "".join(f"{ref}^{{tree}}\n" for ref in wanted).encode())
    targets = own_view_fed(repo, ["cat-file", "--batch-check"],
                           "".join(f"{ref}^{{}}\n" for ref in wanted).encode())
    if peeled is None or targets is None:
        return {}, False
    lines = peeled.decode("utf-8", "replace").splitlines()
    kinds = targets.decode("utf-8", "replace").splitlines()
    complete = complete and len(lines) == len(wanted) == len(kinds)
    named += [p[0] for p in (ln.split() for ln in lines) if len(p) == 3 and p[1] == "tree"]
    out: dict[str, list[tuple[str, int]]] = {}
    for ref, line in zip(wanted, kinds):
        parts = line.split()
        if len(parts) == 3 and parts[1] == "blob":
            out.setdefault(f"/{ref}", []).append((parts[0], _FILE_TYPE))
    seen: set[tuple[str, str]] = set()
    level = [(tree, "") for tree in dict.fromkeys(named) if tree]
    while level:
        level = [pair for pair in dict.fromkeys(level) if pair not in seen]
        if not level:
            break
        if len(seen) + len(level) > limit:
            return out, False
        seen.update(level)
        entries_of, read_all = _read_trees(repo, sorted({tree for tree, _ in level}))
        complete = complete and read_all
        deeper = []
        for tree, base in level:
            for mode, name, sha in entries_of.get(tree, ()):
                kind = _entry_type(mode)
                rel = name.decode("utf-8", "replace")
                path = f"{base}/{rel}" if base else rel
                if kind == _TREE_TYPE:
                    deeper.append((sha, path))
                elif kind is None:
                    complete = False
                elif (sha, kind) not in out.setdefault(path, []):
                    out[path].append((sha, kind))
        level = deeper
    return out, complete and _all_readable(repo, out)


def _all_readable(repo: str | Path, at_path: dict) -> bool:
    """Ask whether every object a walk collected can be read back. Takes the repo and what it
    collected. Returns True when git answered for all of them."""
    wanted = sorted({sha for entries in at_path.values() for sha, _kind in entries})
    if not wanted:
        return True
    answered = own_view_fed(repo, ["cat-file", "--batch-check"], "\n".join(wanted).encode())
    if answered is None:
        return False
    good = {ln.split()[0] for ln in answered.decode("utf-8", "replace").splitlines()
            if len(ln.split()) == 3 and ln.split()[1] in ("blob", "commit")}
    return good >= set(wanted)


def stored_as_links(repo: str | Path, *, limit: int = 200_000,
                    offline: bool = True) -> tuple[dict[str, set[str]], bool]:
    """Search a repository's reachable history for the paths it stores a symlink at. Takes the repo,
    a bound on the paths visited and whether the read must stay local. Returns those paths mapped to
    the blob ids stored there, and whether the whole history was read."""
    at_path, complete = stored_entries(repo, limit=limit, offline=offline)
    return ({path: {sha for sha, kind in entries if kind == _LINK_TYPE}
             for path, entries in at_path.items()
             if any(kind == _LINK_TYPE for _sha, kind in entries)}, complete)


def stored_link_targets(repo: str | Path, *, limit: int = 200_000,
                        offline: bool = True) -> tuple[dict[str, list[str]], bool]:
    """Read the target stored at each path a repository's history holds a symlink at. Takes the repo
    and a bound on the paths visited. Returns those paths mapped to the targets stored there, and
    whether every one of them was established."""
    at_path, complete = stored_as_links(repo, limit=limit, offline=offline)
    if not at_path:
        return {}, complete
    text_of, read_all = link_targets(repo, [sha for shas in at_path.values() for sha in shas])
    if not text_of and not read_all:
        return {}, False
    out, every = {}, True
    for rel, shas in at_path.items():
        raws = [text_of[sha] for sha in sorted(shas) if sha in text_of]
        every = every and len(raws) == len(shas)
        if raws:
            out[rel] = raws
    return out, complete and every and read_all


def reachable_blobs(repo: str | Path, *, limit: int = 200_000,
                    offline: bool = True) -> tuple[list[tuple[str, str]], bool]:
    """Collect every blob a repository's reachable history stores, at every path it stores it at.
    Takes the repo, a bound on the paths visited and whether the read must stay local. Returns
    `(object id, path)` per stored version, and whether the whole history was read."""
    at_path, complete = stored_entries(repo, limit=limit, offline=offline)
    out = [(sha, path) for path, entries in sorted(at_path.items())
           for sha, kind in entries if kind in (_FILE_TYPE, _LINK_TYPE)]
    return out, complete


def _holds_the_tree(here: str, root: str) -> bool:
    """Ask whether a path contains a repository's whole working tree. Takes the path and the
    repository root, both resolved. Returns True when it is that root or an ancestor of it."""
    return here == root or root.startswith(here.rstrip(os.sep) + os.sep)


def exec_paths(repo: str | Path) -> set[str]:
    """Ask a repository where it executes from. Takes the repo. Returns the resolved hooks directory
    and config file, empty when git could not say."""
    try:
        root = os.path.realpath(str(repo))
    except (OSError, ValueError):
        root = os.path.normpath(str(repo))
    out = set()
    for what in ("hooks", "config"):
        res = run(repo, ["rev-parse", "--git-path", what], env=own_env())
        if res is None or res.returncode != 0:
            continue
        answer = (res.stdout or "").strip()
        if not answer:
            continue
        here = answer if os.path.isabs(answer) else os.path.join(str(repo), answer)
        try:
            here = os.path.realpath(here)
        except (OSError, ValueError):
            here = os.path.normpath(here)
        if not _holds_the_tree(here, root):
            out.add(here)
    return out


def branches_matching(repo: str | Path, pattern: str) -> list[str]:
    """Local branch names matching a glob, e.g. 'security/auto-clean*'."""
    out = stdout(repo, ["for-each-ref", "--format=%(refname:short)", f"refs/heads/{pattern}"])
    return [ln.strip() for ln in out.splitlines() if ln.strip()]


@dataclass(frozen=True)
class FetchResult:
    """Outcome of `fetch_refs`. `ok=False` means the remote-tracking refs were NOT refreshed and
    `reason` says why — a refusal the caller must surface, never a smaller branch set."""
    ok: bool
    reason: str = ""


def fetch_refs(repo: str | Path, *, token: str | None = None) -> FetchResult:
    """Refresh every `refs/remotes/origin/*` from the remote, pruning the ones it no longer has.
    Implemented by `write.fetch.fetch_refs`."""
    from stayawake.lib.git.write.fetch import fetch_refs as refresh
    return refresh(repo, token=token)


_LOCAL_REF = "refs/heads/"
_ORIGIN_REF = "refs/remotes/origin/"
_NOT_A_BRANCH = ("refs/remotes/origin/HEAD", "refs/remotes/origin/notes",
                 "refs/remotes/origin/notes/*", "refs/remotes/origin/replace/*")
"""The origin refs `branch_name_of` rejects, as globs a rev walk can exclude. Kept beside it because
the two must answer alike; `test_ref_scope` pins that they do."""


def branch_name_of(ref: str) -> str:
    """Name the branch a ref stands for, for every part of an amend that has to agree on which refs
    it may update. Takes the full ref name. Returns the short branch name, or "" for a ref that is
    not such a branch — origin's HEAD, notes and replace refs among them."""
    if ref.startswith(_LOCAL_REF):
        return ref[len(_LOCAL_REF):]
    if not ref.startswith(_ORIGIN_REF):
        return ""
    short = ref[len(_ORIGIN_REF):]
    if not short or short == "HEAD" or short == "notes":
        return ""
    if short.startswith("notes/") or short.startswith("replace/"):
        return ""
    return short


def _branch_targets(repo: str | Path) -> dict[str, str] | None:
    """The object id each local head and fetched origin branch names, by ref, read without opening
    the objects. Takes the repo. Returns them, or None when git could not list them."""
    res = own_view(repo, ["for-each-ref", "--format=%(objectname) %(refname)",
                          _LOCAL_REF.rstrip("/"), _ORIGIN_REF.rstrip("/")])
    if res is None or res.returncode != 0:
        return None
    targets = {}
    for line in (res.stdout or "").splitlines():
        oid, _, ref = line.strip().partition(" ")
        if branch_name_of(ref):
            targets[ref] = oid
    return targets


def listed_branch_refs(repo: str | Path) -> list[tuple[str, str]] | None:
    """List every ref an amend has to read history from. Takes the repo. Returns `(name, ref)` for
    each local head and each fetched origin branch, keeping BOTH where a name has one of each: a
    local head and the origin ref of the same name diverge, and either may hold a version the other
    does not. None when git could not list them."""
    targets = _branch_targets(repo)
    return None if targets is None else sorted((branch_name_of(ref), ref) for ref in targets)


def unreadable_branch_refs(repo: str | Path) -> list[str] | None:
    """Find the refs an amend reads history from that name no commit the repository holds. Takes the
    repo. Returns them, or None when git could not list them."""
    targets = _branch_targets(repo)
    if targets is None:
        return None
    if not targets:
        return []
    refs = sorted(targets)
    kinds = own_view_fed(repo, ["cat-file", "--batch-check=%(objecttype)"],
                         "\n".join(targets[ref] for ref in refs).encode())
    answers = (kinds or b"").decode("ascii", "replace").splitlines()
    if len(answers) != len(refs):
        return None
    return [ref for ref, kind in zip(refs, answers) if not kind.endswith("commit")]


_BRANCH_WALK = (*(f"--exclude={glob}" for glob in _NOT_A_BRANCH), f"--glob={_ORIGIN_REF}*",
                "--branches", "--full-history")


def branches_carrying(repo: str | Path, sha: str) -> list[tuple[str, str, str]] | None:
    """Find every branch that still reaches `sha`. Takes the repo and the sha. Returns
    `(name, replay_tip, cas_old)` per branch, where `cas_old` is the local tip, or the zero SHA when
    no local ref of that name exists yet; a local head for the same name wins the tip. None when git
    could not answer."""
    res = run(repo, ["rev-parse", sha])
    if res is None or res.returncode != 0:
        return None
    full = (res.stdout or "").strip() or sha
    found: dict[str, str] = {}
    local_tips: dict[str, str] = {}
    for scope in (_ORIGIN_REF.rstrip("/"), _LOCAL_REF.rstrip("/")):
        res = run(repo, ["for-each-ref", "--format=%(refname) %(objectname)",
                         f"--contains={full}", scope])
        if res is None or res.returncode != 0:
            return None
        for line in (res.stdout or "").splitlines():
            parts = line.split()
            if len(parts) != 2:
                continue
            ref, tip = parts[0].strip(), parts[1].strip()
            name = branch_name_of(ref)
            if not name:
                continue
            if ref.startswith(_LOCAL_REF):
                local_tips[name] = tip
            found[name] = tip
    zero = "0" * 40
    return [(name, tip, local_tips.get(name, zero)) for name, tip in found.items()]


def remote_branches_matching(remote: str, pattern: str, *, repo: str | Path | None = None,
                             env: dict | None = None) -> list[str] | None:
    """Branch names on `remote` matching a glob. `None` when the remote could not be listed —
    an empty list means it answered and nothing matched."""
    url = gitremote.resolve(remote, repo)
    res = None if url is None else gitremote.ls_remote(url, ["--heads", pattern], env=env)
    if res is None or res.returncode != 0:
        return None
    return [ln.split("refs/heads/", 1)[1].strip()
            for ln in res.stdout.splitlines() if "refs/heads/" in ln]


def parents(repo: str | Path, sha: str) -> list[str] | None:
    """The parents a commit stores. Takes the repo and the commit. Returns them, or None when git
    could not read the commit."""
    res = run(repo, ["rev-list", "--parents", "-n", "1", sha])
    out = (res.stdout or "").split() if res is not None and res.returncode == 0 else []
    return out[1:] if out else None


def changed_paths(repo: str | Path, base: str, target: str,
                  diff_filter: str | None = None, *, renames: bool = True) -> set[str]:
    """Compare two commits or trees and list the paths that differ. Takes the repo, the base, the
    target, the `git diff --diff-filter` letters to keep, and whether a renamed file is reported as
    renamed. Returns the paths. Raises `Unread` when git could not compare them."""
    args = ["diff", "--name-only", "-z"]
    if not renames:
        args.append("--no-renames")
    if diff_filter:
        args.append(f"--diff-filter={diff_filter}")
    args += [base, target]
    res = run(repo, args)
    if res is None or res.returncode != 0:
        raise Unread(f"what {target[:12]} changes")
    return {p for p in (res.stdout or "").split("\0") if p}


TREE_MODE = "040000"
GITLINK_MODE = "160000"


class Unread(Exception):
    """Git could not read something a decision rests on. `subject` names it for the operator."""

    def __init__(self, subject: str):
        super().__init__(subject)
        self.subject = subject


_ARGV_BUDGET = 32_768


def _batches(paths: list[str]):
    """`paths` in order, in batches whose total length stays within one command line."""
    batch: list[str] = []
    size = 0
    for path in paths:
        if batch and size + len(path) > _ARGV_BUDGET:
            yield batch
            batch, size = [], 0
        batch.append(path)
        size += len(path) + 1
    if batch:
        yield batch


def _parents_of(path: str) -> list[str]:
    parts = path.split("/")[:-1]
    return ["/".join(parts[:depth]) for depth in range(1, len(parts) + 1)]


def _entries(repo: str | Path, args: list[str]) -> dict[str, tuple[str, str]] | None:
    """The `(mode, oid)` of each entry `ls-tree -z <args>` names, by path, as the repository stores
    them. Takes the repo and the arguments. Returns them, or None when git could not answer."""
    res = own_view(repo, ["ls-tree", "-z", "--full-tree", *args])
    if res is None or res.returncode != 0:
        return None
    found: dict[str, tuple[str, str]] = {}
    for record in filter(None, (res.stdout or "").split("\0")):
        head, tab, name = record.partition("\t")
        fields = head.split()
        if not tab or len(fields) < 3:
            return None
        found[name] = (fields[0], fields[2])
    return found


def entry_at(repo: str | Path, treeish: str, path: str) -> tuple[bool, tuple[str, str] | None]:
    """Ask for the entry at a path in a commit or tree, as the repository stores it. Takes the repo,
    the commit or tree and the path. Returns whether git answered, and the `(mode, oid)` entry: the
    path's own, the submodule's when a submodule holds the path, or None when the path is not there.

    The MODE travels with the object: writing a blob back into an index without it turns an
    executable into a plain file and a symlink into a file holding its target as text."""
    found = _entries(repo, [treeish, "--", path])
    if found is None:
        return False, None
    if path in found or not _parents_of(path):
        return True, found.get(path)
    for batch in _batches(_parents_of(path)):
        parents = _entries(repo, ["-d", treeish, "--", *batch])
        if parents is None:
            return False, None
        for parent in batch:
            if parents.get(parent, ("",))[0] == GITLINK_MODE:
                return True, parents[parent]
    return True, None


def entries_at(repo: str | Path, treeish: str, paths=None) -> dict[str, tuple[str, str]]:
    """Read the entry a commit or tree holds at each of several paths, as the repository stores
    them. Takes the repo, the commit or tree and the paths, or None for every file it holds. Returns
    the `(mode, oid)` of each path with an entry of its own there, by path. Raises `Unread` naming
    the commit when git could not answer."""
    if paths is None:
        listed = _entries(repo, ["-r", treeish])
        if listed is None:
            raise Unread(f"the files of {treeish[:12]}")
        return listed
    found: dict[str, tuple[str, str]] = {}
    for batch in _batches(list(dict.fromkeys(paths))):
        listed = _entries(repo, ["-r", "-t", treeish, "--", *batch])
        if listed is None:
            raise Unread(f"the files of {treeish[:12]}")
        found.update({path: listed[path] for path in batch if path in listed})
    return found


def file_text_at(repo: str | Path, treeish: str, path: str) -> tuple[str, str] | None:
    """Read the file a commit holds at a path, as the repository stores it. Takes the repo, the commit
    and the path. Returns its `(blob id, text)`, `("", "")` when no file is there, or None when git
    could not read it or a submodule holds the path."""
    answered, entry = entry_at(repo, treeish, path)
    if not answered:
        return None
    if entry is None or entry[0] == TREE_MODE:
        return "", ""
    text = blob_text(repo, entry[1])
    return None if text is None else (entry[1], text)


def stores_path(repo: str | Path, treeish: str, path: str) -> bool:
    """Whether a commit or tree stores content of its own at a path: a file, a link or a directory,
    not a submodule there or above it. Takes the repo, the commit or tree and the path. Raises
    `Unread` naming the path when git could not tell."""
    answered, entry = entry_at(repo, treeish, path)
    if not answered:
        raise Unread(path)
    return entry is not None and entry[0] != GITLINK_MODE


def list_tree(repo: str | Path, treeish: str, path: str | Path) -> list[str] | None:
    """Repo-relative paths of the files under `path` AT a git ref (recursive), [] when the directory
    is absent, or None when git could not read the ref. Lets a caller reason about what a ref/branch
    actually CONTAINS — e.g. what the default branch has, independent of a dirty/untracked working
    tree."""
    res = run(repo, ["ls-tree", "-r", "-z", "--name-only", treeish, "--", str(path)])
    if res is None or res.returncode != 0:
        return None
    return [name for name in (res.stdout or "").split("\0") if name]


def tracked(repo: str | Path, path: str) -> bool:
    """True if `path` is tracked in git — i.e. has committed history we could recover from."""
    res = run(repo, ["ls-files", "--error-unmatch", "--", path])
    return res is not None and res.returncode == 0


def file_commits(repo: str | Path, path: str, limit: int = 50,
                 first_parent: bool = False, all_branches: bool = False) -> list[str] | None:
    """Commit SHAs that touched `path`, newest first (bounded). The walk that the
    remediator uses to find the most recent committed version that scans clean.

    `first_parent=True` restricts the walk to the mainline (first-parent) chain from HEAD:
    a change brought in through a merge is attributed to the merge commit (whose tree at
    `path` is the version that actually landed on mainline), and a blob that only ever
    existed on a merged-in SECOND parent — never on the mainline tree — is not enumerated.
    The recovery source is itself a trust decision (an evil merge can make a "clean-looking"
    blob reachable only through its malicious side), so recovery uses this mode; the default
    keeps the full history walk for callers that want every version.

    `all_branches=True` walks every local head and every fetched origin branch — both where a name
    has one of each — with full history (no merge simplification), not only HEAD, so a version
    reachable only from a fetched branch is enumerated with the rest. The refs go in as globs, not
    one argument each, so a repository with many branches cannot outgrow the argument list.

    Reads the repository as it stores it. Returns None when git could not walk the history.
    """
    args = ["log", f"-n{limit}", "--format=%H"]
    if first_parent:
        args.append("--first-parent")
    if all_branches:
        args += _BRANCH_WALK
    args += ["--", path]
    res = own_view(repo, args)
    if res is None or res.returncode != 0:
        return None
    return [ln.strip() for ln in (res.stdout or "").splitlines() if ln.strip()]


_SHA_BYTES = frozenset(b"0123456789abcdef")


def _commit_header(token: bytes) -> bytes | None:
    """The commit id a log header token names, or None when the token is not one."""
    line = token.strip(b"\n")
    if len(line) in (40, 64) and all(c in _SHA_BYTES for c in line):
        return line
    return None


def blob_paths(repo: str | Path, oid: str, limit: int = 100_000) -> list[str] | None:
    """Every path at which the blob `oid` was ever written or removed. Takes the repo, the blob id
    and the walk bound. Returns the paths, or None when the history is longer than the bound. Raises
    `Unread` when git could not walk it."""
    args = ["-c", "log.showRoot=true", "log", f"-n{limit}", "--format=%H", "-m", "--raw", "-z",
            "--no-abbrev", f"--find-object={oid}", *_BRANCH_WALK]
    out = own_view_fed(repo, args, b"")
    if out is None:
        raise Unread(f"the copies of {oid[:12]}")
    want = oid.encode("ascii")
    commits: set[bytes] = set()
    paths: list[str] = []
    expected, matched = 0, False
    for token in out.split(b"\0"):
        if expected:
            if matched and token:
                name = token.decode("utf-8", "surrogateescape")
                if name not in paths:
                    paths.append(name)
            expected -= 1
            continue
        head, colon, meta = token.partition(b":")
        sha = _commit_header(head)
        if sha is not None:
            commits.add(sha)
        if colon:
            fields = meta.split()
            status = fields[-1] if fields else b""
            expected = 2 if status[:1] in (b"R", b"C") else 1
            matched = want in fields
    if len(commits) >= limit:
        return None
    return paths


def introduced_added_text(repo: str | Path, base_tree: str, target: str, path: str) -> str:
    """The text the diff `base_tree..target` ADDS to `path` — i.e. the merge-introduced
    hunk's `+` lines, with the leading `+` stripped and diff `+++` headers excluded.

    This is the review-evading content itself: the lines present in the recorded merge
    but NOT in the clean auto-merge of its parents. We analyse exactly this delta (never
    the whole file) so a benign conflict resolution that only re-arranges existing code
    contributes nothing for the obfuscation detector to trip on. Raises `Unread` naming the path when
    git could not compare them."""
    res = run(repo, ["diff", "--unified=0", "--no-color", base_tree, target, "--", path])
    if res is None or res.returncode != 0:
        raise Unread(path)
    added: list[str] = []
    for line in (res.stdout or "").splitlines():
        if line.startswith("+++"):
            continue
        if line.startswith("+"):
            added.append(line[1:])
    return "\n".join(added)


def commit_meta(repo: str | Path, sha: str) -> dict[str, str]:
    out = stdout(repo, ["show", "-s", "--format=%an%x09%ae%x09%cI%x09%s", sha]).strip()
    parts = out.split("\t")
    if len(parts) < 4:
        return {"sha": sha}
    return {"sha": sha, "author_name": parts[0], "author_email": parts[1],
            "date": parts[2], "subject": parts[3]}
