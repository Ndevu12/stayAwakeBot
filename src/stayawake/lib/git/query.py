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

from stayawake.lib.git.auth import github_https_auth, run_remote_git
from stayawake.lib.git.run import run, stdout, stdout_bytes_fed, NETWORK_TIMEOUT


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


def ref_exists(repo: str | Path, ref: str) -> bool:
    """True if `ref` resolves in `repo` (a branch, tag, or `origin/<branch>`). Used to prefer a
    fresh `origin/<base>` but fall back to the local base so remediation works offline."""
    res = run(repo, ["rev-parse", "--verify", "--quiet", ref])
    return res is not None and res.returncode == 0


def is_ancestor(repo: str | Path, ancestor: str, descendant: str) -> bool:
    """True if `ancestor` is reachable from `descendant` — i.e. the update fast-forwards.
    Distinguishes a fix branch we can extend from one occupied by unrelated work."""
    res = run(repo, ["merge-base", "--is-ancestor", ancestor, descendant])
    return res is not None and res.returncode == 0


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
    res = run(repo, ["ls-remote", "--heads", remote, branch], env=env, timeout=NETWORK_TIMEOUT)
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
_MAX_LINK_TARGET_BYTES = 4096
_OBJECT_ID_BYTES = 20


_INHERITED_LOCATION = ("GIT_DIR", "GIT_COMMON_DIR", "GIT_WORK_TREE", "GIT_OBJECT_DIRECTORY",
                       "GIT_ALTERNATE_OBJECT_DIRECTORIES", "GIT_INDEX_FILE", "GIT_NAMESPACE")


def _own_env() -> dict:
    """Build the environment a query of a repository's own objects runs in. Returns it."""
    env = {k: v for k, v in os.environ.items() if k not in _INHERITED_LOCATION}
    env["GIT_GRAFT_FILE"] = os.path.join(os.devnull, "grafts")
    env["GIT_TERMINAL_PROMPT"] = "0"
    return env


def holds_its_objects(repo: str | Path) -> bool:
    """Ask whether a repository holds the objects it names. Takes the repo. Returns False when it
    would reach a remote for them, or when the question could not be answered."""
    res = run(repo, ["config", "--get-regexp",
                     r"^(remote\..*\.promisor|extensions\.partialclone)$"], env=_own_env())
    return res is not None and not (res.stdout or "").strip()


def _own_view(repo: str | Path, args: list[str]):
    """Ask git about the objects a repository holds, not about a view configured over them. Takes
    the repo and the arguments. Returns the completed process, or None when it could not run."""
    return run(repo, ["--no-replace-objects", *args], env=_own_env())


def _own_view_fed(repo: str | Path, args: list[str], stdin: bytes) -> bytes | None:
    """Ask git about the objects a repository holds, feeding `stdin`. Takes the repo, the arguments
    and the bytes to write. Returns the raw stdout, or None on any failure."""
    return stdout_bytes_fed(repo, ["--no-replace-objects", *args], stdin, env=_own_env())


def _entry_type(mode: bytes) -> int | None:
    """Read a tree entry's mode as the object type git gives it. Takes the mode field. Returns the
    type bits, or None for a mode that names no type git records."""
    try:
        bits = int(mode, 8) & _TYPE_MASK
    except ValueError:
        return None
    return bits if bits in _ENTRY_TYPES else None


def _batch_objects(raw: bytes):
    """Frame each object in a `cat-file --batch` stream. Takes the raw stream. Yields
    `(id, kind, body, whole)` per object, with empty strings and False for an id git did not
    resolve, and `whole` False for a body the stream ended before."""
    at = 0
    while at < len(raw):
        nl = raw.find(b"\n", at)
        if nl == -1:
            return
        parts = raw[at:nl].split()
        if len(parts) < 3 or not parts[2].isdigit():
            yield "", "", b"", False
            at = nl + 1
            continue
        size = int(parts[2])
        body, at = raw[nl + 1:nl + 1 + size], nl + 1 + size + 1
        yield parts[0].decode(), parts[1].decode(), body, len(body) == size


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
    raw = _own_view_fed(repo, ["cat-file", "--batch"], "\n".join(ids).encode())
    if raw is None:
        return {}, False
    out: dict[str, list] = {}
    complete = True
    for oid, kind, body, whole in _batch_objects(raw):
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
    roots = _own_view(repo, ["rev-list", "--all", "--format=%T"])
    refs = _own_view(repo, ["for-each-ref", "--format=%(refname)"])
    if roots is None or roots.returncode != 0 or refs is None or refs.returncode != 0:
        return {}, False
    complete = not roots.stderr.strip()
    named = [ln.strip() for ln in roots.stdout.splitlines() if not ln.startswith("commit ")]
    wanted = [ln.strip() for ln in refs.stdout.splitlines() if ln.strip()]
    peeled = _own_view_fed(repo, ["cat-file", "--batch-check"],
                           "".join(f"{ref}^{{tree}}\n" for ref in wanted).encode())
    if peeled is None:
        return {}, False
    lines = peeled.decode("utf-8", "replace").splitlines()
    complete = complete and len(lines) == len(wanted)
    named += [p[0] for p in (ln.split() for ln in lines) if len(p) == 3 and p[1] == "tree"]
    out: dict[str, list[tuple[str, int]]] = {}
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
    answered = _own_view_fed(repo, ["cat-file", "--batch-check"], "\n".join(wanted).encode())
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
    wanted = sorted({sha for shas in at_path.values() for sha in shas})
    sized = _own_view_fed(repo, ["cat-file", "--batch-check"], "\n".join(wanted).encode())
    if sized is None:
        return {}, False
    readable = []
    for line in sized.decode("utf-8", "replace").splitlines():
        parts = line.split()
        if (len(parts) >= 3 and parts[1] == "blob" and parts[2].isdigit()
                and int(parts[2]) <= _MAX_LINK_TARGET_BYTES):
            readable.append(parts[0])
    raw = _own_view_fed(repo, ["cat-file", "--batch"], "\n".join(readable).encode())
    if raw is None:
        return {}, False
    text_of: dict[str, str] = {}
    for oid, kind, body, whole in _batch_objects(raw):
        if not whole or kind != "blob":
            complete = False
            continue
        text_of[oid] = body.split(b"\0", 1)[0].decode("utf-8", "replace")
    out, every = {}, True
    for rel, shas in at_path.items():
        raws = [text_of[sha] for sha in sorted(shas) if sha in text_of]
        every = every and len(raws) == len(shas)
        if raws:
            out[rel] = raws
    return out, complete and every


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
        res = run(repo, ["rev-parse", "--git-path", what], env=_own_env())
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


def _without_token(text: str, token: str | None) -> str:
    return text.replace(token, "***") if token else text


def fetch_refs(repo: str | Path, *, token: str | None = None) -> FetchResult:
    """Refresh every `refs/remotes/origin/*` from the remote, pruning the ones it no longer has.

    `branches_carrying` can only see branches this clone fetched, so on a stale clone a branch
    that carries an infected commit is invisible and a sweep reports it updated every carrier
    when it did not. The explicit `+refs/heads/*:refs/remotes/origin/*` is what makes the
    refresh complete: a bare `git fetch origin` honours the clone's CONFIGURED refspec, which a
    `--single-branch` clone narrows to one branch, and stays blind to the rest. `--prune` is
    the other half — a branch deleted on the remote must stop counting as a carrier.

    Never raises, and never reports success it did not achieve: git failing, being unable to
    run, or exceeding `NETWORK_TIMEOUT` all return `ok=False` with a reason. `write.fetch` is
    the neighbouring single-ref helper; it returns a bare bool and cannot express that refusal.

    `token` authenticates through `github_https_auth`, so the secret reaches git only in the
    child environment. Trap: that helper falls back to credential-in-URL on Windows, so git's
    own message is scrubbed of the token before it becomes a `reason` anyone may log.
    """
    slug = origin_slug(repo) if token else None
    refspec = "+refs/heads/*:refs/remotes/origin/*"
    if slug:
        res = run_remote_git(slug, token, lambda url, env: run(
            repo, ["fetch", "--prune", "--no-tags", url, refspec], env=env,
            timeout=NETWORK_TIMEOUT))
    else:
        with github_https_auth(token) as (_prefix, env):
            res = run(repo, ["fetch", "--prune", "--no-tags", "origin", refspec],
                      env=env, timeout=NETWORK_TIMEOUT)
    if res is None:
        return FetchResult(False, "git fetch could not run, or exceeded the network timeout")
    if res.returncode == 0:
        return FetchResult(True)
    reported = (res.stderr or res.stdout or "").strip() or f"git fetch exited {res.returncode}"
    return FetchResult(False, _without_token(reported, token))


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


def branch_refs(repo: str | Path) -> list[tuple[str, str]]:
    """List every ref an amend has to read history from. Takes the repo. Returns `(name, ref)` for
    each local head and each fetched origin branch, keeping BOTH where a name has one of each: a
    local head and the origin ref of the same name diverge, and either may hold a version the other
    does not. Which single ref an amend then updates is `branches_carrying`'s answer, not this one."""
    found: list[tuple[str, str]] = []
    for scope in (_LOCAL_REF.rstrip("/"), _ORIGIN_REF.rstrip("/")):
        for line in stdout(repo, ["for-each-ref", "--format=%(refname)", scope]).splitlines():
            ref = line.strip()
            name = branch_name_of(ref)
            if name:
                found.append((name, ref))
    return sorted(found)


def branches_carrying(repo: str | Path, sha: str) -> list[tuple[str, str, str]]:
    """Find every branch that still reaches `sha`. Takes the repo and the sha. Returns
    `(name, replay_tip, cas_old)` per branch, where `cas_old` is the local tip, or the zero SHA when
    no local ref of that name exists yet; a local head for the same name wins the tip."""
    full = stdout(repo, ["rev-parse", sha]).strip() or sha
    found: dict[str, str] = {}
    local_tips: dict[str, str] = {}
    for scope in (_ORIGIN_REF.rstrip("/"), _LOCAL_REF.rstrip("/")):
        listing = stdout(repo, ["for-each-ref", "--format=%(refname) %(objectname)",
                                f"--contains={full}", scope])
        for line in listing.splitlines():
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
    res = run(repo, ["ls-remote", "--heads", remote, pattern], env=env, timeout=NETWORK_TIMEOUT)
    if res is None or res.returncode != 0:
        return None
    return [ln.split("refs/heads/", 1)[1].strip()
            for ln in res.stdout.splitlines() if "refs/heads/" in ln]


def parents(repo: str | Path, sha: str) -> list[str]:
    out = stdout(repo, ["rev-list", "--parents", "-n", "1", sha]).split()
    return out[1:] if len(out) > 1 else []


def changed_paths(repo: str | Path, base: str, target: str,
                  diff_filter: str | None = None) -> set[str]:
    """Paths that differ between two commits/trees (name-only).

    `diff_filter` is passed straight to `git diff --diff-filter` (e.g. "AM" keeps only the
    paths `target` Adds or Modifies and drops Deletions) — callers that care about content
    `target` *introduces* want to ignore paths it merely removes.
    """
    # `-z` is load-bearing, exactly as in `_differing_paths`: without it git C-quotes and
    # octal-escapes any path holding a non-ASCII byte, a quote, a backslash, a tab or a newline.
    # That spelling matches nothing when it is later looked up, so the path reads as absent —
    # and a remediation path that treats "absent" as "this commit introduced it" then reports
    # having removed something it never found.
    args = ["diff", "--name-only", "-z"]
    if diff_filter:
        args.append(f"--diff-filter={diff_filter}")
    args += [base, target]
    res = run(repo, args)
    if res is None or res.returncode != 0:
        return set()
    return {p for p in (res.stdout or "").split("\0") if p}


def path_exists_at(repo: str | Path, treeish: str, path: str) -> bool:
    """True if `path` exists at a commit/tree (presence only — independent of whether the
    blob is text or binary). Used by the new-vs-ALL-parents corroborator so a binary file
    that decodes to '' is never mistaken for an absent file."""
    res = run(repo, ["cat-file", "-e", f"{treeish}:{path}"])
    return res is not None and res.returncode == 0


def tree_entry(repo: str | Path, treeish: str, path: str) -> tuple[str, str] | None:
    """`(mode, oid)` for `path` at a commit/tree, or None when it is not there.

    The MODE travels with the object: writing a blob back into an index without it turns an
    executable into a plain file and a symlink into a file holding its target as text.
    """
    res = run(repo, ["ls-tree", "--full-tree", treeish, "--", path])
    if res is None or res.returncode != 0:
        return None
    line = (res.stdout or "").strip()
    if not line:
        return None
    head = line.split("\t", 1)[0].split()
    if len(head) < 3:
        return None
    return head[0], head[2]


def file_at(repo: str | Path, treeish: str, path: str) -> str:
    """Contents of `path` at a commit/tree (empty string if absent or binary-unreadable)."""
    res = run(repo, ["cat-file", "-p", f"{treeish}:{path}"])
    if res is None or res.returncode != 0 or not res.stdout:
        return ""
    return res.stdout


def list_tree(repo: str | Path, treeish: str, path: str | Path) -> list[str]:
    """Repo-relative paths of the files under `path` AT a git ref (recursive), or [] if the ref or
    directory is absent. Lets a caller reason about what a ref/branch actually CONTAINS — e.g. what
    the default branch has, independent of a dirty/untracked working tree."""
    res = run(repo, ["ls-tree", "-r", "--name-only", treeish, "--", str(path)])
    if res is None or res.returncode != 0 or not res.stdout:
        return []
    return [ln for ln in res.stdout.splitlines() if ln.strip()]


def tracked(repo: str | Path, path: str) -> bool:
    """True if `path` is tracked in git — i.e. has committed history we could recover from."""
    res = run(repo, ["ls-files", "--error-unmatch", "--", path])
    return res is not None and res.returncode == 0


def file_commits(repo: str | Path, path: str, limit: int = 50,
                 first_parent: bool = False, all_branches: bool = False) -> list[str]:
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
    """
    args = ["log", f"-n{limit}", "--format=%H"]
    if first_parent:
        args.append("--first-parent")
    if all_branches:
        args += [f"--exclude={glob}" for glob in _NOT_A_BRANCH]
        args += [f"--glob={_ORIGIN_REF}*", "--branches", "--full-history"]
    args += ["--", path]
    out = stdout(repo, args)
    return [ln.strip() for ln in out.splitlines() if ln.strip()]


def introduced_added_text(repo: str | Path, base_tree: str, target: str, path: str) -> str:
    """The text the diff `base_tree..target` ADDS to `path` — i.e. the merge-introduced
    hunk's `+` lines, with the leading `+` stripped and diff `+++` headers excluded.

    This is the review-evading content itself: the lines present in the recorded merge
    but NOT in the clean auto-merge of its parents. We analyse exactly this delta (never
    the whole file) so a benign conflict resolution that only re-arranges existing code
    contributes nothing for the obfuscation detector to trip on."""
    out = stdout(repo, ["diff", "--unified=0", "--no-color", base_tree, target, "--", path])
    added: list[str] = []
    for line in out.splitlines():
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
