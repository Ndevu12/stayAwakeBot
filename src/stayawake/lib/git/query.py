#!/usr/bin/env python3
"""Read-only git queries — answer questions about a repository's history and trees WITHOUT
ever executing repository code. The evil-merge detector and the recovery walks build on these.

`fetch_refs` is the one helper here that writes: it refreshes the remote-tracking refs the
other queries read, because a query can only answer for refs the clone actually has."""
from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

from stayawake.lib.git.auth import github_https_auth
from stayawake.lib.git.run import run, stdout, NETWORK_TIMEOUT


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
    this answers 'is ANYTHING under this directory still tracked?' — the quarantine-clean check."""
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
    with github_https_auth(token) as (prefix, env):
        target = f"{prefix}{slug}.git" if slug else "origin"
        res = run(repo, ["fetch", "--prune", "--no-tags", target,
                         "+refs/heads/*:refs/remotes/origin/*"],
                  env=env, timeout=NETWORK_TIMEOUT)
    if res is None:
        return FetchResult(False, "git fetch could not run, or exceeded the network timeout")
    if res.returncode == 0:
        return FetchResult(True)
    reported = (res.stderr or res.stdout or "").strip() or f"git fetch exited {res.returncode}"
    return FetchResult(False, _without_token(reported, token))


def branches_carrying(repo: str | Path, sha: str) -> list[tuple[str, str, str]]:
    """Each branch that still reaches `sha`: `(name, replay_tip, cas_old)`.

    `origin/*` is included so a commit that only sits on a fetched remote-tracking
    ref is still a branch this identity may have to update. Notes and replace refs
    are not branches. A local head for the same name wins the tip. `cas_old` is
    that local tip, or the zero SHA when the local ref does not exist yet.
    """
    full = stdout(repo, ["rev-parse", sha]).strip() or sha
    found: dict[str, str] = {}
    remote = stdout(repo, ["for-each-ref", "--format=%(refname) %(objectname)",
                           f"--contains={full}", "refs/remotes/origin"])
    for line in remote.splitlines():
        parts = line.split()
        if len(parts) != 2:
            continue
        ref, tip = parts[0].strip(), parts[1].strip()
        if not ref.startswith("refs/remotes/origin/"):
            continue
        short = ref[len("refs/remotes/origin/"):]
        if not short or short == "HEAD" or short.startswith("saw-amend/"):
            continue
        if short == "notes" or short.startswith("notes/") or short.startswith("replace/"):
            continue
        found[short] = tip
    local = stdout(repo, ["for-each-ref", "--format=%(refname) %(objectname)",
                          f"--contains={full}", "refs/heads"])
    local_tips: dict[str, str] = {}
    for line in local.splitlines():
        parts = line.split()
        if len(parts) != 2:
            continue
        ref, tip = parts[0].strip(), parts[1].strip()
        if not ref.startswith("refs/heads/"):
            continue
        name = ref[len("refs/heads/"):]
        if not name or name.startswith("saw-amend/"):
            continue
        local_tips[name] = tip
        found[name] = tip
    zero = "0" * 40
    return [(name, tip, local_tips.get(name, zero)) for name, tip in found.items()]


def remote_branches_matching(remote: str, pattern: str, *, repo: str | Path | None = None,
                             env: dict | None = None) -> list[str]:
    """Branch names on `remote` matching a glob. Empty when the remote is unreachable."""
    res = run(repo, ["ls-remote", "--heads", remote, pattern], env=env, timeout=NETWORK_TIMEOUT)
    if res is None or res.returncode != 0:
        return []
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
                 first_parent: bool = False) -> list[str]:
    """Commit SHAs that touched `path`, newest first (bounded). The walk that the
    remediator uses to find the most recent committed version that scans clean.

    `first_parent=True` restricts the walk to the mainline (first-parent) chain from HEAD:
    a change brought in through a merge is attributed to the merge commit (whose tree at
    `path` is the version that actually landed on mainline), and a blob that only ever
    existed on a merged-in SECOND parent — never on the mainline tree — is not enumerated.
    The recovery source is itself a trust decision (an evil merge can make a "clean-looking"
    blob reachable only through its malicious side), so recovery uses this mode; the default
    keeps the full history walk for callers that want every version.
    """
    args = ["log", f"-n{limit}", "--format=%H"]
    if first_parent:
        args.append("--first-parent")
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
