#!/usr/bin/env python3
"""Read-only git queries — answer questions about a repository's history and trees WITHOUT
ever executing repository code. The evil-merge detector and the recovery walks build on these."""
from __future__ import annotations

import re
from pathlib import Path

from stayawake.core.git.run import run, stdout, NETWORK_TIMEOUT


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
    args = ["diff", "--name-only"]
    if diff_filter:
        args.append(f"--diff-filter={diff_filter}")
    args += [base, target]
    out = stdout(repo, args)
    return {line.strip() for line in out.splitlines() if line.strip()}


def path_exists_at(repo: str | Path, treeish: str, path: str) -> bool:
    """True if `path` exists at a commit/tree (presence only — independent of whether the
    blob is text or binary). Used by the new-vs-ALL-parents corroborator so a binary file
    that decodes to '' is never mistaken for an absent file."""
    res = run(repo, ["cat-file", "-e", f"{treeish}:{path}"])
    return res is not None and res.returncode == 0


def file_at(repo: str | Path, treeish: str, path: str) -> str:
    """Contents of `path` at a commit/tree (empty string if absent or binary-unreadable)."""
    res = run(repo, ["cat-file", "-p", f"{treeish}:{path}"])
    if res is None or res.returncode != 0 or not res.stdout:
        return ""
    return res.stdout


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
