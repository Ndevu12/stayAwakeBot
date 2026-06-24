#!/usr/bin/env python3
"""Read-only git plumbing helpers (subprocess-based, no third-party deps).

Single responsibility: answer questions about a repository's history and trees
without ever executing repository code. Used mainly by the evil-merge detector.
"""
from __future__ import annotations

import contextlib
import os
import stat
import subprocess
import tempfile
from pathlib import Path

_HOST = "github.com"


@contextlib.contextmanager
def github_https_auth(token: str | None):
    """Yield (url_prefix, env) for authenticated GitHub HTTPS that keeps the token OUT of
    the URL and process args — so it can't leak via argv, `ps`, git's own error output,
    or anything we might log.

    With a token (POSIX), GIT_ASKPASS points at a throwaway 0700 script that reads the
    token from the child env, and the URL prefix carries only the username
    (`https://x-access-token@github.com/`). The secret therefore lives only in the child
    environment, never in argv/URLs/files. On Windows (no POSIX askpass) and when there
    is no token, it falls back to the prior behaviour.

        with github_https_auth(token) as (prefix, env):
            subprocess.run(["git", "clone", f"{prefix}{slug}.git", dst], env=env, ...)
    """
    base_env = dict(os.environ, GIT_TERMINAL_PROMPT="0", GIT_EDITOR="true")
    if not token:
        yield f"https://{_HOST}/", base_env
        return
    if os.name == "nt":  # no /bin/sh askpass on native Windows — keep credential-in-URL
        yield f"https://x-access-token:{token}@{_HOST}/", base_env
        return
    fd, path = tempfile.mkstemp(prefix="sab-askpass-")
    try:
        with os.fdopen(fd, "w") as f:
            f.write("#!/bin/sh\n"
                    'case "$1" in\n'
                    "  Username*) printf %s 'x-access-token' ;;\n"
                    '  *) printf %s "$SAB_GH_TOKEN" ;;\n'
                    "esac\n")
        os.chmod(path, stat.S_IRWXU)  # 0700: only this user can read/exec the helper
        env = dict(base_env, GIT_ASKPASS=path, SAB_GH_TOKEN=token)
        yield f"https://x-access-token@{_HOST}/", env
    finally:
        with contextlib.suppress(OSError):
            os.unlink(path)


def _run_full(repo: str | Path, args: list[str]) -> subprocess.CompletedProcess | None:
    """Run a git command in `repo`; return the CompletedProcess (None if git can't run).

    Unlike `_run`, this exposes the return code and stdout even on non-zero exit — needed
    for `merge-tree`, which exits 1 (not 0) on a conflicting auto-merge yet still prints the
    resulting tree OID.
    """
    try:
        return subprocess.run(
            ["git", "-C", str(repo), *args],
            capture_output=True,
            text=True,
            timeout=60,
            check=False,
        )
    except (subprocess.SubprocessError, OSError):
        return None


def _run(repo: str | Path, args: list[str]) -> str:
    """Run a git command in `repo`; return stdout (empty string on failure)."""
    res = _run_full(repo, args)
    return res.stdout if (res is not None and res.returncode == 0) else ""


def is_git_repo(repo: str | Path) -> bool:
    return _run(repo, ["rev-parse", "--is-inside-work-tree"]).strip() == "true"


def merge_commits(repo: str | Path, max_count: int = 200) -> list[str]:
    """SHAs of merge commits (>=2 parents), newest first."""
    out = _run(repo, ["rev-list", "--merges", f"--max-count={max_count}", "--all"])
    return [s for s in out.split() if s]


def parents(repo: str | Path, sha: str) -> list[str]:
    out = _run(repo, ["rev-list", "--parents", "-n", "1", sha]).split()
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
    out = _run(repo, args)
    return {line.strip() for line in out.splitlines() if line.strip()}


def _auto_merge_tree(repo: str | Path, a: str, b: str) -> str | None:
    """OID of the tree produced by a clean 3-way merge of commits `a` and `b` (their
    merge-base auto-detected). Returns the tree even when the auto-merge *conflicts* (so the
    recorded merge can be compared against the conflicted result). None when git lacks
    `merge-tree --write-tree` (pre-2.38) or the command errors.
    """
    res = _run_full(repo, ["merge-tree", "--write-tree", a, b])
    if res is None or res.returncode not in (0, 1):   # 0 = clean, 1 = conflicts; else unsupported
        return None
    oid = res.stdout.split("\n", 1)[0].strip() if res.stdout else ""
    is_oid = bool(oid) and len(oid) in (40, 64) and all(c in "0123456789abcdef" for c in oid)
    return oid if is_oid else None


def evil_merge_paths(repo: str | Path, merge_sha: str) -> set[str]:
    """Paths whose content the merge introduced BEYOND a clean 3-way merge of its parents.

    An evil merge smuggles content in the merge commit itself, where a normal PR review —
    which shows each parent's diff — can't see it. The signal is *not* "differs from both
    parents": a benign 3-way merge of independent edits to one file also differs from both.
    The signal is "differs from what merging the parents would have produced". So we compute
    the parents' clean auto-merged tree and flag only the paths the recorded merge ADDS or
    MODIFIES relative to it (injected files, or content slipped in during conflict
    resolution). Pure deletions are NOT flagged: a path the merge *removes* relative to the
    auto-merge — e.g. resolving by accepting the other branch's deletion of a file one branch
    had added — introduces no review-evading content, so it is not an evil-merge signal.

    Falls back to the coarser "changed vs every parent" intersection for octopus merges
    (>2 parents) or when git is too old for `merge-tree --write-tree`.
    """
    ps = parents(repo, merge_sha)
    if len(ps) < 2:
        return set()
    if len(ps) == 2:
        auto = _auto_merge_tree(repo, ps[0], ps[1])
        if auto is not None:
            return changed_paths(repo, auto, merge_sha, diff_filter="AM")
    # Fallback: paths added/modified vs EVERY parent (over-reports overlapping clean merges).
    common: set[str] | None = None
    for p in ps:
        diff = changed_paths(repo, p, merge_sha, diff_filter="AM")
        common = diff if common is None else (common & diff)
    return common or set()


def commit_meta(repo: str | Path, sha: str) -> dict[str, str]:
    out = _run(repo, ["show", "-s", "--format=%an%x09%ae%x09%cI%x09%s", sha]).strip()
    parts = out.split("\t")
    if len(parts) < 4:
        return {"sha": sha}
    return {"sha": sha, "author_name": parts[0], "author_email": parts[1],
            "date": parts[2], "subject": parts[3]}
