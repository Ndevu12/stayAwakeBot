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


def _run(repo: str | Path, args: list[str]) -> str:
    """Run a git command in `repo`; return stdout (empty string on failure)."""
    try:
        out = subprocess.run(
            ["git", "-C", str(repo), *args],
            capture_output=True,
            text=True,
            timeout=60,
            check=False,
        )
        return out.stdout if out.returncode == 0 else ""
    except (subprocess.SubprocessError, OSError):
        return ""


def is_git_repo(repo: str | Path) -> bool:
    return _run(repo, ["rev-parse", "--is-inside-work-tree"]).strip() == "true"


def merge_commits(repo: str | Path, max_count: int = 200) -> list[str]:
    """SHAs of merge commits (>=2 parents), newest first."""
    out = _run(repo, ["rev-list", "--merges", f"--max-count={max_count}", "--all"])
    return [s for s in out.split() if s]


def parents(repo: str | Path, sha: str) -> list[str]:
    out = _run(repo, ["rev-list", "--parents", "-n", "1", sha]).split()
    return out[1:] if len(out) > 1 else []


def changed_paths(repo: str | Path, base: str, target: str) -> set[str]:
    """Paths that differ between two commits (name-only)."""
    out = _run(repo, ["diff", "--name-only", base, target])
    return {line.strip() for line in out.splitlines() if line.strip()}


def evil_merge_paths(repo: str | Path, merge_sha: str) -> set[str]:
    """Paths a merge introduces that exist in NEITHER parent.

    The worm injects files in the merge commit itself, so they appear in neither
    parent's diff — invisible in a normal PR review. Those paths are the signal.
    """
    ps = parents(repo, merge_sha)
    if len(ps) < 2:
        return set()
    # A path changed vs EVERY parent is content unique to the merge commit.
    common: set[str] | None = None
    for p in ps:
        diff = changed_paths(repo, p, merge_sha)
        common = diff if common is None else (common & diff)
    return common or set()


def commit_meta(repo: str | Path, sha: str) -> dict[str, str]:
    out = _run(repo, ["show", "-s", "--format=%an%x09%ae%x09%cI%x09%s", sha]).strip()
    parts = out.split("\t")
    if len(parts) < 4:
        return {"sha": sha}
    return {"sha": sha, "author_name": parts[0], "author_email": parts[1],
            "date": parts[2], "subject": parts[3]}
