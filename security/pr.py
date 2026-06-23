#!/usr/bin/env python3
"""Submit a remediation as a real pull request — the way a security engineer would.

One stable fix branch per repo (`security/auto-clean`) → one rolling PR per repo.
Before opening, it checks the API for an existing open PR from that branch and
updates it instead of opening a duplicate. All work happens in an isolated git
worktree off the remote's default branch, so the user's working tree is untouched
and the PR contains only the fix. Targets the default branch for human review —
never commits to or force-pushes main.
"""
from __future__ import annotations

import re
import subprocess
import tempfile
from pathlib import Path

from shared.adapters import github_api
from security.scanner import scan_target
from security.targets import LocalRepoTarget
from security import remediation

FIX_BRANCH = "security/auto-clean"
_BOT = ("-c", "user.name=StayAwakeBot Security", "-c", "user.email=security-bot@stayawake.local")


def _git(cwd: Path, *args: str) -> subprocess.CompletedProcess:
    return subprocess.run(["git", "-C", str(cwd), *args],
                          capture_output=True, text=True, check=False)


def slug_from_url(url: str) -> str | None:
    """Parse 'owner/name' from a GitHub SSH or HTTPS remote URL (pure)."""
    m = re.search(r"github\.com[:/]([^/]+/[^/]+?)(?:\.git)?/?$", url.strip())
    return m.group(1) if m else None


def origin_slug(repo: Path) -> str | None:
    """Return 'owner/name' from the origin remote (SSH or HTTPS), else None."""
    return slug_from_url(_git(repo, "remote", "get-url", "origin").stdout)


def default_branch(repo: Path) -> str:
    out = _git(repo, "symbolic-ref", "refs/remotes/origin/HEAD").stdout.strip()
    return out.rsplit("/", 1)[-1] if out else "main"


def _pr_body(slug: str, changes) -> str:
    lines = [f"Automated worm remediation for `{slug}` by StayAwakeBot Security Sentinel.",
             "", "## Changes", ""]
    lines += [f"- `{c.action}` — `{c.path}`" for c in changes]
    lines += ["", "Originals are recoverable from git history. Evil-merge findings (if any) "
              "are reported separately and need a manual history rewrite.", "",
              "_Review and merge if correct. This is a single rolling PR — re-runs update it "
              "rather than opening duplicates._"]
    return "\n".join(lines)


def submit_fix_pr(repo: Path, opts, signatures, allowlist, token: str) -> str:
    """Open (or update) one dedup'd remediation PR for `repo`. Returns an outcome string."""
    slug = origin_slug(repo)
    if not slug:
        return "no GitHub origin remote — skipped"
    owner, name = slug.split("/", 1)
    base = default_branch(repo)

    existing = github_api.list_open_pulls(owner, name, FIX_BRANCH, token)

    _git(repo, "fetch", "--quiet", "origin", base)
    wt = Path(tempfile.mkdtemp(prefix="sab-fix-"))
    quarantine = Path(tempfile.mkdtemp(prefix="sab-bak-"))  # backups kept OUT of the PR
    try:
        if _git(repo, "worktree", "add", "-f", "-B", FIX_BRANCH, str(wt),
                f"origin/{base}").returncode != 0:
            return f"{slug}: could not create worktree"

        findings = scan_target(LocalRepoTarget(wt, slug, opts), signatures, allowlist).findings
        changes = remediation.plan(findings)
        if not changes:
            return f"{slug}: '{base}' already clean — nothing to PR"

        remediation.apply(wt, changes, quarantine)
        _git(wt, "add", "-A")
        msg = "security: auto-remediate worm indicators\n\n" + \
              "\n".join(f"- {c.action}: {c.path}" for c in changes)
        _git(wt, *_BOT, "commit", "-m", msg)

        push_url = f"https://x-access-token:{token}@github.com/{slug}.git"
        if _git(wt, "push", "--force", push_url, f"{FIX_BRANCH}:{FIX_BRANCH}").returncode != 0:
            return f"{slug}: branch push failed (check token write scope)"

        if existing:
            pr = existing[0]
            return f"{slug}: updated existing PR #{pr['number']} ({pr.get('html_url','')}) — no duplicate"
        pr = github_api.create_pull(owner, name,
                                    title="security: auto-remediate worm indicators",
                                    head=FIX_BRANCH, base=base,
                                    body=_pr_body(slug, changes), token=token)
        if pr and pr.get("number"):
            return f"{slug}: opened PR #{pr['number']} ({pr.get('html_url','')})"
        return f"{slug}: branch pushed but PR creation failed (check token scope)"
    finally:
        _git(repo, "worktree", "remove", "--force", str(wt))
