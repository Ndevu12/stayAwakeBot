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

from stayawake.core.adapters import github_api
from stayawake.core import git as gitutil
from stayawake.bots.security.scanner import scan_target
from stayawake.bots.security.targets import LocalRepoTarget
from stayawake.bots.security.models import QUARANTINE_DIR
from stayawake.bots.security import remediation

FIX_BRANCH = "security/auto-clean"
PATCHES_DIR = Path("sab-patches")   # where the read-only fallback writes .patch files
_BOT = ("-c", "user.name=StayAwakeBot Security", "-c", "user.email=security-bot@stayawake.local")


def _git(cwd: Path, *args: str, env: dict | None = None) -> subprocess.CompletedProcess:
    return subprocess.run(["git", "-C", str(cwd), *args],
                          capture_output=True, text=True, check=False, env=env)


def _untrack_quarantine(repo: Path) -> bool:
    """git only ignores UNTRACKED paths, so untrack any pre-existing tracked
    quarantine dir before staging. Returns True if the quarantine is clean after."""
    _git(repo, "rm", "-r", "--cached", "--ignore-unmatch", QUARANTINE_DIR)
    return not _git(repo, "ls-files", QUARANTINE_DIR).stdout.strip()


def _save_patch(wt: Path, slug: str, out_dir: Path) -> Path | None:
    """Capture the fix commit as a git-am-able patch so a read-only run (no write access)
    never loses the work when the branch can't be pushed. Returns the path, or None on
    failure. This is the no-write floor of the remediation ladder."""
    r = _git(wt, "format-patch", "-1", "HEAD", "--stdout")
    if r.returncode != 0 or not r.stdout.strip():
        return None
    try:
        out_dir.mkdir(parents=True, exist_ok=True)
        dest = (out_dir / (slug.replace("/", "-") + ".patch")).resolve()
        dest.write_text(r.stdout, encoding="utf-8")
    except OSError:
        return None
    return dest


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


def submit_fix_pr(repo: Path, opts, signatures, allowlist, token: str,
                  patches_dir: Path | None = None) -> str:
    """Open (or update) one dedup'd remediation PR for `repo`. Returns an outcome string.
    If the branch can't be pushed (read-only access), falls back to writing a patch file
    instead of discarding the fix when the worktree is torn down."""
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

        applied = remediation.apply(wt, changes, quarantine)

        # Post-apply verification — a worm-killer must never open a PR over a file
        # that is still infected. Re-scan; quarantine any residual auto-fixable
        # finding outright; abort the PR if the tree still is not clean.
        def _residual():
            fs = scan_target(LocalRepoTarget(wt, slug, opts), signatures, allowlist).findings
            return [f for f in fs if remediation.is_auto_fixable(f)]
        residual = _residual()
        if residual:
            applied += remediation.quarantine_residual(wt, residual, quarantine)
            residual = _residual()
        if residual:
            return (f"{slug}: ABORTED — {len(residual)} finding(s) still present after "
                    f"remediation; no PR opened (needs manual review)")
        if not applied:
            return f"{slug}: nothing was actually remediated — no PR"

        # quarantine backups live in an out-of-tree tempdir here; still untrack any
        # pre-existing TRACKED quarantine dir so live-malware backups never ship.
        if not _untrack_quarantine(wt):
            return f"{slug}: ABORTED — could not untrack {QUARANTINE_DIR}/ (would commit backups)"
        _git(wt, "add", "-A")
        msg = "security: auto-remediate worm indicators\n\n" + \
              "\n".join(f"- {c.action}: {c.path}" for c in applied)
        _git(wt, *_BOT, "commit", "-m", msg)

        # Token is passed via GIT_ASKPASS (env), never embedded in the push URL/argv.
        with gitutil.github_https_auth(token) as (prefix, env):
            pushed = _git(wt, "push", "--force", f"{prefix}{slug}.git",
                          f"{FIX_BRANCH}:{FIX_BRANCH}", env=env).returncode == 0
        if not pushed:
            # No write access: don't lose the fix when the worktree is removed — save it
            # as a patch the repo owner can apply themselves.
            patch = _save_patch(wt, slug, Path(patches_dir) if patches_dir else PATCHES_DIR)
            if patch:
                return (f"{slug}: push rejected (no write access?) — saved the fix as a patch at "
                        f"{patch}. Apply on '{base}' with `git am {patch.name}`, or re-run with a "
                        f"token that has repo + PR write scope.")
            return f"{slug}: branch push failed (check token write scope)"

        if existing:
            pr = existing[0]
            return f"{slug}: updated existing PR #{pr['number']} ({pr.get('html_url','')}) — no duplicate"
        pr = github_api.create_pull(owner, name,
                                    title="security: auto-remediate worm indicators",
                                    head=FIX_BRANCH, base=base,
                                    body=_pr_body(slug, applied), token=token)
        if pr and pr.get("number"):
            return f"{slug}: opened PR #{pr['number']} ({pr.get('html_url','')})"
        return f"{slug}: branch pushed but PR creation failed (check token scope)"
    finally:
        _git(repo, "worktree", "remove", "--force", str(wt))
