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
import time
from pathlib import Path

from stayawake.core.adapters import github_api
from stayawake.core import git as gitutil
from stayawake.bots.security.scanner import scan_target
from stayawake.bots.security.targets import LocalRepoTarget
from stayawake.bots.security.models import QUARANTINE_DIR
from stayawake.bots.security import remediation

FIX_BRANCH = "security/auto-clean"
PATCHES_DIR = Path("sab-patches")   # where the read-only fallback writes .patch files
ISSUE_LABEL = "stayawake-security"  # de-dup marker for the issue fallback
_FORK_POLL_TRIES = 10               # async fork readiness: poll up to ~30s
_FORK_POLL_DELAY = 3
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


def _issue_body(slug: str, findings) -> str:
    lines = [f"StayAwakeBot detected self-propagating worm indicators in `{slug}` and could "
             "not open a fix PR automatically (no write access to this repository).",
             "", "## Indicators", ""]
    for f in findings[:50]:
        loc = f.path + (f":{f.line}" if getattr(f, "line", None) else "")
        lines.append(f"- **[{f.severity.label()}]** `{f.signature_id}` — `{loc}`")
    lines += ["", "A remediation has been generated. To apply it, grant the scanner repo + "
              "pull-request write access for an automated PR, or run "
              "`stayawake-security-remediate` against a local clone to produce a patch.", "",
              "_Opened by StayAwakeBot Security. De-duplicated — re-runs won't open another._"]
    return "\n".join(lines)


def _open_issue_fallback(owner: str, name: str, findings, token: str) -> str | None:
    """Notify the repo via a de-duplicated issue when a fix can't be PR'd. Needs only
    `issues: write`; returns a short outcome, or None if it couldn't open one."""
    try:
        existing = github_api.list_open_issues(owner, name, token, labels=ISSUE_LABEL)
        if existing:
            return f"an open issue already tracks this (#{existing[0].get('number')})"
        issue = github_api.create_issue(
            owner, name, f"StayAwakeBot: worm indicators detected in {owner}/{name}",
            _issue_body(f"{owner}/{name}", findings), token, labels=[ISSUE_LABEL])
        if issue and issue.get("number"):
            return f"opened issue #{issue['number']} ({issue.get('html_url', '')})"
    except Exception:  # noqa: BLE001 — notification is best-effort; never mask the patch result
        pass
    return None


def _wait_for_fork(slug: str, token: str) -> bool:
    """A new fork is created asynchronously; poll until it's queryable (or give up)."""
    owner, name = slug.split("/", 1)
    for attempt in range(_FORK_POLL_TRIES):
        if github_api.get_repo(owner, name, token) is not None:
            return True
        if attempt < _FORK_POLL_TRIES - 1:
            time.sleep(_FORK_POLL_DELAY)
    return False


def _fork_and_pr(wt: Path, owner: str, name: str, base: str, applied, token: str) -> str | None:
    """When we can't push to the upstream, push the fix to a fork under the authenticated
    user and open a cross-fork PR. Returns an outcome string when forking is viable
    (success OR a post-fork failure worth reporting), or None when forking isn't possible
    so the caller falls through to the patch/issue floor.

    Handles: no token identity, can't fork (permissions), forking your own repo, async
    fork not ready, push-to-fork failure, duplicate fork PR, and PR-creation failure."""
    me = (github_api.get_authenticated_user(token) or {}).get("login")
    if not me or me.lower() == owner.lower():
        return None  # no identity, or it's our own repo (a fork wouldn't help)
    fork = github_api.create_fork(owner, name, token)
    fork_slug = fork.get("full_name") if isinstance(fork, dict) else None
    if not fork_slug or "/" not in fork_slug:
        return None  # forking not permitted → fall back
    if not _wait_for_fork(fork_slug, token):
        return f"{owner}/{name}: forked to {fork_slug} but it wasn't ready in time — retry later"
    # Push the fix branch to the fork (token via GIT_ASKPASS, never in URL/argv).
    with gitutil.github_https_auth(token) as (prefix, env):
        pushed = _git(wt, "push", "--force", f"{prefix}{fork_slug}.git",
                      f"{FIX_BRANCH}:{FIX_BRANCH}", env=env).returncode == 0
    if not pushed:
        return None  # couldn't push to the fork either → fall back to patch/issue
    fork_owner = fork_slug.split("/", 1)[0]
    existing = github_api.list_open_pulls(owner, name, FIX_BRANCH, token, head_owner=fork_owner)
    if existing:
        pr = existing[0]
        return (f"{owner}/{name}: updated existing fork PR #{pr['number']} "
                f"({pr.get('html_url', '')}) from {fork_slug}")
    pr = github_api.create_pull(owner, name, title="security: auto-remediate worm indicators",
                                head=f"{fork_owner}:{FIX_BRANCH}", base=base,
                                body=_pr_body(f"{owner}/{name}", applied), token=token)
    if pr and pr.get("number"):
        return (f"{owner}/{name}: opened fork PR #{pr['number']} ({pr.get('html_url', '')}) "
                f"from {fork_slug}")
    return f"{owner}/{name}: pushed to fork {fork_slug} but PR creation failed (check token scope)"


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
            # No write access — walk down the remediation ladder:
            #   1) push to a fork under our account and open a cross-fork PR,
            #   2) else save the fix as a patch (needs no permissions) AND
            #      notify the repo via a de-duplicated issue (needs only issues:write).
            forked = _fork_and_pr(wt, owner, name, base, applied, token)
            if forked:
                return forked
            patch = _save_patch(wt, slug, Path(patches_dir) if patches_dir else PATCHES_DIR)
            issue = _open_issue_fallback(owner, name, findings, token)
            bits = []
            if patch:
                bits.append(f"saved the fix as a patch at {patch} "
                            f"(apply on '{base}' with `git am {patch.name}`)")
            if issue:
                bits.append(issue)
            if not bits:
                return f"{slug}: branch push failed (check token write scope)"
            return f"{slug}: push rejected (no write access?) — " + "; ".join(bits) + "."

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
