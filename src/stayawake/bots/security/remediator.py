#!/usr/bin/env python3
"""Remediator service: scan local repos → plan fixes → (with apply) fix safely.

Dry-run by default. With apply=True it writes fixes to the working tree (backing
originals up to .malware-quarantine/) and, when the repo was clean beforehand,
commits them to a fresh `security/auto-clean-<stamp>` branch — never main, never a
force-push, never pushed. The human reviews and opens the PR.
"""
from __future__ import annotations

import shutil
import subprocess
import tempfile
from datetime import datetime, timezone
from pathlib import Path

from stayawake.core.config import load_yaml
from stayawake.core.adapters import github_api
from stayawake.core import auth
from stayawake.core import git as gitutil
from stayawake.bots.security.signatures import load_signatures
from stayawake.bots.security.scanner import scan_target
from stayawake.bots.security.service import discover_local_repos, _enclosing_repo_root, DEFAULT_CONFIG
from stayawake.bots.security.targets import ScanOptions, LocalRepoTarget
from stayawake.bots.security.models import QUARANTINE_DIR
from stayawake.bots.security import remediation
from stayawake.bots.security import pr as pr_submit


def _residual_auto_fixable(repo: Path, sigs, allowlist, opts) -> list:
    """Re-scan a repo and return only findings that *should* have been auto-fixed —
    i.e. anything the remediator claims to handle but left behind."""
    fs = scan_target(LocalRepoTarget(repo, str(repo), opts), sigs, allowlist).findings
    return [f for f in fs if remediation.is_auto_fixable(f)]


def _options(settings: dict) -> ScanOptions:
    base = ScanOptions()
    return ScanOptions(
        exclude_dirs=set(settings.get("exclude_dirs", base.exclude_dirs)),
        max_file_bytes=int(settings.get("max_file_bytes", base.max_file_bytes)),
        remote_clone_depth=int(settings.get("remote_clone_depth", base.remote_clone_depth)),
    )


def _git(repo: Path, *args: str) -> bool:
    r = subprocess.run(["git", "-C", str(repo), *args],
                       capture_output=True, text=True, check=False)
    return r.returncode == 0


def _is_clean(repo: Path) -> bool:
    r = subprocess.run(["git", "-C", str(repo), "status", "--porcelain"],
                       capture_output=True, text=True, check=False)
    return r.returncode == 0 and r.stdout.strip() == ""


def _commit_branch(repo: Path, applied) -> str | None:
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    branch = f"security/auto-clean-{stamp}"
    body = "\n".join(f"- {c.action}: {c.path}" for c in applied)
    if not _git(repo, "checkout", "-b", branch):
        return None
    # git only ignores UNTRACKED paths — untrack any pre-existing tracked quarantine
    # dir so live-malware backups are never committed onto the fix branch.
    _git(repo, "rm", "-r", "--cached", "--ignore-unmatch", QUARANTINE_DIR)
    _git(repo, "add", "-A")
    _git(repo, "-c", "user.name=StayAwakeBot Security",
         "-c", "user.email=security-bot@stayawake.local",
         "commit", "-m", f"security: auto-remediate worm indicators\n\n{body}")
    return branch


def _resolve_config(config_path: str | None):
    """Load the remediation config without ever crashing on a missing file (#1054).
    None → the packaged default if it exists, else an empty config — so `saw fix` and
    `saw scan --fix` work on the current repo with no config, mirroring `saw scan`. An
    explicitly-passed --config that is missing prints a clear, actionable error and
    returns None (the caller exits non-zero) instead of a raw FileNotFoundError."""
    if config_path is None:
        p = Path(DEFAULT_CONFIG)
        return load_yaml(p) if p.exists() else {}
    if not Path(config_path).is_file():
        print(f"error: config '{config_path}' not found. Pass --config <path>, or omit it "
              "to remediate the current repository.")
        return None
    return load_yaml(config_path)


def remediate_scanned(repo: Path, result, *, sigs, allowlist, opts,
                      apply: bool = False, open_pr: bool = False,
                      token: str | None = None) -> int:
    """Plan — and with `apply`, write — fixes for ONE already-scanned repo, returning the
    number of auto-fix changes. The caller supplies the `ScanResult`, so the SAME analysis
    that produced the report drives the fix: no re-scan, no report-file coupling. Shared by
    `saw scan --fix` (scans once, then calls this) and `saw fix` (scans, then calls this)."""
    changes = remediation.plan(result.findings)
    # Everything not auto-fixed — true `manual` findings AND heuristic ones we refuse to
    # auto-edit — surfaces here so a suspicious match is reviewed, never silently stripped.
    manual = [f for f in result.findings if not remediation.is_auto_fixable(f)]
    if not changes and not manual:
        return 0
    rel = str(repo).replace(str(Path.home()), "~")
    print(f"\n■ {rel}")
    for c in changes:
        print(f"    fix  {c.action:14} {c.path}")
    for f in manual:
        print(f"    ⚠ manual {f.signature_id}: {f.path} ({f.description[:50]})")
    if not (apply and changes):
        return len(changes)
    if open_pr:
        if not token:
            print("    → " + auth.no_credential_hint("opening pull requests") + " Skipped.")
        else:
            print(f"    → {pr_submit.submit_fix_pr(repo, opts, sigs, allowlist, token)}")
        return len(changes)
    was_clean = _is_clean(repo)
    quarantine = remediation.quarantine_path(repo)
    applied = remediation.apply(repo, changes, quarantine)
    # Post-apply verification: quarantine anything still flagged; never present an
    # incompletely-cleaned repo as remediated.
    residual = _residual_auto_fixable(repo, sigs, allowlist, opts)
    if residual:
        applied += remediation.quarantine_residual(repo, residual, quarantine)
        residual = _residual_auto_fixable(repo, sigs, allowlist, opts)
    remediation.ensure_ignored(repo)       # keep quarantine artifacts out of any commit
    print(f"    → applied {len(applied)} change(s); originals in {QUARANTINE_DIR}/")
    if residual:
        print(f"    → ⚠ {len(residual)} finding(s) still present after remediation; "
              "left in the working tree for manual review (NOT committed).")
    elif was_clean:
        branch = _commit_branch(repo, applied)
        print(f"    → committed to branch '{branch}'. Review and open a PR (do NOT push to main)."
              if branch else "    → could not create branch; review `git diff` and commit manually.")
    else:
        print("    → repo had uncommitted changes; left in working tree. Review `git diff`, "
              "then commit to a branch + open a PR.")
    return len(changes)


def remediation_summary(total: int, apply: bool) -> None:
    """Print the dry-run / applied footer. Shared by `saw fix` and `saw scan --fix`."""
    if total == 0:
        print("No auto-remediable findings.")
    elif not apply:
        print(f"\nDRY-RUN: {total} change(s) planned across the repos above. Re-run with "
              "--apply (local branch) or --apply --pr (push a fix branch + open one rolling "
              "PR per repo, de-duplicated).")
    else:
        print(f"\nApplied remediation for {total} change(s). Review the branches/diffs, then open PRs. "
              "Evil-merge findings (⚠ manual) need a history rewrite — not auto-fixed.")


def remediate(config_path: str | None = None, apply: bool = False,
              open_pr: bool = False) -> int:
    """`saw fix`: scan configured/local repos and remediate. Config-optional (#1054) — with
    no config it falls back to the enclosing repository, mirroring `saw scan`. Returns a
    process exit code (0 ok; 2 when an explicitly-passed --config is missing)."""
    cfg = _resolve_config(config_path)
    if cfg is None:
        return 2
    settings = cfg.get("settings", {})
    opts = _options(settings)
    sigs = load_signatures(settings.get("signatures_path"))
    allowlist = cfg.get("allowlist", [])
    token, _ = auth.resolve_token()

    # No configured local targets → remediate the repo we're standing in (mirrors `saw scan`).
    local_patterns = cfg.get("targets", {}).get("local", []) or [str(_enclosing_repo_root())]
    total = 0
    for repo in discover_local_repos(local_patterns, opts):
        result = scan_target(LocalRepoTarget(repo, str(repo), opts), sigs, allowlist)
        total += remediate_scanned(repo, result, sigs=sigs, allowlist=allowlist, opts=opts,
                                   apply=apply, open_pr=open_pr, token=token)
    remediation_summary(total, apply)
    return 0


def submit_org_prs(config_path: str | None = None, token: str | None = None) -> int:
    """Event-driven / on-demand org sweep: for each configured GitHub repo, open or
    update ONE de-duplicated remediation PR (clean repos are skipped). Returns the
    number of repos that now have an open fix PR. Config-optional (#1054): a missing
    explicit --config is a clear message (returns 0), never a raw traceback.
    """
    cfg = _resolve_config(config_path)
    if cfg is None:
        return 0
    settings = cfg.get("settings", {})
    opts = _options(settings)
    sigs = load_signatures(settings.get("signatures_path"))
    allowlist = cfg.get("allowlist", [])
    source = "explicit"
    if not token:
        token, source = auth.resolve_token()
    if not token:
        print(auth.no_credential_hint("org remediation PRs") +
              " The token needs repo + pull-request write scope.")
        return 0

    gconf = cfg.get("targets", {}).get("github", {}) or {}
    slugs: list[str] = []
    for kind in ("users", "orgs"):
        for acct in gconf.get(kind, []) or []:
            slugs += github_api.list_repos(acct, kind, token,
                                           gconf.get("include_forks", False),
                                           gconf.get("include_archived", False))
    # With a GitHub App and no explicit accounts, sweep everything the install can see.
    if source == "github-app" and not slugs:
        slugs += github_api.list_installation_repos(token, gconf.get("include_archived", False))
    slugs = sorted(set(slugs))
    if not slugs:
        print("No GitHub targets configured (targets.github.users/orgs or an App installation).")
        return 0

    print(f"Sweeping {len(slugs)} repo(s) for worm indicators…")
    opened = 0
    for slug in slugs:
        tmp = Path(tempfile.mkdtemp(prefix="sab-org-"))
        clone = tmp / "repo"
        # Token via GIT_ASKPASS (env), never in the clone URL/argv.
        with gitutil.github_https_auth(token) as (prefix, env):
            r = subprocess.run(["git", "clone", "--quiet", "--depth", "50",
                                f"{prefix}{slug}.git", str(clone)],
                               capture_output=True, text=True, check=False, env=env)
        if r.returncode != 0:
            print(f"  {slug}: clone failed (check token access)")
            shutil.rmtree(tmp, ignore_errors=True)
            continue
        try:
            outcome = pr_submit.submit_fix_pr(clone, opts, sigs, allowlist, token)
            print(f"  {slug}: {outcome}")
            if "opened PR" in outcome or "updated existing PR" in outcome:
                opened += 1
        finally:
            shutil.rmtree(tmp, ignore_errors=True)
    print(f"Done. {opened} repo(s) have an open remediation PR (duplicates avoided).")
    return opened
