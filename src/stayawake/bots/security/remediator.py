#!/usr/bin/env python3
"""Remediator service: scan local repos → plan fixes → (with apply) fix safely.

Dry-run by default. With apply=True it writes fixes to the working tree (backing
originals up to .malware-quarantine/) and, when the repo was clean beforehand,
commits them to a fresh `security/auto-clean-<stamp>` branch — never main, never a
force-push, never pushed. The human reviews and opens the PR.
"""
from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
from datetime import datetime, timezone
from pathlib import Path

from stayawake.core.config import load_yaml
from stayawake.core.adapters import github_api
from stayawake.bots.security.signatures import load_signatures
from stayawake.bots.security.scanner import scan_target
from stayawake.bots.security.service import discover_local_repos
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


def remediate(config_path: str = "config/security.yml", apply: bool = False,
              open_pr: bool = False) -> int:
    cfg = load_yaml(config_path)
    settings = cfg.get("settings", {})
    opts = _options(settings)
    sigs = load_signatures(settings.get("signatures_path"))
    allowlist = cfg.get("allowlist", [])
    token = os.environ.get("GH_SECURITY_TOKEN") or os.environ.get("GITHUB_TOKEN")

    total = 0
    for repo in discover_local_repos(cfg.get("targets", {}).get("local", []), opts):
        result = scan_target(LocalRepoTarget(repo, str(repo), opts), sigs, allowlist)
        changes = remediation.plan(result.findings)
        manual = [f for f in result.findings if f.remediation == "manual"]
        if not changes and not manual:
            continue
        rel = str(repo).replace(str(Path.home()), "~")
        print(f"\n■ {rel}")
        for c in changes:
            print(f"    fix  {c.action:14} {c.path}")
        for f in manual:
            print(f"    ⚠ manual {f.signature_id}: {f.path} ({f.description[:50]})")
        total += len(changes)

        if not (apply and changes):
            continue
        if open_pr:
            if not token:
                print("    → --open-pr needs GH_SECURITY_TOKEN or GITHUB_TOKEN; skipped")
            else:
                print(f"    → {pr_submit.submit_fix_pr(repo, opts, sigs, allowlist, token)}")
        else:
            was_clean = _is_clean(repo)
            quarantine = remediation.quarantine_path(repo)
            applied = remediation.apply(repo, changes, quarantine)

            # Post-apply verification: quarantine anything still flagged; never
            # present an incompletely-cleaned repo as remediated.
            residual = _residual_auto_fixable(repo, sigs, allowlist, opts)
            if residual:
                applied += remediation.quarantine_residual(repo, residual, quarantine)
                residual = _residual_auto_fixable(repo, sigs, allowlist, opts)
            remediation.ensure_ignored(repo)   # keep quarantine artifacts out of any commit
            print(f"    → applied {len(applied)} change(s); originals in {QUARANTINE_DIR}/")
            if residual:
                print(f"    → ⚠ {len(residual)} finding(s) still present after remediation; "
                      "left in the working tree for manual review (NOT committed).")
                continue
            if was_clean:
                branch = _commit_branch(repo, applied)
                print(f"    → committed to branch '{branch}'. Review and open a PR (do NOT push to main)."
                      if branch else "    → could not create branch; review `git diff` and commit manually.")
            else:
                print("    → repo had uncommitted changes; left in working tree. Review `git diff`, "
                      "then commit to a branch + open a PR.")

    if total == 0:
        print("No auto-remediable findings.")
    elif not apply:
        print(f"\nDRY-RUN: {total} change(s) planned across the repos above. "
              "Re-run with --apply (local branch) or --apply --open-pr (push a fix branch + "
              "open one rolling PR per repo, de-duplicated).")
    else:
        print(f"\nApplied remediation for {total} change(s). Review the branches/diffs, then open PRs. "
              "Evil-merge findings (⚠ manual) need a history rewrite — not auto-fixed.")
    return total


def submit_org_prs(config_path: str = "config/security.yml", token: str | None = None) -> int:
    """Event-driven / on-demand org sweep: for each configured GitHub repo, open or
    update ONE de-duplicated remediation PR (clean repos are skipped). Returns the
    number of repos that now have an open fix PR.
    """
    cfg = load_yaml(config_path)
    settings = cfg.get("settings", {})
    opts = _options(settings)
    sigs = load_signatures(settings.get("signatures_path"))
    allowlist = cfg.get("allowlist", [])
    token = token or os.environ.get("GH_SECURITY_TOKEN") or os.environ.get("GITHUB_TOKEN")
    if not token:
        print("Org remediation needs GH_SECURITY_TOKEN/GITHUB_TOKEN with repo + PR write scope.")
        return 0

    gconf = cfg.get("targets", {}).get("github", {}) or {}
    slugs: list[str] = []
    for kind in ("users", "orgs"):
        for acct in gconf.get(kind, []) or []:
            slugs += github_api.list_repos(acct, kind, token,
                                           gconf.get("include_forks", False),
                                           gconf.get("include_archived", False))
    slugs = sorted(set(slugs))
    if not slugs:
        print("No GitHub targets configured (targets.github.users/orgs).")
        return 0

    print(f"Sweeping {len(slugs)} repo(s) for worm indicators…")
    opened = 0
    for slug in slugs:
        tmp = Path(tempfile.mkdtemp(prefix="sab-org-"))
        clone = tmp / "repo"
        url = f"https://x-access-token:{token}@github.com/{slug}.git"
        r = subprocess.run(["git", "clone", "--quiet", "--depth", "50", url, str(clone)],
                           capture_output=True, text=True, check=False)
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
