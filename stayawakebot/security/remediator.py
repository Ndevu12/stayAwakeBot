#!/usr/bin/env python3
"""Remediator service: scan local repos → plan fixes → (with apply) fix safely.

Dry-run by default. With apply=True it writes fixes to the working tree (backing
originals up to .malware-quarantine/) and, when the repo was clean beforehand,
commits them to a fresh `security/auto-clean-<stamp>` branch — never main, never a
force-push, never pushed. The human reviews and opens the PR.
"""
from __future__ import annotations

import subprocess
from datetime import datetime, timezone
from pathlib import Path

from stayawakebot.common.config import load_yaml
from stayawakebot.security.signatures import load_signatures
from stayawakebot.security.scanner import scan_target
from stayawakebot.security.service import discover_local_repos
from stayawakebot.security.targets import ScanOptions, LocalRepoTarget
from stayawakebot.security import remediation


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
    _git(repo, "add", "-A")
    _git(repo, "-c", "user.name=StayAwakeBot Security",
         "-c", "user.email=security-bot@stayawake.local",
         "commit", "-m", f"security: auto-remediate worm indicators\n\n{body}")
    return branch


def remediate(config_path: str = "config/security.yml", apply: bool = False) -> int:
    cfg = load_yaml(config_path)
    settings = cfg.get("settings", {})
    opts = _options(settings)
    sigs = load_signatures(settings.get("signatures_path", "config/security_signatures.yml"))
    allowlist = cfg.get("allowlist", [])

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

        if apply and changes:
            was_clean = _is_clean(repo)
            applied = remediation.apply(repo, changes, repo / ".malware-quarantine")
            print(f"    → applied {len(applied)} change(s); originals in .malware-quarantine/")
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
              "Re-run with --apply to fix (backs up to .malware-quarantine/ and commits to a branch).")
    else:
        print(f"\nApplied remediation for {total} change(s). Review the branches/diffs, then open PRs. "
              "Evil-merge findings (⚠ manual) need a history rewrite — not auto-fixed.")
    return total
