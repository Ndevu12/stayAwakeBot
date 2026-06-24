#!/usr/bin/env python3
"""Local machine security-posture checks (the "harden the surface" layer).

Single responsibility: inspect the *developer machine* — not repositories — for the
worm's entry and propagation surfaces, and report actionable hygiene issues:

  * a cached GitHub credential (the worm steals the macOS Keychain / git-credentials
    token; it survives SSH-key rotation and is how it pushed as you),
  * VS Code automatic-task execution + Workspace Trust disabled (the auto-run vector).

Repository indicator scanning lives in the scanner/service; this is complementary.
Stdlib only; every probe degrades gracefully when a path/tool is absent.
"""
from __future__ import annotations

import os
import re
import subprocess
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Any


@dataclass
class HygieneIssue:
    id: str
    severity: str          # "warning" (act now) | "info" (recommended)
    title: str
    detail: str
    remediation: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


# --- credential hygiene -----------------------------------------------------

def _macos_keychain_has_github() -> bool:
    """True if a github.com internet password is cached in the macOS Keychain."""
    try:
        r = subprocess.run(
            ["security", "find-internet-password", "-s", "github.com"],
            capture_output=True, text=True, timeout=10,
        )
        return r.returncode == 0
    except (FileNotFoundError, OSError, subprocess.SubprocessError):
        return False


def _git_credentials_file_with_github() -> Path | None:
    """Path to a plaintext ~/.git-credentials holding a github.com entry, else None."""
    p = Path.home() / ".git-credentials"
    try:
        if p.is_file() and "github.com" in p.read_text(encoding="utf-8", errors="ignore"):
            return p
    except OSError:
        pass
    return None


def check_credentials() -> list[HygieneIssue]:
    issues: list[HygieneIssue] = []
    if _macos_keychain_has_github():
        issues.append(HygieneIssue(
            id="cached-github-keychain",
            severity="warning",
            title="GitHub credential cached in the macOS Keychain",
            detail="A github.com token is stored in the login Keychain. This is exactly "
                   "what the worm exfiltrates to push as you — and it survives SSH-key removal.",
            remediation="Remove it: security delete-internet-password -s github.com . "
                        "Prefer a short-lived token or the GitHub CLI's keyring over a cached password.",
        ))
    cred_file = _git_credentials_file_with_github()
    if cred_file is not None:
        issues.append(HygieneIssue(
            id="git-credentials-plaintext",
            severity="warning",
            title="Plaintext GitHub credential in ~/.git-credentials",
            detail=f"{cred_file} stores a github.com credential in plaintext (credential.helper=store).",
            remediation="Delete the file and switch to an OS keychain helper or SSH; "
                        "rotate the exposed token on GitHub.",
        ))
    return issues


# --- editor (VS Code) hygiene ----------------------------------------------

def _vscode_user_settings() -> Path | None:
    """Locate the VS Code user settings.json across macOS / Linux / Windows."""
    home = Path.home()
    candidates = [
        home / "Library/Application Support/Code/User/settings.json",   # macOS
        home / ".config/Code/User/settings.json",                       # Linux
        Path(os.environ.get("APPDATA", home / "AppData/Roaming")) / "Code/User/settings.json",  # Windows
    ]
    for c in candidates:
        try:
            if c.is_file():
                return c
        except OSError:
            continue
    return None


def check_vscode(settings_path: Path | None = None) -> list[HygieneIssue]:
    issues: list[HygieneIssue] = []
    path = settings_path if settings_path is not None else _vscode_user_settings()
    if path is None:
        return issues  # VS Code not detected — nothing to assert
    try:
        text = path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return issues

    # JSONC-tolerant key probes (settings.json allows comments / trailing commas).
    auto = re.search(r'"task\.allowAutomaticTasks"\s*:\s*"([^"]+)"', text)
    if auto is None:
        issues.append(HygieneIssue(
            id="vscode-autotasks-default",
            severity="info",
            title="VS Code automatic tasks not explicitly disabled",
            detail=f'{path} does not set "task.allowAutomaticTasks". Folder-open auto-run is '
                   "the vector the worm used to execute a disguised font on open.",
            remediation='Set "task.allowAutomaticTasks": "off" in VS Code user settings.',
        ))
    elif auto.group(1) != "off":
        issues.append(HygieneIssue(
            id="vscode-autotasks-on",
            severity="warning",
            title="VS Code automatic tasks are enabled",
            detail=f'{path} sets "task.allowAutomaticTasks": "{auto.group(1)}" — folder-open '
                   "tasks can run on open without confirmation.",
            remediation='Set "task.allowAutomaticTasks": "off".',
        ))

    if re.search(r'"security\.workspace\.trust\.enabled"\s*:\s*false', text):
        issues.append(HygieneIssue(
            id="vscode-workspace-trust-off",
            severity="warning",
            title="VS Code Workspace Trust is disabled",
            detail=f"{path} disables Workspace Trust, so untrusted folders run code freely.",
            remediation='Remove the override or set "security.workspace.trust.enabled": true.',
        ))
    return issues


# --- repository branch protection (the only enforced CI gate) ---------------

def check_branch_protection(slug: str | None, token: str | None,
                            branch: str = "main") -> list[HygieneIssue]:
    """Warn if the default branch isn't protected or the Worm Guard check isn't
    required — i.e. the CI gate can be bypassed by a direct push / unchecked merge.
    No-op without a repo slug and token."""
    if not slug or "/" not in slug or not token:
        return []
    from stayawake.core.adapters import github_api
    owner, name = slug.split("/", 1)
    prot = github_api.get_branch_protection(owner, name, branch, token)
    if prot is None:
        return [HygieneIssue(
            id="branch-unprotected",
            severity="warning",
            title=f"{slug}@{branch} has no branch protection",
            detail="Anyone with push access can push straight to the default branch, "
                   "bypassing the Worm Guard CI gate entirely.",
            remediation="Protect the branch: require a PR review and the "
                        "'Worm Guard' status check before merging.",
        )]
    rsc = prot.get("required_status_checks") or {}
    contexts = set(rsc.get("contexts") or [])
    contexts |= {c.get("context") for c in (rsc.get("checks") or []) if isinstance(c, dict)}
    if not any("worm" in (c or "").lower() for c in contexts):
        return [HygieneIssue(
            id="worm-guard-not-required",
            severity="warning",
            title=f"Worm Guard is not a required status check on {slug}@{branch}",
            detail="An infected PR/merge can be merged without the worm scan passing.",
            remediation="Add 'Worm Guard — block infected merges' to the branch's "
                        "required status checks.",
        )]
    return []


# --- orchestration ----------------------------------------------------------

def audit(slug: str | None = None, token: str | None = None) -> list[HygieneIssue]:
    """Run every local-posture check and return the combined issue list. When a repo
    `slug` and `token` are supplied, also audit the branch-protection gate."""
    return check_credentials() + check_vscode() + check_branch_protection(slug, token)


def render(issues: list[HygieneIssue]) -> str:
    if not issues:
        return "✓ Local security hygiene: no issues found."
    icon = {"warning": "⚠️", "info": "•"}
    lines = [f"Local security hygiene — {len(issues)} item(s):", ""]
    for i in issues:
        lines.append(f"{icon.get(i.severity, '•')}  [{i.severity}] {i.title}")
        lines.append(f"     {i.detail}")
        lines.append(f"     fix: {i.remediation}")
        lines.append("")
    return "\n".join(lines).rstrip()
