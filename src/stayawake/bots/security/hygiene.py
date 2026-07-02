#!/usr/bin/env python3
"""Local machine security-posture checks (the "harden the surface" layer).

Single responsibility: inspect the *developer machine* — not repositories — for the
worm's entry and propagation surfaces, and report actionable hygiene issues:

  * a cached GitHub credential (the worm steals the macOS Keychain / git-credentials
    token; it survives SSH-key rotation and is how it pushed as you),
  * VS Code automatic-task execution + Workspace Trust disabled (the auto-run vector),
  * a self-hosted GitHub Actions runner / rotation-wiper service (the worm's most durable,
    credential-rotation-surviving foothold).

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


# --- incident-response sequencing (SAFETY: rotate credentials LAST) ---------
#
# Rotating a token while worm persistence is still live on a host can arm a reported
# destructive tripwire: the Mini Shai-Hulud variant is reported to install a service
# (gh-token-monitor.service) that WIPES the home directory when it detects credential
# rotation (MITRE T1485). So the reflexive "rotate everything now" reaction is exactly
# what turns containment into data loss — isolate and neutralize persistence FIRST.

# Naming the tripwire once, reused in the rotation remediation and the runbook below.
_WIPER_NOTE = ("Mini Shai-Hulud is reported to install a service (gh-token-monitor.service) "
               "that wipes the home directory when it detects credential rotation")

# Issues whose presence means the ordered incident-response runbook must be surfaced —
# credential exposure (a user seeing this will want to rotate) or host persistence. Host
# runner/service persistence belongs here too: seeing it, a user's reflex is to rotate, which
# is exactly the wiper tripwire — so the rotate-LAST runbook must lead.
INCIDENT_TRIGGER_IDS = {"cached-github-keychain", "git-credentials-plaintext",
                        "self-hosted-runner-persistence", "wiper-service-present"}


def incident_response_sequence() -> list[str]:
    """The canonical order for responding to a suspected worm compromise. Rotation is
    ALWAYS the last step: rotating while persistence is live can trigger the reported
    home-directory wiper. Isolate → rebuild → neutralize → THEN rotate."""
    return [
        "1. Isolate the host from the network before doing anything else.",
        "2. Take self-hosted CI runners offline and rebuild affected hosts from known-clean "
        "images (watch for a runner named SHA1HULUD).",
        "3. Neutralize per-host persistence: rogue OS services (e.g. gh-token-monitor.service), "
        "planted CI workflows, and editor/AI-agent auto-run hooks (.vscode/, .claude/).",
        "4. ONLY THEN rotate credentials, in order: npm → GitHub PATs → cloud keys → SSH keys. "
        f"Rotating earlier is dangerous — {_WIPER_NOTE}.",
    ]


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
            remediation="Delete the file and switch to an OS keychain helper or SSH now. "
                        "Rotate the exposed token LAST — only after isolating the host and "
                        f"neutralizing any persistence (see the incident-response steps): {_WIPER_NOTE}.",
        ))
    return issues


# --- self-hosted runner persistence (the worm's most durable foothold) ------
#
# Shai-Hulud 2.0 / Mini registers the compromised host as a self-hosted GitHub Actions
# runner (reported name SHA1HULUD) so attacker workflows keep executing on the host —
# surviving credential rotation and CI re-provisioning (T1543/T1546). It is also reported
# to install an OS-service foothold (gh-token-monitor.service, the rotation wiper). Both
# leave detectable host artifacts: an installed runner dir with a `.runner` config, and/or
# a registered runner/service. Every probe degrades to a no-op when a tool/path is absent.

# Common self-hosted-runner install locations (the runner may live anywhere, but these
# cover the documented defaults). We treat a dir as an install only if it holds a `.runner`
# config — i.e. an actually *registered* runner, not just an extracted tarball. A runner
# under a dedicated service account or on Windows is a known coverage gap (see the service
# probe, which is the primary signal); this is a fast best-effort corroborator.
_RUNNER_DIR_CANDIDATES = (
    Path.home() / "actions-runner",
    Path.home() / "runner",
    Path("/opt/actions-runner"),
    Path("/actions-runner"),
)

# The reported rotation-wiper unit, matched by substring so a `@template` / case variant also
# hits. On-disk unit paths are checked directly so an INSTALLED-but-not-started wiper (which
# `systemctl list-units` would not show) is still caught — it's the safety-critical signal.
_WIPER_UNIT_PATHS = (
    Path("/etc/systemd/system/gh-token-monitor.service"),
    Path("/usr/lib/systemd/system/gh-token-monitor.service"),
    Path.home() / ".config/systemd/user/gh-token-monitor.service",
)


def _installed_runner_dir() -> Path | None:
    for d in _RUNNER_DIR_CANDIDATES:
        try:
            if (d / ".runner").is_file():
                return d
        except OSError:
            continue
    return None


def _is_runner_or_wiper(name: str) -> bool:
    return name.startswith("actions.runner.") or "gh-token-monitor" in name


def _runner_services() -> list[str]:
    """Best-effort list of registered-runner / known-wiper service labels on this host.

    Reads launchd (macOS) and systemd (Linux) — the latter in BOTH system and user scope and
    via `list-unit-files` too, so an installed-but-not-started unit (e.g. a dropped wiper) is
    seen, not just running ones. Absent tools / missing session buses degrade to a no-op. The
    wiper is matched on both launchd and systemd (the safety-critical signal must not be
    platform-dependent). Order-preserving de-dup at the end."""
    found: list[str] = []
    try:                                    # macOS launchd — actions.runner.<...> + wiper job
        r = subprocess.run(["launchctl", "list"], capture_output=True, text=True, timeout=10)
        if r.returncode == 0:
            for ln in r.stdout.splitlines():
                parts = ln.split()
                if parts and _is_runner_or_wiper(parts[-1]):
                    found.append(parts[-1])
    except (FileNotFoundError, OSError, subprocess.SubprocessError, IndexError):
        pass
    for scope in (["--system"], ["--user"]):    # Linux systemd — system + user managers
        for verb in ("list-units", "list-unit-files"):
            try:
                r = subprocess.run(
                    ["systemctl", *scope, verb, "--type=service", "--all",
                     "--no-legend", "--plain"],
                    capture_output=True, text=True, timeout=10)
            except (FileNotFoundError, OSError, subprocess.SubprocessError):
                scope = None                    # systemctl absent — stop probing systemd
                break
            if r.returncode != 0:
                continue
            for ln in r.stdout.splitlines():
                parts = ln.split()
                if parts and _is_runner_or_wiper(parts[0]):
                    found.append(parts[0])
        if scope is None:
            break
    for p in _WIPER_UNIT_PATHS:                  # installed-but-not-started wiper unit file
        try:
            if p.is_file():
                found.append(p.name)
        except OSError:
            continue
    return list(dict.fromkeys(found))            # de-dup, preserve order


def check_runner_persistence() -> list[HygieneIssue]:
    """Detect a self-hosted runner install and/or the reported wiper service on this host.

    SAFETY: the remediation must NOT tell the user to rotate credentials first — rotating
    while the runner/wiper persistence is still live can trip the reported home-dir wiper.
    Advise isolate → runner offline + registration/service removed → rebuild → THEN rotate."""
    runner_dir = _installed_runner_dir()
    services = _runner_services()
    wiper = [s for s in services if "gh-token-monitor" in s]
    runner_services = [s for s in services if s.startswith("actions.runner")]

    issues: list[HygieneIssue] = []
    if runner_dir is not None or runner_services:
        where = []
        if runner_dir is not None:
            where.append(f"install at {runner_dir} (.runner config present)")
        if runner_services:
            where.append(f"registered service(s): {', '.join(sorted(runner_services))}")
        issues.append(HygieneIssue(
            id="self-hosted-runner-persistence",
            severity="warning",
            title="Self-hosted GitHub Actions runner registered on this host",
            # Conditional framing — a legitimately-operated runner is not itself malicious; we
            # flag it because an UNEXPECTED one is the worm's persistence (reported name SHA1HULUD).
            detail="A self-hosted runner is installed/registered — " + "; ".join(where) + ". "
                   "If you did not intentionally set this up, it is the worm's most durable "
                   "foothold (reported runner name SHA1HULUD): attacker workflows keep executing "
                   "here and it survives credential rotation.",
            remediation="Do NOT rotate credentials first. Isolate the host, take the runner "
                        "offline and remove its registration (./config.sh remove) and service, "
                        "rebuild from a known-clean image, and rotate credentials LAST — "
                        f"{_WIPER_NOTE}.",
        ))
    if wiper:
        issues.append(HygieneIssue(
            id="wiper-service-present",
            severity="warning",
            title="Reported credential-rotation wiper service is installed",
            detail=f"Found {', '.join(sorted(wiper))} — the Mini Shai-Hulud service reported to "
                   "WIPE the home directory when it detects credential rotation (T1485). Rotating "
                   "any token while this is live can destroy data.",
            remediation="Do NOT rotate credentials while this service exists. Isolate the host, "
                        "disable and remove the service, rebuild from a known-clean image, and "
                        "only THEN rotate credentials (see the incident-response order).",
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

def audit(slug: str | None = None, token: str | None = None,
          branch: str = "main") -> list[HygieneIssue]:
    """Run every local-posture check and return the combined issue list — the SINGLE place the
    checks are composed, so a new probe is picked up everywhere (the `saw audit` CLI calls this,
    it must never hand-assemble its own subset). When a repo `slug` and `token` are supplied,
    also audit the branch-protection gate on `branch`."""
    return (check_credentials() + check_vscode() + check_runner_persistence()
            + check_branch_protection(slug, token, branch))


def render(issues: list[HygieneIssue]) -> str:
    if not issues:
        return "✓ Local security hygiene: no issues found."
    icon = {"warning": "⚠️", "info": "•"}
    lines = [f"Local security hygiene — {len(issues)} item(s):", ""]
    # Credential exposure / host persistence present → lead with the ordered runbook so the
    # user rotates LAST (rotating while persistence is live can trip the wiper).
    if any(i.id in INCIDENT_TRIGGER_IDS for i in issues):
        lines.append("⚠️  Credential exposure or active host persistence detected — "
                     "respond in THIS order (rotate LAST):")
        lines += [f"     {step}" for step in incident_response_sequence()]
        lines.append("")
    for i in issues:
        lines.append(f"{icon.get(i.severity, '•')}  [{i.severity}] {i.title}")
        lines.append(f"     {i.detail}")
        lines.append(f"     fix: {i.remediation}")
        lines.append("")
    return "\n".join(lines).rstrip()
