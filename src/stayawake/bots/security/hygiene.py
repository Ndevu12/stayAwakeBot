#!/usr/bin/env python3
"""Local machine security-posture checks (the "harden the surface" layer).

Single responsibility: inspect the *developer machine* — not repositories — for the
worm's entry and propagation surfaces, and report actionable hygiene issues:

  * a cached GitHub credential (the worm steals the macOS Keychain / git-credentials
    token; it survives SSH-key rotation and is how it pushed as you),
  * VS Code automatic-task execution + Workspace Trust disabled (the auto-run vector),
  * a self-hosted GitHub Actions runner (the worm's most durable, credential-rotation-
    surviving foothold), and a planted OS service / launch agent (the rotation wiper),
  * host filesystem drop-files — staged ingress tooling and data bundled for exfil.

Repository indicator scanning lives in the scanner/service; this is complementary.
Stdlib only; every probe degrades gracefully when a path/tool is absent.
"""
from __future__ import annotations

import getpass
import os
import re
import socket
import subprocess
import tempfile
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
                        "self-hosted-runner-persistence", "os-service-persistence",
                        "host-drop-artifacts"}


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
# surviving credential rotation and CI re-provisioning (T1543/T1546). Detection: an installed
# runner dir with a `.runner` config, and/or a registered `actions.runner.*` service. (The
# rotation-wiper OS service, gh-token-monitor, is a SEPARATE persistence artifact owned by
# check_persistence() below.) Every probe degrades to a no-op when a tool/path is absent.

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


def _installed_runner_dir() -> Path | None:
    for d in _RUNNER_DIR_CANDIDATES:
        try:
            if (d / ".runner").is_file():
                return d
        except OSError:
            continue
    return None


def _is_runner_label(name: str) -> bool:
    return name.startswith("actions.runner.")


def _runner_services() -> list[str]:
    """Best-effort list of registered self-hosted-runner service labels on this host.

    Reads launchd (macOS) and systemd (Linux) — the latter in BOTH system and user scope and
    via `list-unit-files` too, so an installed-but-not-started unit is seen, not just running
    ones. Absent tools / missing session buses degrade to a no-op. Order-preserving de-dup."""
    found: list[str] = []
    try:                                    # macOS launchd — actions.runner.<...>
        r = subprocess.run(["launchctl", "list"], capture_output=True, text=True, timeout=10)
        if r.returncode == 0:
            for ln in r.stdout.splitlines():
                parts = ln.split()
                if parts and _is_runner_label(parts[-1]):
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
                if parts and _is_runner_label(parts[0]):
                    found.append(parts[0])
        if scope is None:
            break
    return list(dict.fromkeys(found))            # de-dup, preserve order


def check_runner_persistence() -> list[HygieneIssue]:
    """Detect a self-hosted runner install/registration on this host.

    SAFETY: the remediation must NOT tell the user to rotate credentials first — rotating
    while the runner persistence is still live can trip the reported home-dir wiper.
    Advise isolate → runner offline + registration/service removed → rebuild → THEN rotate."""
    runner_dir = _installed_runner_dir()
    runner_services = _runner_services()

    if runner_dir is None and not runner_services:
        return []
    where = []
    if runner_dir is not None:
        where.append(f"install at {runner_dir} (.runner config present)")
    if runner_services:
        where.append(f"registered service(s): {', '.join(sorted(runner_services))}")
    return [HygieneIssue(
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
    )]


# --- OS-service persistence (the rotation-wiper foothold, T1543/T1485) -------
#
# The Mini variant installs a planted OS service — reported as gh-token-monitor.service on
# Linux (systemd) — that watches for credential rotation and WIPES the home directory when it
# fires (T1485). Detect it by NAME across the standard unit/agent directories (read-only dir
# listing, so it works with no systemctl/launchctl and degrades to a no-op when the dirs are
# absent). Finding it must precede any rotation — it is an INCIDENT_TRIGGER, so render() leads
# with the rotate-LAST runbook. Consolidates all wiper/OS-service detection in one place
# (check_runner_persistence handles the runner; this handles the service).
_PERSIST_NAMED = "gh-token-monitor"             # the reported wiper — strong, named IoC
_PERSIST_LOOKALIKE = re.compile(r"gh-token|token-monitor", re.IGNORECASE)  # investigate-worthy


def _systemd_unit_dirs() -> tuple[Path, ...]:
    # Computed at call time (not baked at import) so Path.home() is evaluated fresh — testable.
    return (Path.home() / ".config/systemd/user",   # Linux user units (no root needed)
            Path("/etc/systemd/system"),            # system units (read-only, best-effort)
            Path("/etc/systemd/user"),
            Path("/usr/lib/systemd/system"))


def _launchd_dirs() -> tuple[Path, ...]:
    return (Path.home() / "Library/LaunchAgents",   # macOS user agents (no root needed)
            Path("/Library/LaunchAgents"),          # system agents/daemons (read-only, best-effort)
            Path("/Library/LaunchDaemons"))


def _scan_service_dirs(dirs, suffixes) -> list[tuple[Path, bool]]:
    """(path, is_named) for unit/agent files whose NAME matches the wiper or a lookalike.
    Read-only directory listing; a missing/unreadable dir is skipped (graceful degradation)."""
    hits: list[tuple[Path, bool]] = []
    for d in dirs:
        try:
            entries = sorted(d.iterdir())
        except (OSError, ValueError):
            continue                             # dir absent/unreadable — skip
        for p in entries:
            name = p.name.lower()
            if not name.endswith(suffixes):
                continue
            if _PERSIST_NAMED in name:
                hits.append((p, True))
            elif _PERSIST_LOOKALIKE.search(name):
                hits.append((p, False))
    return hits


def check_persistence() -> list[HygieneIssue]:
    """Detect a planted OS service / launch agent (the reported gh-token-monitor rotation wiper
    and lookalikes) on this host. Stdlib-only, read-only, graceful when dirs are absent.

    SAFETY: its mere presence makes rotation dangerous, so the remediation sequences isolate +
    neutralize BEFORE any credential rotation (the wiper tripwire)."""
    hits = (_scan_service_dirs(_systemd_unit_dirs(), (".service", ".timer"))
            + _scan_service_dirs(_launchd_dirs(), (".plist",)))
    if not hits:
        return []
    named = sorted({str(p) for p, is_named in hits if is_named})
    lookalike = sorted({str(p) for p, is_named in hits if not is_named})
    what = []
    if named:
        what.append(f"the reported wiper service ({', '.join(named)})")
    if lookalike:
        what.append(f"lookalike unit(s) to investigate ({', '.join(lookalike)})")
    return [HygieneIssue(
        id="os-service-persistence",
        severity="warning",
        title="Planted OS-service persistence (credential-rotation wiper)",
        detail="Found a planted OS service / launch agent — " + "; ".join(what) + ". The Mini "
               "Shai-Hulud gh-token-monitor service watches for credential rotation and WIPES the "
               "home directory when it detects one (T1543/T1485) — so its presence makes rotating "
               "any token dangerous.",
        remediation="Do NOT rotate any credential yet. Isolate the host, disable and remove the "
                    "service/agent (systemctl --user disable --now <unit>, or launchctl bootout + "
                    "delete the plist), rebuild from a known-clean image, and rotate credentials "
                    f"LAST — {_WIPER_NOTE}.",
    )]


# --- host filesystem drop artifacts (ingress tooling / data staging, T1105/T1074) ---
#
# Distinct from the runner / OS-service PERSISTENCE probes above (#1092/#1094): these are the
# drop-files this wave stages on a developer host — downloaded tooling and stolen data bundled
# before exfil. Some are weak on their own (a stray ~/.node_modules, an npm cache), so a LONE weak
# indicator is `info`; a strong, specific IoC or a corroborated set (>=2) is a `warning`. A positive
# means persistence may be LIVE, so the guidance follows the rotate-LAST order (#1088), never first.
# Every probe is a read-only stat/listdir and degrades to nothing when a path is absent/unreadable.

def _host_user_tag() -> str | None:
    """`<hostname>$<username>` — the name the wave gives a staged exfil archive on this host."""
    try:
        host = socket.gethostname().split(".")[0]
        user = getpass.getuser()
    except Exception:                       # gethostname/getuser can fail on odd hosts — degrade
        return None
    return f"{host}${user}" if host and user else None


def _first_child_named(directory: Path, prefix: str) -> Path | None:
    try:
        for entry in sorted(directory.iterdir()):
            if entry.name.startswith(prefix):
                return entry
    except OSError:
        pass
    return None


def _sideloaded_python_dir() -> Path | None:
    """A Windows `%LOCALAPPDATA%\\…\\Python3127\\` dir carrying the sideloaded interpreter/archiver
    (python.exe/python.zip/python.7z/7zr.exe). No-op off Windows (LOCALAPPDATA unset)."""
    local = os.environ.get("LOCALAPPDATA")
    if not local:
        return None
    sideload = {"python.exe", "python.zip", "python.7z", "7zr.exe"}
    for pattern in ("Python3127", "*/Python3127", "*/*/Python3127"):   # bounded, not a full walk
        try:
            for d in Path(local).glob(pattern):
                try:
                    if d.is_dir() and {f.name.lower() for f in d.iterdir()} & sideload:
                        return d
                except OSError:
                    continue
        except OSError:
            continue
    return None


def _staged_secret_scanner(dirs) -> Path | None:
    """A trufflehog secret-scanner BINARY staged in a cache/temp dir (T1588.002/T1552). Matches a
    FILE only — trufflehog's own `~/.cache/trufflehog` DIR (a legit user's cache) is not a hit."""
    for d in dirs:
        for name in ("trufflehog", "trufflehog.exe"):
            p = d / name
            try:
                if p.is_file():
                    return p
            except OSError:
                continue
    return None


def _host_artifacts() -> tuple[list[str], list[str]]:
    """Return (strong, weak) descriptions of detected host-IoC drop artifacts."""
    home = Path.home()
    tmp_dirs = sorted({Path("/tmp"), Path(tempfile.gettempdir())}, key=str)
    strong: list[str] = []
    weak: list[str] = []

    def _present(p: Path) -> bool:
        try:
            return p.exists()
        except OSError:
            return False

    # Weak drop-files — rarely benign, but each is a single low-confidence indicator.
    if _present(home / ".node_modules"):
        weak.append(f"{home}/.node_modules (payload-created)")
    for t in tmp_dirs:
        if _present(t / ".npm"):
            weak.append(f"{t}/.npm")
        if _present(t / "get-pip.py"):
            weak.append(f"{t}/get-pip.py")

    # Strong, specific IoCs.
    tag = _host_user_tag()                                  # <host>$<user> staged exfil archive
    if tag:
        for d in (home, home / ".npm", *tmp_dirs, Path.cwd()):
            match = _first_child_named(d, tag)
            if match is not None:
                strong.append(f"{match} (<host>$<user> exfil staging archive)")
                break
    sideloaded = _sideloaded_python_dir()
    if sideloaded is not None:
        strong.append(f"{sideloaded} (sideloaded Python3127 interpreter)")
    scanner = _staged_secret_scanner((home / ".cache", home / ".npm", *tmp_dirs))
    if scanner is not None:
        strong.append(f"{scanner} (staged secret-scanner binary)")
    return strong, weak


def check_host_artifacts() -> list[HygieneIssue]:
    """Detect host filesystem drop-files this wave stages on a developer workstation.

    FP-bounded: a strong/specific IoC or a corroborated set (>=2) is a `warning`; a lone weak
    indicator is `info`. SAFETY: a positive means persistence may be live, so the remediation
    follows the rotate-LAST order (#1088) — never advise rotating a credential first."""
    strong, weak = _host_artifacts()
    found = strong + weak
    if not found:
        return []
    if strong or len(found) >= 2:
        return [HygieneIssue(
            id="host-drop-artifacts",
            severity="warning",
            title="Host filesystem artifacts consistent with a supply-chain payload",
            detail="Found: " + "; ".join(found) + ". These are ingress-tooling / data-staging "
                   "drop-files (T1105/T1074) this wave leaves on a developer host.",
            remediation="Do NOT rotate credentials first — treat as possible LIVE compromise. "
                        "Isolate the host, neutralize any persistence, rebuild from a known-clean "
                        f"image, and rotate credentials LAST — {_WIPER_NOTE}.",
        )]
    return [HygieneIssue(          # a single weak indicator — inform, don't alarm; still rotate-LAST
        id="host-drop-artifact-weak",
        severity="info",
        title="Possible supply-chain drop-file on this host",
        detail="Found: " + "; ".join(found) + ". Rarely benign, but only one weak indicator — "
               "verify whether you created it.",
        remediation="If you did not create it, treat as possible compromise: isolate the host and "
                    f"neutralize any persistence BEFORE rotating any credential ({_WIPER_NOTE}).",
    )]


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
            + check_persistence() + check_host_artifacts()
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
