#!/usr/bin/env python3
"""Self-hosted GitHub Actions runner persistence — the worm's most durable, rotation-surviving foothold."""
from __future__ import annotations

import subprocess
from pathlib import Path

from .models import HygieneIssue, _WIPER_NOTE

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


