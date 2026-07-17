#!/usr/bin/env python3
"""Shared hygiene domain types: HygieneIssue + the incident-response sequencing (rotate-LAST).

Leaf module (no dependency on the check submodules) so every check imports it without a cycle.
"""
from __future__ import annotations

from dataclasses import dataclass, asdict
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
                        "host-drop-artifacts",
                        # active mechanism-based persistence (a live backdoor, not just hardening)
                        "ssh-authorized-keys-forced-command", "shell-profile-fetch-exec",
                        "git-fsmonitor-command", "git-hookspath-unsafe", "git-config-fetch-exec"}


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
