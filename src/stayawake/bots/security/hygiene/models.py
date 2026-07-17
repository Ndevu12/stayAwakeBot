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

# Response is GRADED to the evidence (proportionality — match the alarm to what was actually found):
#
# ACTIVE_PERSISTENCE — a live foothold/backdoor is present, so the full isolate → neutralize → rebuild
# → rotate-LAST runbook is warranted. These are the findings that justify "isolate and rebuild".
ACTIVE_PERSISTENCE_IDS = {"self-hosted-runner-persistence", "os-service-persistence",
                          "host-drop-artifacts",
                          # a content-scan (--verify) found CONFIRMED worm code on the host
                          "host-artifact-content-infected",
                          # active mechanism-based persistence (a live backdoor, not just hardening)
                          "ssh-authorized-keys-forced-command", "shell-profile-fetch-exec",
                          "git-fsmonitor-command", "git-hookspath-unsafe", "git-config-fetch-exec"}

# CREDENTIAL EXPOSURE — a cached/plaintext token is worth acting on, but is NOT proof of a compromised
# host. When it is the WORST thing found (no active persistence alongside it), the response is a calm
# credential note, NOT "isolate and rebuild" — while keeping the one caveat that matters: a hidden
# rotation-wiper can't be fully excluded, so don't make bulk rotation the first move.
CREDENTIAL_EXPOSURE_IDS = {"cached-github-keychain", "git-credentials-plaintext"}

# Union kept for back-compat (any finding that carries an incident context, of either tier).
INCIDENT_TRIGGER_IDS = ACTIVE_PERSISTENCE_IDS | CREDENTIAL_EXPOSURE_IDS


def incident_response_sequence() -> list[str]:
    """The canonical order for responding to a suspected worm compromise. Rotation is
    ALWAYS the last step: rotating while persistence is live can trigger the reported
    home-directory wiper. Isolate → rebuild → neutralize → THEN rotate."""
    # Steps only — no "1./2." prefixes: the renderer owns the numbering (core.render.marked_list),
    # so this stays pure data (and a non-terminal consumer can renumber/reformat it freely).
    return [
        "Isolate the host from the network before doing anything else.",
        "Take self-hosted CI runners offline and rebuild affected hosts from known-clean "
        "images (watch for a runner named SHA1HULUD).",
        "Neutralize per-host persistence: rogue OS services (e.g. gh-token-monitor.service), "
        "planted CI workflows, and editor/AI-agent auto-run hooks (.vscode/, .claude/).",
        "ONLY THEN rotate credentials, in order: npm → GitHub PATs → cloud keys → SSH keys. "
        f"Rotating earlier is dangerous — {_WIPER_NOTE}.",
    ]


def credential_exposure_note() -> list[str]:
    """Proportionate guidance when a credential is exposed but NO active persistence was detected —
    exposure, not a confirmed compromise. Keeps the rotate-carefully caveat (a rotation-triggered
    home-directory wiper can't be fully excluded) WITHOUT the alarmist isolate-and-rebuild runbook."""
    return [
        "Move the exposed credential to a safer store (see the fix on each item below).",
        "No active host persistence was detected here — this is credential EXPOSURE, not a confirmed "
        "compromise, so host isolation / rebuild isn't warranted on this evidence alone.",
        "Detection is best-effort, though: if you have any OTHER reason to suspect this host, isolate "
        "it first regardless.",
        "Precaution: don't make a bulk credential rotation your first move — a rotation-triggered "
        "home-directory wiper (not found here, but not fully excludable) is the reason.",
    ]
