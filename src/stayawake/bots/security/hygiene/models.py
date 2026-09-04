#!/usr/bin/env python3
"""Shared hygiene domain types: HygieneIssue + the incident-response sequencing (rotate-LAST).

Leaf module (no dependency on the check submodules) so every check imports it without a cycle.
"""
from __future__ import annotations


POSIX_SHELLS = ("sh", "bash", "zsh", "dash", "ksh")
SCRATCH_ROOTS = ("/tmp", "/var/tmp", "/private/tmp", "/dev/shm")

import sys
from dataclasses import dataclass, asdict
from typing import Any


def persistence_surface_is_enumerable() -> bool:
    """Does THIS platform have a user-scope persistence surface `saw` enumerates at all?

    ONE authority — the scope note and the coverage probe both ask here, because on Windows every
    certified location reads absent for a reason that says nothing about the host."""
    return not sys.platform.startswith("win")


@dataclass
class HygieneIssue:
    id: str
    severity: str
    title: str
    detail: str
    remediation: str
    command: str | None = None
    reference: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


# --- incident-response sequencing (SAFETY: rotate credentials LAST) ---------
#
# Rotating a token while worm persistence is still live on a host can arm a reported
# destructive tripwire: the Mini Shai-Hulud variant is reported to install a service
# (gh-token-monitor.service) that WIPES the home directory when it detects credential
# rotation (MITRE T1485). So the reflexive "rotate everything now" reaction is exactly
# what turns containment into data loss — isolate and neutralize persistence FIRST.

_WIPER_NOTE = "rotating can trigger a reported wiper that deletes your home directory"

ACTIVE_PERSISTENCE_IDS = {"self-hosted-runner-persistence", "os-service-persistence",
                          "host-drop-artifacts",
                          # a content-scan (--verify) found CONFIRMED worm code on the host
                          "host-artifact-content-infected",
                          # worm code appended to a module an installed application loads at startup
                          "app-bundle-payload",
                          # code running right now that never touched the disk
                          "live-obfuscated-process",
                          # active mechanism-based persistence (a live backdoor, not just hardening)
                          "ssh-authorized-keys-forced-command", "shell-profile-fetch-exec",
                          "git-fsmonitor-command", "git-hookspath-unsafe", "git-config-fetch-exec",
                          "autorun-unattributed-foothold"}

UNCONFIRMED_STAGING_IDS = {"host-drop-artifacts-staging",
                           "host-drop-artifact-outside-a-control"}

CREDENTIAL_EXPOSURE_IDS = {"git-credentials-plaintext"}

INCIDENT_TRIGGER_IDS = ACTIVE_PERSISTENCE_IDS | CREDENTIAL_EXPOSURE_IDS

TIER_ACTIVE_PERSISTENCE = "active-persistence"
TIER_CREDENTIAL_EXPOSURE = "credential-exposure"
TIER_UNCONFIRMED_STAGING = "unconfirmed-staging"
TIER_IDS: tuple[tuple[str, set[str]], ...] = (
    (TIER_ACTIVE_PERSISTENCE, ACTIVE_PERSISTENCE_IDS),
    (TIER_CREDENTIAL_EXPOSURE, CREDENTIAL_EXPOSURE_IDS),
    (TIER_UNCONFIRMED_STAGING, UNCONFIRMED_STAGING_IDS),
)


def incident_tier(issue_ids: set[str]) -> str | None:
    """The ONE place a run's incident tier is decided, for every consumer that must be proportionate to
    it (the banner, the scope note). None when no incident is indicated.

    This exists because deciding the tier twice is how five consecutive review rounds each found the
    report contradicting itself: a consumer re-derived "what kind of run is this?" from something that
    only CORRELATED with the answer — the rotation verdict (a priority function where persistence
    dominates), then `severity == "warning"` (nine warning ids are not incident-tier), then
    INCIDENT_TRIGGER_IDS (the union above, which flattens these tiers). Every proxy was right about the
    cases in front of it and wrong one case deeper. Ask here instead."""
    for tier, ids in TIER_IDS:
        if issue_ids & ids:
            return tier
    return None

SURFACE_UNREADABLE_ID = "persistence-surface-unverified"
SURFACE_ABSENT_ID = "persistence-surface-not-established"
BLOCKED_ID = "check-blocked"
BLOCKED_SURFACE_ID = "surface-check-blocked"
SURFACE_NOT_IMPLEMENTED_ID = "persistence-surface-not-implemented"
PROCESSES_NOT_READABLE_ID = "process-arguments-not-readable"
APP_BUNDLE_SCAN_BLOCKED_ID = "app-bundle-scan-blocked"
APP_BUNDLE_MODULE_UNREADABLE_ID = "app-bundle-module-unreadable"
HOST_ARTIFACT_SCAN_BLOCKED_ID = "host-artifact-scan-blocked"
UNVERIFIED_PERSISTENCE_IDS = {SURFACE_UNREADABLE_ID, SURFACE_ABSENT_ID, BLOCKED_SURFACE_ID,
                              SURFACE_NOT_IMPLEMENTED_ID, PROCESSES_NOT_READABLE_ID,
                              APP_BUNDLE_SCAN_BLOCKED_ID, APP_BUNDLE_MODULE_UNREADABLE_ID,
                              HOST_ARTIFACT_SCAN_BLOCKED_ID}


def could_not_read(paths) -> HygieneIssue:
    shown = "; ".join(str(p) for p in paths)
    return HygieneIssue(
        id=SURFACE_UNREADABLE_ID,
        severity="unknown",
        title="A location this check needed could not be read",
        detail="These locations exist but could not be read, so this host is UNKNOWN, not clean: "
               + shown + ".",
        remediation="Read them, or inspect them by hand. Until then do not rotate credentials: "
                    f"{_WIPER_NOTE}.",
    )

ROTATION_UNSAFE_IDS = ACTIVE_PERSISTENCE_IDS | UNVERIFIED_PERSISTENCE_IDS | UNCONFIRMED_STAGING_IDS

# `host-artifact-scanned-clean` retired: a clean content scan no longer renders a calmer
# finding, so the artifact keeps this grade whether or not `--verify` ran.
VERIFY_BEFORE_ROTATE_IDS = {"host-drop-artifact-weak"}

ROTATION_SAFE = "safe"
ROTATION_UNSAFE_PERSISTENCE = "unsafe-persistence"
ROTATION_UNSAFE_STAGING = "unsafe-staging"
ROTATION_UNSAFE_UNKNOWN = "unsafe-unknown"
ROTATION_SAFE_PENDING_CHECK = "safe-pending-check"


def rotation_safety(issue_ids: set[str]) -> str:
    """The run-level rotation-safety verdict from the set of finding ids. Active persistence dominates
    (a live wiper), then an unverified surface (couldn't look), else safe. See ROTATION_* above."""
    if issue_ids & ACTIVE_PERSISTENCE_IDS:
        return ROTATION_UNSAFE_PERSISTENCE
    if issue_ids & UNCONFIRMED_STAGING_IDS:
        return ROTATION_UNSAFE_STAGING
    if issue_ids & UNVERIFIED_PERSISTENCE_IDS:
        return ROTATION_UNSAFE_UNKNOWN
    if issue_ids & VERIFY_BEFORE_ROTATE_IDS:
        # weak context never modulates the verdict. What it does change is the CLAIM — "safe" becomes
        # "safe once you confirm", which is what the finding underneath already says.
        return ROTATION_SAFE_PENDING_CHECK
    return ROTATION_SAFE


def response_order(issue_id: str) -> int:
    """Where one finding sits in the response order — live foothold first, then exposure, then the
    rest. Reads the SAME `TIER_IDS` table `incident_tier()` does, so a new tier is one entry there
    and both the banner and the ordering follow. A second table would drift."""
    for rank, (_tier, ids) in enumerate(TIER_IDS):
        if issue_id in ids:
            return rank
    return len(TIER_IDS)


def display_rank(issue_id: str, severity: str) -> str:
    """The rank a finding is SHOWN at, which is not always the severity it carries.

    Active host persistence is graded `warning` like every other act-now finding, so a live
    foothold rendered identically to an editor setting. It is shown as `critical` instead. Reads
    the same set the banner and the rotation verdict read, so the three cannot disagree.
    """
    return "critical" if severity == "warning" and issue_id in ACTIVE_PERSISTENCE_IDS else severity


def incident_response_sequence() -> list[str]:
    """The canonical order for responding to a suspected worm compromise. Rotation is
    ALWAYS the last step: rotating while persistence is live can trigger the reported
    home-directory wiper. Isolate → image → rebuild → neutralize → THEN rotate."""
    # Steps only — no "1./2." prefixes: the renderer owns the numbering (core.render.marked_list),
    # so this stays pure data (and a non-terminal consumer can renumber/reformat it freely).
    return [
        "Isolate the host from the network first.",
        # Before the rebuild, which destroys what a plain delete left recoverable. Whether any
        # survives is a property of the PAYLOAD this host-side path never saw — so it is not asserted.
        "If files are missing, image the disk before rebuilding or running any fix — every write "
        "can overwrite content, and how much is recoverable depends on the wipe variant.",
        "Take self-hosted CI runners offline and rebuild affected hosts from known-clean images.",
        "Neutralize per-host persistence: unexpected services, planted CI workflows, and editor "
        "or agent auto-run hooks.",
        f"ONLY THEN rotate credentials, in order: npm → GitHub PATs → cloud keys → SSH keys. "
        f"Rotating earlier is dangerous: {_WIPER_NOTE}. If the step above could not be confirmed, "
        "image first and rotate anyway.",
    ]


def unconfirmed_staging_note() -> list[str]:
    """One kind of staging artifact in more than one place: enough to gate rotation, not enough to
    claim a live implant. Points at what to look at, and keeps rotation last."""
    return [
        "Inspect each location before trusting it — ordinary tooling puts one there, not several.",
        "`saw audit --verify` content-scans them for payload code.",
        f"Do NOT rotate credentials yet: {_WIPER_NOTE}.",
        "Rebuild the host only if a scan or your own inspection finds payload code.",
    ]


def credential_exposure_note() -> list[str]:
    """Proportionate guidance when a credential is exposed but NO active persistence was detected —
    exposure, not a confirmed compromise. Keeps the rotate-carefully caveat (a rotation-triggered
    home-directory wiper can't be fully excluded) WITHOUT the alarmist isolate-and-rebuild runbook."""
    return [
        "Move the exposed credential to a safer store — see the fix on each item below.",
        "No active host persistence was found, so this is exposure rather than a confirmed "
        "compromise; isolating or rebuilding is not warranted on this alone.",
        "Detection is best-effort: if you suspect this host for any other reason, isolate it first.",
        "Do not make a bulk credential rotation your first move — a rotation-triggered wiper cannot be fully "
        "excluded.",
    ]
