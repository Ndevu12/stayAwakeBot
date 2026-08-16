#!/usr/bin/env python3
"""Shared hygiene domain types: HygieneIssue + the incident-response sequencing (rotate-LAST).

Leaf module (no dependency on the check submodules) so every check imports it without a cycle.
"""
from __future__ import annotations


# Host vocabulary — WHERE things live and WHAT they are called, shared by the probes. Detection
# PATTERNS (what a threat looks like) stay with their detector; only the nouns live here.
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
    severity: str          # "warning" (act now) | "info" (recommended)
    title: str
    detail: str
    remediation: str
    command: str | None = None    # copy-pasteable command(s), rendered VERBATIM on their own selectable
                                  # line(s) — kept out of `remediation` prose so the fix is selectable (#1237)
    reference: str | None = None  # optional docs URL, rendered as a "→ details: <url>" line (#1237)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


# --- incident-response sequencing (SAFETY: rotate credentials LAST) ---------
#
# Rotating a token while worm persistence is still live on a host can arm a reported
# destructive tripwire: the Mini Shai-Hulud variant is reported to install a service
# (gh-token-monitor.service) that WIPES the home directory when it detects credential
# rotation (MITRE T1485). So the reflexive "rotate everything now" reaction is exactly
# what turns containment into data loss — isolate and neutralize persistence FIRST.

# The tripwire named once, reused at every site where an operator might rotate. It stays at ALL of
# them: each is a decision point, and the cost of missing it is a wiped home directory.
#
# The SERVICE NAME stays too — it is greppable, so it is the actionable half, and #1088 pins it here.
# What went is the campaign name: the incident record eliminated both candidate campaigns on
# mechanism, so naming one asserted a guess as fact.
_WIPER_NOTE = ("rotating can trigger a reported wiper (gh-token-monitor.service) that deletes your "
               "home directory")

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
                          "git-fsmonitor-command", "git-hookspath-unsafe", "git-config-fetch-exec",
                          # a novel, unattributed autorun foothold caught by state+provenance, #1333
                          "autorun-unattributed-foothold"}

# CREDENTIAL EXPOSURE — a credential in a location that is genuinely a misconfiguration (plaintext on
# disk) is worth acting on, but is NOT proof of a compromised host. When it is the WORST thing found (no
# active persistence alongside it), the response is a calm credential note, NOT "isolate and rebuild" —
# while keeping the one caveat that matters: a hidden rotation-wiper can't be fully excluded, so don't
# make bulk rotation the first move.
#
# NOTE (#1237): a token cached in the *encrypted* login Keychain is deliberately NOT here. The Keychain
# is the recommended store — a cached token there is normal, not an exposure incident, so it renders as
# a calm `info` review item (see credentials.py) and never triggers this banner on its own. Only a
# genuinely misconfigured store — a PLAINTEXT `~/.git-credentials` — counts as exposure.
CREDENTIAL_EXPOSURE_IDS = {"git-credentials-plaintext"}

# Union kept for back-compat (any finding that carries an incident context, of either tier).
# DO NOT grade proportionality on this: it FLATTENS the two tiers below, which the report grades apart
# — that is how a plaintext-credential finding once ended a green, no-incident report with "scope your
# response". Ask incident_tier() instead; it is the single authority.
INCIDENT_TRIGGER_IDS = ACTIVE_PERSISTENCE_IDS | CREDENTIAL_EXPOSURE_IDS

# Incident tiers, most severe first. TABLE-DRIVEN so adding a tier is one entry here and every
# consumer follows — no consumer re-derives the tier, and no test can silently miss the new one.
TIER_ACTIVE_PERSISTENCE = "active-persistence"     # a live foothold on THIS host
TIER_CREDENTIAL_EXPOSURE = "credential-exposure"   # a secret is exposed; the host is not implicated
TIER_IDS: tuple[tuple[str, set[str]], ...] = (
    (TIER_ACTIVE_PERSISTENCE, ACTIVE_PERSISTENCE_IDS),
    (TIER_CREDENTIAL_EXPOSURE, CREDENTIAL_EXPOSURE_IDS),
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

# The run could not ESTABLISH the surface, so it may not claim clean over it — NOT a finding (nothing
# was found) and NOT clean (nothing was established). Two causes: a location EXISTS but could not be
# read (#1332), or the ENTIRE surface is absent so nothing was enumerated (#120, see coverage.py).
SURFACE_UNREADABLE_ID = "persistence-surface-unverified"
SURFACE_ABSENT_ID = "persistence-surface-not-established"
UNVERIFIED_PERSISTENCE_IDS = {SURFACE_UNREADABLE_ID, SURFACE_ABSENT_ID}

# The run may NOT assert that credential rotation is safe when EITHER active persistence was found OR
# the persistence surface could not be fully enumerated. Both withhold the all-clear (safety dominates:
# the catastrophic axis, encoded orthogonally to the confidence-graded finding verdict).
ROTATION_UNSAFE_IDS = ACTIVE_PERSISTENCE_IDS | UNVERIFIED_PERSISTENCE_IDS

# Rotation-safety verdict states (the run-level property #1332 adds). A property of the WHOLE run,
# reachable even when no individual finding is present.
ROTATION_SAFE = "safe"                 # surface enumerated AND clean → rotating credentials is safe
ROTATION_UNSAFE_PERSISTENCE = "unsafe-persistence"   # active persistence found → rotate LAST
ROTATION_UNSAFE_UNKNOWN = "unsafe-unknown"           # surface could not be verified → treat as unsafe


def rotation_safety(issue_ids: set[str]) -> str:
    """The run-level rotation-safety verdict from the set of finding ids. Active persistence dominates
    (a live wiper), then an unverified surface (couldn't look), else safe. See ROTATION_* above."""
    if issue_ids & ACTIVE_PERSISTENCE_IDS:
        return ROTATION_UNSAFE_PERSISTENCE
    if issue_ids & UNVERIFIED_PERSISTENCE_IDS:
        return ROTATION_UNSAFE_UNKNOWN
    return ROTATION_SAFE


def response_order(issue_id: str) -> int:
    """Where one finding sits in the response order — live foothold first, then exposure, then the
    rest. Reads the SAME `TIER_IDS` table `incident_tier()` does, so a new tier is one entry there
    and both the banner and the ordering follow. A second table would drift."""
    for rank, (_tier, ids) in enumerate(TIER_IDS):
        if issue_id in ids:
            return rank
    return len(TIER_IDS)


def incident_response_sequence() -> list[str]:
    """The canonical order for responding to a suspected worm compromise. Rotation is
    ALWAYS the last step: rotating while persistence is live can trigger the reported
    home-directory wiper. Isolate → image → rebuild → neutralize → THEN rotate."""
    # Steps only — no "1./2." prefixes: the renderer owns the numbering (core.render.marked_list),
    # so this stays pure data (and a non-terminal consumer can renumber/reformat it freely).
    return [
        "Isolate the host from the network before doing anything else.",
        # BEFORE the rebuild step, which is the one that destroys the evidence a plain delete left
        # recoverable. `saw scan` already computes the discriminator; nothing asked it here.
        "If files are missing, image the disk before rebuilding or using this host — continued use "
        "overwrites recoverable data. `saw scan` names which wipe variant ran.",
        "Take self-hosted CI runners offline and rebuild affected hosts from known-clean "
        "images (watch for a runner named SHA1HULUD).",
        "Neutralize per-host persistence: rogue OS services (e.g. gh-token-monitor.service), "
        "planted CI workflows, and editor/AI-agent auto-run hooks (.vscode/, .claude/).",
        f"ONLY THEN rotate credentials, in order: npm → GitHub PATs → cloud keys → SSH keys. "
        f"Rotating earlier is dangerous: {_WIPER_NOTE}.",
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
