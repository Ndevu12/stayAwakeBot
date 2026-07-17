#!/usr/bin/env python3
"""Planted OS-service / launch-agent persistence — the gh-token-monitor rotation wiper + lookalikes."""
from __future__ import annotations

import re
from pathlib import Path

from .models import HygieneIssue, _WIPER_NOTE

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


