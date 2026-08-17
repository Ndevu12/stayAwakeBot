---
description: Mapping the removed stayawake-security-* scripts to their saw equivalents.
---

# Migrating from the legacy scripts

The `stayawake-security-*` console scripts have been removed; `saw` is the only local security
surface. The `stayawake-health-*` scripts are unchanged.

| Legacy command (removed) | `saw` equivalent |
| --- | --- |
| `stayawake-security-scan` | `saw scan` (the exit code **is** the verdict — no flag) |
| `stayawake-security-report` | `saw scan` (the report renders to the terminal) |
| `stayawake-security-alert` | `saw scan --alert` |
| `stayawake-security-remediate [--apply --open-pr\|--remote]` | `saw fix [--pr\|--remote]` |
| `stayawake-security-audit --repo OWNER/NAME --fail-on-issues` | `saw audit --repo OWNER/NAME -f` |
