#!/usr/bin/env python3
"""Links to saw's hosted documentation (single responsibility: where each page saw points to lives)."""
from __future__ import annotations

SITE = "https://saw-docs.ndevuspace.com/latest"


def page(path: str, section: str = "") -> str:
    """Build the link to one page of the hosted documentation. Takes the page's path under `docs/`
    without `.md`, and the id of a section on it. Returns the address."""
    return f"{SITE}/{path}/" + (f"#{section}" if section else "")


FIX_FINDINGS = page("how-to/fix-findings")
AUDIT_A_MACHINE = page("how-to/audit-a-machine")
WHAT_A_CLEAN_AUDIT_MEANS = page("how-to/audit-a-machine", "what-a-clean-audit-does-and-does-not-mean")
CREDENTIAL_HYGIENE = page("explanation/credential-hygiene")
