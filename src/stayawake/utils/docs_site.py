#!/usr/bin/env python3
"""Links saw prints to its hosted documentation (single responsibility: the address of each topic)."""
from __future__ import annotations

SITE = "https://saw-docs.ndevuspace.com"


def link(name: str) -> str:
    """Build the short link to one documentation topic. Takes the topic's name in
    `docs/short-links.yml`. Returns the address."""
    return f"{SITE}/go/{name}/"


AUDIT_A_MACHINE = link("audit-a-machine")
WHAT_A_CLEAN_AUDIT_MEANS = link("clean-audit")
CREDENTIAL_HYGIENE = link("credential-hygiene")
FIX_FINDINGS = link("fix-findings")
