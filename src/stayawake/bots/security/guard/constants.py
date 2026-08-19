#!/usr/bin/env python3
"""Shared constants for `saw guard` — the canonical Strix action, its third-party action pins,
workflow paths, setup branch."""
from __future__ import annotations

from dataclasses import dataclass

STRIX_OWNER, STRIX_REPO = "Ndevu12", "strix"
WORKFLOW_DIR = ".github/workflows"
WORM_GUARD_FILE = f"{WORKFLOW_DIR}/worm-guard.yml"
SETUP_BRANCH = "security/guard-setup"


@dataclass(frozen=True)
class ActionPin:
    """A third-party action pinned by COMMIT SHA, carrying the release tag it names.

    The tag is a readability comment only — never the ref. A tag can be repointed at different code
    after someone reviewed it; a SHA cannot, and this generator writes into OTHER people's
    repositories, into a job holding `contents: write`."""

    repo: str
    sha: str
    tag: str

    def uses(self) -> str:
        """The `uses:` value plus its trailing tag comment, as written into the workflow."""
        return f"{self.repo}@{self.sha}   # {self.tag}"


CHECKOUT_ACTION = ActionPin("actions/checkout", "9c091bb21b7c1c1d1991bb908d89e4e9dddfe3e0", "v7.0.0")
SETUP_PYTHON_ACTION = ActionPin(
    "actions/setup-python", "ece7cb06caefa5fff74198d8649806c4678c61a1", "v6.3.0")
