#!/usr/bin/env python3
"""`saw fix` / `saw discard` PR flows. Split per concern: `constants` / `render` (PR & issue bodies +
review-line summaries) / `fix` (build & submit the fix PR, proposed-only) / `discard` (the inverse).
Flat re-export of the PUBLIC API so callers import unchanged; internal body helpers (`_pr_body`,
`_issue_body`, …) live in their submodule and are reached at `pr.render.<helper>`."""
from __future__ import annotations

from stayawake.bots.security.pr.constants import FIX_BRANCH, ISSUE_LABEL, PARTIAL_LABEL
from stayawake.bots.security.pr.render import manual_review_lines, computed_review_lines
from stayawake.bots.security.pr.fix import prepare_fix, submit_fix_pr
from stayawake.bots.security.pr.discard import (
    discard_branch, discard_pr, discard_remote_branch, discard_remote_pr)
# Module singletons re-exported so `pr.github_api` / `pr.gitutil` / `pr.remediation` resolve (tests
# patch these) — a module is one object, so patching here reaches the submodules that use it.
from stayawake.lib.adapters import github_api
from stayawake.lib import git as gitutil
from stayawake.bots.security import remediation

__all__ = [
    "FIX_BRANCH", "ISSUE_LABEL", "PARTIAL_LABEL",
    "manual_review_lines", "computed_review_lines", "prepare_fix", "submit_fix_pr",
    "discard_branch", "discard_pr", "discard_remote_branch", "discard_remote_pr",
    "github_api", "gitutil", "remediation",
]
