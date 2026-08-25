#!/usr/bin/env python3
"""Which branch a fix is committed to.

One constant name meant one branch could only ever carry one base's fix, so a second base collided
with the first and an occupied name had no fallback. Names are derived from the base instead; the
generic construction lives in `lib.git.naming`.
"""
from __future__ import annotations

from stayawake.lib.git.naming import choose_branch, ref_safe_segment
from stayawake.bots.security.pr.constants import FIX_BRANCH

LEGACY_FIX_BRANCH = FIX_BRANCH


def fix_branch_for(base: str) -> str:
    """The fix branch for `base`. The separator is `-`, never `/`: refs are paths, so
    `security/auto-clean/<base>` cannot exist wherever `security/auto-clean` already does."""
    return f"{FIX_BRANCH}-{ref_safe_segment(base)}"


def choose_fix_branch(base: str, *, exists, fast_forwardable, limit: int = 20) -> str:
    """The fix branch for `base` that is free to push."""
    return choose_branch(fix_branch_for(base), exists=exists,
                         fast_forwardable=fast_forwardable, limit=limit)
