#!/usr/bin/env python3
"""The notice an assertion carries when its result depends on the machine the suite runs on."""
from __future__ import annotations

READS_THE_REAL_HOST = (
    "This test's result depends on the machine it runs on. Probes this test does not substitute "
    "read the real host, so a finding present on this machine and absent on a clean runner makes "
    "it fail. Before treating this as a regression, run the same test against origin/main in a "
    "throwaway worktree."
)
