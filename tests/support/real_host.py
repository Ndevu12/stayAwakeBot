#!/usr/bin/env python3
"""The notice an assertion carries when its result depends on the machine the suite runs on, and
stand-ins for the audit's probes for tests about how their outcomes are graded."""
from __future__ import annotations

from stayawake.bots.security import hygiene


def probes_that_find_nothing(findings=None, called=None):
    """Return every registered audit probe with its check replaced by a stand-in.

    `findings` maps a probe label to the issues its stand-in returns (default: none). `called`, when
    given, is a list each stand-in appends its label to when it runs."""
    findings = findings or {}

    def stand_in(label):
        def check():
            if called is not None:
                called.append(label)
            return list(findings.get(label, []))
        return check

    return [(label, stand_in(label)) for label, _check in hygiene.audit_checks()]


READS_THE_REAL_HOST = (
    "This test's result depends on the machine it runs on. Probes this test does not substitute "
    "read the real host, so a finding present on this machine and absent on a clean runner makes "
    "it fail. Before treating this as a regression, run the same test against origin/main in a "
    "throwaway worktree."
)
