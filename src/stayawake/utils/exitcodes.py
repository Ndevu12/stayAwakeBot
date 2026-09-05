#!/usr/bin/env python3
"""The exit codes every `saw` command returns.

One definition per code, so a caller reading a number and a command returning one cannot drift.
"""
from __future__ import annotations

# Nothing to act on: the target was examined and came back clean.
CLEAN = 0

# The verdict a gate fails on: at least one confirmed finding.
FINDINGS = 1

# The run happened but could not answer in full — a refused argument, a probe that went blind. A
# report may still have been printed; it is not an all-clear.
INCOMPLETE = 2

# From a host audit: rotating a credential from this machine is unsafe, or could not be shown safe.
ROTATION_UNSAFE = 3

# The command stopped before it could produce any result at all. Distinct from INCOMPLETE, which
# still answered in part.
DID_NOT_RUN = 4
