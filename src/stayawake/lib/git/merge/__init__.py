#!/usr/bin/env python3
"""Evil-merge analysis — enumerate merge candidates and confirm review-evading injection.

Public surface (flat): `merge_commits` (candidates), `evil_merge_paths` (the detector) and
`merge_evidence` (the detector with the payloads each path carries).
Split per concern: candidates · tree (auto-merge baseline) · corroborate · detect."""
from stayawake.lib.git.merge.candidates import merge_commits
from stayawake.lib.git.merge.corroborate import ReadBudget
from stayawake.lib.git.merge.detect import (MergeEvidence, evil_merge_paths, merge_evidence,
                                            clean_merge_blob, borrowed_or_none)

__all__ = ["merge_commits", "evil_merge_paths", "merge_evidence", "MergeEvidence", "ReadBudget",
           "clean_merge_blob", "borrowed_or_none"]
