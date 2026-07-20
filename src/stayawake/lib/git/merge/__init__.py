#!/usr/bin/env python3
"""Evil-merge analysis — enumerate merge candidates and confirm review-evading injection.

Public surface (flat): `merge_commits` (candidates) and `evil_merge_paths` (the detector).
Split per concern: candidates · tree (auto-merge baseline) · corroborate · detect."""
from stayawake.lib.git.merge.candidates import merge_commits
from stayawake.lib.git.merge.detect import evil_merge_paths

__all__ = ["merge_commits", "evil_merge_paths"]
