#!/usr/bin/env python3
"""The hook events git runs hooks for, as githooks(5) lists them."""
from __future__ import annotations

HOOK_NAMES = frozenset((
    "applypatch-msg pre-applypatch post-applypatch pre-commit pre-merge-commit prepare-commit-msg "
    "commit-msg post-commit pre-rebase post-checkout post-merge pre-push pre-receive update "
    "proc-receive post-receive post-update reference-transaction push-to-checkout pre-auto-gc "
    "post-rewrite sendemail-validate fsmonitor-watchman post-index-change p4-changelist "
    "p4-prepare-changelist p4-post-changelist p4-pre-submit").split())
