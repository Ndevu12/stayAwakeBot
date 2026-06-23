#!/usr/bin/env python3
"""Git-history matcher — the evil-merge detector."""
from __future__ import annotations

from stayawake.core import git as gitutil
from stayawake.bots.security.models import Finding, Severity
from stayawake.bots.security.matchers.base import Matcher


class GitHistoryMatcher(Matcher):
    handles = "git-history"

    def scan(self, target, signatures):
        sig = next((s for s in signatures if s.get("kind") == "evil-merge"), None)
        if not sig or not gitutil.is_git_repo(target.repo_root):
            return []
        findings: list[Finding] = []
        for sha in gitutil.merge_commits(target.repo_root):
            evil = gitutil.evil_merge_paths(target.repo_root, sha)
            if evil:
                meta = gitutil.commit_meta(target.repo_root, sha)
                findings.append(Finding(
                    signature_id=sig["id"], category=sig["category"],
                    severity=Severity.parse(sig["severity"]), path=sha[:10],
                    description=sig["description"], remediation=sig.get("remediation", "manual"),
                    evidence=f"{len(evil)} path(s) in neither parent; e.g. {sorted(evil)[:3]}; "
                             f"by {meta.get('author_email','?')}", vector="evil-merge"))
        return findings
