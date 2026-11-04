#!/usr/bin/env python3
"""Scan the files an incoming update brought in, with the operator's allowlist."""
from __future__ import annotations

from pathlib import Path

from stayawake.bots.security.hook_policy import operator_policy
from stayawake.bots.security.models import ScanReport
from stayawake.bots.security.scanner import scan_target
from stayawake.bots.security.sinks.json_sink import _in_plain_words
from stayawake.bots.security.targets.local import LocalRepoTarget
from stayawake.utils import exitcodes
from stayawake.utils.timeutil import now_iso


def scan_arrived(root: Path, paths: tuple[str, ...], config_path: str | None) -> tuple[dict, int]:
    """Scan `paths` under `root`. Takes the tree, the repo-relative files that arrived, and the
    operator config. Returns the `saw scan --json` document and the status a scan of it uses.
    An empty path list still returns a document for that tree."""
    policy = operator_policy(config_path)
    with LocalRepoTarget(str(root), str(root), policy.opts, include_only=paths) as target:
        result = scan_target(target, policy.signatures, policy.allowlist)
    report = ScanReport(generated_at=now_iso(), results=[result])
    if report.any_infected:
        code = exitcodes.FINDINGS
    elif report.any_error:
        code = exitcodes.INCOMPLETE
    else:
        code = exitcodes.CLEAN
    return _in_plain_words(report.to_payload()), code
