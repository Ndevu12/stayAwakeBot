#!/usr/bin/env python3
"""Apply the remediation plan to the checkout the operator is standing in."""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from stayawake.bots.security.models import CONFIRMED
from stayawake.bots.security.remediation import changes as ch, installed, preserve
from stayawake.bots.security.remediation.oracle import (ABSENT, REFUSED, UNREADABLE,
                                                        still_condemned)


@dataclass
class LiveResult:
    """What a run did to the live checkout."""

    removed: list[str] = field(default_factory=list)
    stripped: list[str] = field(default_factory=list)
    absent: list[str] = field(default_factory=list)
    unread: list[str] = field(default_factory=list)
    refused: list[str] = field(default_factory=list)

    @property
    def named(self) -> list[str]:
        """Every path the plan condemned, whatever became of it."""
        return self.removed + self.stripped + self.absent + self.unread + self.refused

    @property
    def unfinished(self) -> list[str]:
        """The paths still to account for."""
        return self.unread + self.refused

    @property
    def complete(self) -> bool:
        """Whether every condemned path was accounted for."""
        return not self.unfinished

    def note(self, detail: bool = False) -> str:
        """Describe what happened in the checkout. Takes whether paths may be named."""
        parts = []
        if self.removed:
            parts.append(f"removed {len(self.removed)} file(s) from your checkout")
        if self.stripped:
            parts.append(f"took what was found out of {len(self.stripped)} more")
        if self.unfinished:
            head = f"{len(self.unfinished)} still to deal with — your checkout is not clean"
            parts.append(f"{head}: {', '.join(self.unfinished)}" if detail else head)
        return "; ".join(parts)


def clean(root: Path, findings, signatures, allowlist, opts) -> LiveResult:
    """Remove from `root` what the findings condemn.

    Takes the checkout, the findings, the by-matcher signatures, the allowlist and the scan
    options. Returns what was removed and what was not.
    """
    plan = ch.plan(findings)
    if not plan:
        return LiveResult()
    result = LiveResult()
    bucket = {ABSENT: result.absent, UNREADABLE: result.unread, REFUSED: result.refused}

    def skipped(path: str, reason: str) -> None:
        bucket.get(reason, result.unread).append(path)

    applied = ch.apply(root, plan, None,
                       condemned=still_condemned(root, signatures, allowlist, opts),
                       on_skip=skipped)
    for change in applied:
        if change.action == "remove":
            result.removed.append(change.path)
        else:
            result.stripped.append(change.path)
    return result


@dataclass
class CheckoutResult:
    """What a run found in the operator's checkout and what it did about it."""

    confirmed: int = 0
    left_alone: list[str] = field(default_factory=list)
    report: object = None
    removed: LiveResult = field(default_factory=LiveResult)
    kept: preserve.Preserved = field(default_factory=preserve.Preserved)
    scan_error: str = ""
    failure: str = ""

    @property
    def infected(self) -> bool:
        """Whether the checkout carried a confirmed payload."""
        return self.confirmed > 0

    @property
    def complete(self) -> bool:
        """Whether the checkout can be called clean."""
        return (self.removed.complete and not self.left_alone and not self.scan_error
                and not self.failure and not self.kept.blocked)

    def note(self, detail: bool = False) -> str:
        """Describe the whole pass, for the operator. Takes whether paths may be named."""
        parts = [self.scan_error, self.failure,
                 self.report.note() if self.report is not None else "",
                 self.removed.note(detail), self._left_note(detail), self.kept.note()]
        return "; ".join(p for p in parts if p)

    def _left_note(self, detail: bool) -> str:
        """What the run confirmed and did not clear. Takes whether paths may be named."""
        if not self.left_alone:
            return ""
        head = (f"{len(self.left_alone)} confirmed file(s) are still in your checkout — "
                "your checkout is not clean")
        return f"{head}: {', '.join(self.left_alone)}" if detail else head


def clean_checkout(repo: Path, opts, signatures, allowlist, *, scan=None, keep=(),
                   lockfile_root: Path | None = None, committed=None,
                   remove_lockfiles: bool = True) -> CheckoutResult:
    """Scan the checkout the operator is standing in and clear what it confirms.

    Takes the checkout, the scan options, the by-matcher signatures, the allowlist, the scan to
    run, the directory names to keep, the tree the lockfiles are read from,
    `committed(path) -> list[str]` and whether the lockfile goes. Returns what was found and what
    was done, the operator's own uncommitted work put on a branch of its own.
    """
    from stayawake.bots.security.targets import LocalRepoTarget
    if scan is None:
        from stayawake.bots.security.scanner import scan_target
        scan = scan_target
    read = scan(LocalRepoTarget(repo, str(repo), opts), signatures, allowlist)
    if read.error:
        return CheckoutResult(scan_error="your checkout was not read in full, so it is not clean")
    findings = [f for f in read.findings if getattr(f, "confidence", None) == CONFIRMED]
    if not findings:
        return CheckoutResult()
    theirs = preserve.uncommitted(repo)
    report, failure = None, ""
    try:
        report = installed.remove_installed(repo, confirmed=True, keep=keep,
                                            remove_lockfiles=remove_lockfiles,
                                            lockfile_root=lockfile_root, committed=committed)
    except OSError as exc:
        failure = f"could not remove the installed tree ({exc})"
    removed = clean(repo, findings, signatures, allowlist, opts)
    named = sorted({f.path for f in findings} | set(removed.named))
    verdict = still_condemned(repo, signatures, allowlist, opts)
    present = [p for p in named if verdict(p) != ABSENT]
    kept = preserve.preserve(repo, theirs, condemned=present)
    dealt = set(removed.removed) | set(removed.stripped) | set(removed.absent)
    return CheckoutResult(confirmed=len(findings), report=report, removed=removed,
                          left_alone=[p for p in named if p not in dealt],
                          kept=kept, failure=failure)

