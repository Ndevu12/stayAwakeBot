#!/usr/bin/env python3
"""What one `saw fix amend` run established, as structure — plus the single line it renders to.

The verdict used to be recovered from the sentence the run printed (`"force-updated '" not in
line`), so a reword moved the exit code without anyone touching a decision. Here the decision IS
the structure and prose runs one way only: outcome → line. Nothing reads the line back.

Two conditions leave the payload reachable after every branch has moved, and both are verdicts
rather than footnotes: a tag still pointing at the replaced commit is a published entry point no
branch update touches (one `git clone --branch` puts it back on disk), and no action the origin
owner takes removes an object from a fork. Whether a repository has forks is not knowable without
the network, so *not established* is its own answer — a run that could not look must not read as a
run that looked and found none.

`needs_review` is fail-closed — a reason counts as review unless it is named in
`_NEEDING_NO_ACTION` — so a cause added later flags until someone decides it does not.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Iterable, Sequence

from stayawake.utils import textsafe


class Cause(Enum):
    """One distinct answer about why nothing moved, or what is still reachable now that it has.

    Distinct members, because an operator acts differently on each: a commit shape the tool does
    not model is a gap to report, while a merge that will not resolve cleanly is a conflict to
    resolve by hand. Collapsed into one "could not replace" both read as the tool giving up.
    """

    NOT_A_GIT_REPOSITORY = "not-a-git-repository"
    WORKING_TREE_NOT_CLEAN = "working-tree-not-clean"
    NO_REMOTE = "no-remote"
    NO_CREDENTIAL = "no-credential"
    SCAN_DID_NOT_FINISH = "scan-did-not-finish"
    NO_CONFIRMED_PAYLOAD = "no-confirmed-payload"
    MANY_CONFIRMED_COMMITS = "many-confirmed-commits"
    CONFIRMED_COMMIT_UNRESOLVED = "confirmed-commit-unresolved"
    COMMIT_ON_NO_BRANCH = "commit-on-no-branch"
    REMOTE_BRANCH_UNREADABLE = "remote-branch-unreadable"
    COMMIT_SHAPE_NOT_MODELLED = "commit-shape-not-modelled"
    MERGE_WOULD_NOT_RESOLVE = "merge-would-not-resolve"
    RECONSTRUCTION_UNAVAILABLE = "reconstruction-unavailable"
    REPLAY_FAILED = "replay-failed"
    PUSH_REFUSED = "push-refused"
    NOT_PERMITTED_TO_REWRITE = "not-permitted-to-rewrite"
    REMOTE_REFS_UNREADABLE = "remote-refs-unreadable"
    SIGNING_UNAVAILABLE = "signing-unavailable"
    REPLACEMENT_LOSES_MORE_THAN_THE_PAYLOAD = "replacement-loses-more-than-the-payload"
    CAPTURE_FAILED = "capture-failed"
    REPLAY_CHANGED_UNRELATED_COMMITS = "replay-changed-unrelated-commits"
    LEFT_PART_WAY = "left-part-way"
    BRANCH_PROTECTED = "branch-protected"
    PROTECTION_UNKNOWN = "protection-unknown"
    PUSH_NOT_CONFIRMED = "push-not-confirmed"
    REMOTE_DID_NOT_MOVE = "remote-did-not-move"
    LOCAL_MISSING_REMOTE_COMMITS = "local-missing-remote-commits"
    TAGS_AT_REPLACED_COMMIT = "tags-at-replaced-commit"
    FORKS_EXIST = "forks-exist"
    FORKS_NOT_ESTABLISHED = "forks-not-established"
    PREVIOUS_OBJECTS_UNCOLLECTED = "previous-objects-uncollected"


_NEEDING_NO_ACTION = frozenset({Cause.PREVIOUS_OBJECTS_UNCOLLECTED})


@dataclass(frozen=True)
class Reason:
    """One cause, with the identifier the operator needs to act on it (a branch, a tag, a count)."""

    cause: Cause
    detail: str = ""
    subjects: str = ""
    """The things to go and look at, when `detail` is a count rather than an identifier. A count
    with nothing named is not actionable: "2 confirmed past commits" leaves the operator with
    nowhere to start."""


@dataclass(frozen=True)
class BranchResult:
    """One branch that reached the payload, and whether its remote ref actually moved."""

    name: str
    force_updated: bool
    reason: Reason | None = None


@dataclass(frozen=True)
class AmendOutcome:
    """One repository's run: what moved, what did not, and what is still reachable.

    `completed` describes the act — every branch that reached the payload was force-updated.
    `needs_review` describes the operator's remaining work, which outlives a completed act: a
    reachable tag or an existing fork still carries the payload after every branch has moved.
    """

    repository: str
    completed: bool
    commit: str = ""
    branches: tuple[BranchResult, ...] = ()
    reasons: tuple[Reason, ...] = ()

    def __post_init__(self) -> None:
        if self.completed and not self.branches:
            raise ValueError("completed with no branch force-updated")
        if self.completed and not all(b.force_updated for b in self.branches):
            raise ValueError("completed while a branch was left behind")

    @property
    def needs_review(self) -> bool:
        """Whether a person still has to act. Read from the structure, never from the rendered
        line — that is the defect this type exists to close."""
        return not self.completed or any(r.cause not in _NEEDING_NO_ACTION for r in self.reasons)


def refused(repository: str, cause: Cause, detail: str = "",
            subjects: str = "") -> AmendOutcome:
    """Nothing was force-updated, and this is the one reason why. No ref moved."""
    return AmendOutcome(repository=repository, completed=False,
                        reasons=(Reason(cause, detail, subjects),))


def amended(repository: str, commit: str, branches: Sequence[BranchResult],
            reasons: Iterable[Reason] = ()) -> AmendOutcome:
    """The replacement was pushed at the branches that reached the payload.

    `completed` follows the pushes rather than the caller's word, so a run that left a branch on
    the payload cannot be reported as done.
    """
    acted = tuple(branches)
    if not acted:
        raise ValueError("an amend that touched no branch is a refusal, not an amend")
    return AmendOutcome(repository=repository,
                        completed=all(b.force_updated for b in acted),
                        commit=commit, branches=acted, reasons=tuple(reasons))


_PHRASE = {
    Cause.NOT_A_GIT_REPOSITORY: "not a git repository",
    Cause.WORKING_TREE_NOT_CLEAN: "working tree is not clean; commit or stash first",
    Cause.NO_REMOTE: "no remote",
    Cause.NO_CREDENTIAL: "no credential",
    Cause.NOT_PERMITTED_TO_REWRITE: "this identity may not rewrite here",
    Cause.REMOTE_REFS_UNREADABLE: "the remote branches could not be refreshed",
    Cause.SIGNING_UNAVAILABLE: "this repository signs commits and a signature could not be made",
    Cause.REPLACEMENT_LOSES_MORE_THAN_THE_PAYLOAD:
        "the replacement would drop content the finding does not cover",
    Cause.CAPTURE_FAILED: "the previous commits could not be captured first",
    Cause.REPLAY_CHANGED_UNRELATED_COMMITS: "replaying changed commits it should not have",
    Cause.BRANCH_PROTECTED: "the branch is protected — the amended history is on",
    Cause.PROTECTION_UNKNOWN:
        "the protection rule could not be read — the amended history is on",
    Cause.PUSH_NOT_CONFIRMED:
        "the push was accepted and the remote could not be read back, so this branch may or may "
        "not have moved",
    Cause.REMOTE_DID_NOT_MOVE: "the remote branch did not move",
    Cause.LOCAL_MISSING_REMOTE_COMMITS:
        "this clone does not have everything the remote branch has, so a force-update would "
        "delete commits nothing here has seen",
    Cause.LEFT_PART_WAY:
        "branches were moved and could not be put back — inspect this repository",
    Cause.SCAN_DID_NOT_FINISH: "the scan did not finish",
    Cause.NO_CONFIRMED_PAYLOAD: "no confirmed payload in past commits to replace",
    Cause.MANY_CONFIRMED_COMMITS: "{detail} confirmed past commits",
    Cause.CONFIRMED_COMMIT_UNRESOLVED: "the confirmed commit could not be resolved",
    Cause.COMMIT_ON_NO_BRANCH: "the commit is not on any branch",
    Cause.REMOTE_BRANCH_UNREADABLE: "a remote branch could not be read",
    Cause.COMMIT_SHAPE_NOT_MODELLED: "this commit shape is not modelled",
    Cause.MERGE_WOULD_NOT_RESOLVE: "the merge would not resolve cleanly",
    Cause.RECONSTRUCTION_UNAVAILABLE: "the replacement could not be built",
    Cause.REPLAY_FAILED: "the replay failed; branches left as they stood",
    Cause.PUSH_REFUSED: "the push was refused",
    Cause.TAGS_AT_REPLACED_COMMIT: "tags still point at it",
    Cause.FORKS_EXIST: "forks still carry it",
    Cause.FORKS_NOT_ESTABLISHED: "could not check for forks",
    Cause.PREVIOUS_OBJECTS_UNCOLLECTED: "previous objects remain until collected",
}

_UNNAMED_CAUSE = "the run did not say why"
_NOTHING_MOVED = "nothing was force-updated"
_NOT_FULLY_UPDATED = "the remote was not fully updated"


def _clause(reason: Reason) -> str:
    """One cause as prose. A phrase carrying `{detail}` places the identifier itself — a count
    reads as a count, not as a parenthetical after one."""
    detail = textsafe.plain(reason.detail, 120)
    phrase = _PHRASE.get(reason.cause, _UNNAMED_CAUSE)
    if "{detail}" in phrase:
        phrase, detail = phrase.format(detail=detail), textsafe.plain(reason.subjects, 120)
    return f"{phrase} ({detail})" if detail else phrase


def _quoted(names: Iterable[str]) -> str:
    return ", ".join(f"'{textsafe.plain(name, 60)}'" for name in names)


def render_amend_line(outcome: AmendOutcome) -> str:
    """The one operator line for a run.

    The ONLY place this flow turns structure into prose. Nothing parses the result, so rewording
    it can move no verdict and no exit code. Every attacker-influenced field (repository, branch,
    detail) goes through `textsafe.plain`, so a crafted name cannot break the line or forge a
    workflow command in a CI log.
    """
    repository = textsafe.plain(outcome.repository, 120)
    clauses = [_clause(r) for r in outcome.reasons]
    if not outcome.branches:
        return f"{repository}: {_NOTHING_MOVED}" + (f" — {'; '.join(clauses)}" if clauses else "")
    acts = []
    moved = [b.name for b in outcome.branches if b.force_updated]
    left = [b.name for b in outcome.branches if not b.force_updated]
    if moved:
        acts.append(f"force-updated {_quoted(moved)}")
    if left:
        acts.append(f"{_quoted(left)} {'was' if len(left) == 1 else 'were'} not force-updated")
        clauses = [_clause(b.reason) for b in outcome.branches
                   if not b.force_updated and b.reason is not None] + clauses
    line = f"{repository}: {'; '.join(acts)}"
    if outcome.commit:
        line += f" (commit {textsafe.plain(outcome.commit, 40)})"
    if not outcome.completed:
        clauses.insert(0, _NOT_FULLY_UPDATED)
    return line + (f"; {'; '.join(clauses)}" if clauses else "")
