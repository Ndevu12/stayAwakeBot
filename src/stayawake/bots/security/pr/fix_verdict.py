#!/usr/bin/env python3
"""What one `saw fix` run established for one repository, as structure, and the lines it renders to.

`FixVerdict.grade` is read from the base-branch fix, the checkout and the history.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from stayawake.utils import textsafe


class Checkout(Enum):
    """What became of the checkout the operator is standing in."""

    CLEAN = "clean"
    CLEANED = "cleaned"
    NOT_CLEAN = "not-clean"
    UNREAD = "unread"


class Remedy(Enum):
    """What removes a confirmed file from a place in the history."""

    FIX_PR = "fix-pr"
    AMEND = "amend"
    NAMED_ONLY = "named-only"


class Grade(Enum):
    """The operator's remaining work for one repository."""

    DONE = "done"
    HISTORY_REMAINS = "history-remains"
    NEEDS_REVIEW = "needs-review"


class BaseState(Enum):
    """What the fix prepared against the base branch came to."""

    NOTHING_TO_FIX = "nothing-to-fix"
    SUSPICIOUS_ONLY = "suspicious-only"
    PREPARED = "prepared"
    PR_OPENED = "pr-opened"
    PARTIAL = "partial"
    MANUAL = "manual"
    ABORTED = "aborted"
    PR_FAILED = "pr-failed"


_SETTLED = frozenset({BaseState.NOTHING_TO_FIX, BaseState.SUSPICIOUS_ONLY,
                      BaseState.PREPARED, BaseState.PR_OPENED})
_BRANCH_MADE = frozenset({BaseState.PREPARED, BaseState.PR_OPENED, BaseState.PARTIAL,
                          BaseState.PR_FAILED})


@dataclass(frozen=True)
class BaseFix:
    """The fix prepared against the base branch.

    `summary` is the operator's account of it, led by the repository. `branch` is set when a fix
    branch was made, `pull_request` when a pull request holds it, and `published` when the run was
    asked to open one.
    """

    state: BaseState
    summary: str
    base: str = ""
    branch: str = ""
    pull_request: int | None = None
    published: bool = False


@dataclass(frozen=True)
class CheckoutDetail:
    """The counts and names the checkout line is rendered from."""

    removed: int = 0
    stripped: int = 0
    still_in: tuple[str, ...] = ()
    unread: tuple[str, ...] = ()
    reasons: tuple[str, ...] = ()
    notes: tuple[str, ...] = ()


@dataclass(frozen=True)
class HistoryHold:
    """One place in the history that still stores a confirmed file.

    `where` is "head", "branch" or "stash"; `name` names the branch or stash entry. `on_remote` is
    True when a remote branch also reaches the commit.
    """

    where: str
    name: str
    paths: tuple[str, ...]
    remedy: Remedy
    on_remote: bool = False


@dataclass(frozen=True)
class History:
    """What the history still stores at the paths the run cleared from the checkout.

    `unread` names why git could not answer, "" when it could.
    """

    holds: tuple[HistoryHold, ...] = ()
    unread: str = ""


@dataclass(frozen=True)
class Arrivals:
    """The files added in the same commit as a confirmed payload, with no finding of their own.

    `files` are the operator's to decide; `first_commits` are first commits that carry a payload
    beside other files; `unread` names what git could not read; `unread_records` are earlier lists of
    files to decide, or earlier answers, that could not be read. `take_out` are the versions the
    operator chose to take out, as `(path, blob, ids of the commits that added it)`;
    `taken_out_held` are the places that still store one;
    `not_saved` is True when this run's answers could not be kept.
    """

    files: tuple[str, ...] = ()
    first_commits: tuple[str, ...] = ()
    unread: tuple[str, ...] = ()
    unread_records: tuple[str, ...] = ()
    take_out: tuple[tuple[str, str, tuple[str, ...]], ...] = ()
    taken_out_held: tuple[HistoryHold, ...] = ()
    not_saved: bool = False

    @property
    def undecided(self) -> bool:
        """Tell whether anything is left for the operator. Returns the answer."""
        return bool(self.files or self.first_commits or self.unread or self.unread_records
                    or self.not_saved)


@dataclass(frozen=True)
class FixVerdict:
    """One repository's `saw fix` run."""

    repository: str
    base_fix: BaseFix
    checkout: Checkout
    history: History = History()
    checkout_detail: CheckoutDetail = CheckoutDetail()
    arrivals: Arrivals = Arrivals()

    @property
    def grade(self) -> Grade:
        """Grade the remaining work, anything not known to be settled needing review. Returns the
        grade."""
        if (self.checkout not in (Checkout.CLEAN, Checkout.CLEANED) or self.history.unread
                or self.arrivals.undecided
                or not isinstance(self.base_fix, BaseFix) or self.base_fix.state not in _SETTLED):
            return Grade.NEEDS_REVIEW
        if self.history.holds or self.arrivals.taken_out_held:
            return Grade.HISTORY_REMAINS
        return Grade.DONE

    @property
    def needs_review(self) -> bool:
        """Whether a person still has to look at this repository."""
        return self.grade is Grade.NEEDS_REVIEW


def checkout_of(result) -> tuple[Checkout, CheckoutDetail]:
    """Grade what a run did to the checkout. Takes the checkout pass's result. Returns the state and
    the counts and names its line is rendered from."""
    removed = result.removed
    staged = list(result.staged)
    reasons = [r for r in (result.failure,) if r]
    if staged:
        reasons.append(f"{len(staged)} of them are staged")
    notes = []
    if result.report is not None and result.report.note():
        notes.append(result.report.note())
    kept = result.kept.note()
    if kept:
        (reasons if result.kept.blocked else notes).append(kept)
    if getattr(result, "unstaged", None):
        notes.append(f"took {len(result.unstaged)} confirmed file(s) out of your staged changes")
    if result.index_unread:
        notes.append(f"git could not say what its index holds ({result.index_unread})")
    detail = CheckoutDetail(removed=len(removed.removed), stripped=len(removed.stripped),
                            still_in=tuple(result.still_in), unread=tuple(removed.unread),
                            reasons=tuple(reasons), notes=tuple(notes))
    if result.unread:
        return Checkout.UNREAD, detail
    if result.still_in or result.failure or result.kept.blocked or result.not_removed:
        return Checkout.NOT_CLEAN, detail
    return (Checkout.CLEANED if result.infected else Checkout.CLEAN), detail


_INDENT = "    "
_HOLD_INDENT = "      "


def _paths(paths) -> str:
    return ", ".join(textsafe.plain(p, 200) for p in paths)


def _checkout_line(verdict: FixVerdict, detail: bool) -> str:
    """Say what the run did to the checkout. Takes the verdict and whether paths may be named.
    Returns the line."""
    if verdict.arrivals.undecided and verdict.checkout is Checkout.CLEAN:
        return "your checkout has no confirmed finding left"
    if verdict.arrivals.undecided and verdict.checkout is Checkout.CLEANED:
        found = verdict.checkout_detail
        line = f"removed {found.removed} confirmed file(s) from your checkout"
        if found.stripped:
            line += f" and took what was found out of {found.stripped} more"
        return line + ("; your history still carries it:" if verdict.history.holds
                       else "; no confirmed finding is left in it")
    return checkout_sentence(verdict.checkout, verdict.checkout_detail,
                             history_follows=bool(verdict.history.holds), detail=detail)


def checkout_clauses(state: Checkout, found: CheckoutDetail) -> list[str]:
    """What a checkout pass did, as clauses for a one-line report: its sentence, then its notes;
    nothing when the checkout was already clean and nothing was noted. Takes the state and the
    detail `checkout_of` gave."""
    if state is Checkout.CLEAN and not found.notes:
        return []
    return [checkout_sentence(state, found), *found.notes]


def checkout_sentence(state: Checkout, found: CheckoutDetail, *, history_follows: bool = False,
                      detail: bool = True) -> str:
    """The sentence that says what a checkout pass came to. Takes the state, the detail, whether a
    line about the history follows it, and whether to name paths. Returns the sentence."""
    if state is Checkout.UNREAD:
        line = "your checkout was not read in full, so it is not called clean"
        if detail and found.unread:
            line += f": {_paths(found.unread)}"
        return line
    if state is Checkout.NOT_CLEAN:
        parts = []
        if found.still_in:
            head = (f"your checkout is not clean — {len(found.still_in)} confirmed file(s) are "
                    "still in it")
            parts.append(f"{head}: {_paths(found.still_in)}" if detail else head)
        else:
            parts.append("your checkout is not clean")
        return "; ".join(parts + [textsafe.plain(r, 300) for r in found.reasons])
    if state is Checkout.CLEANED:
        if history_follows:
            return "your checkout is cleaned; your history still carries it:"
        line = f"your checkout is cleaned — removed {found.removed} file(s)"
        if found.stripped:
            line += f"; took what was found out of {found.stripped} more"
        return line
    return "your checkout is clean"


def _fix_pr_tail(fix: BaseFix, it: str = "it") -> str:
    """Say what the base fix does about a commit the base branch holds. Takes the base fix and the
    word for what it stores. Returns the clause, or "" when there is nothing to say."""
    base = f"'{textsafe.plain(fix.base, 120)}'"
    if fix.pull_request is not None:
        return f" — pull request #{fix.pull_request} removes {it} from {base}"
    if fix.state in _BRANCH_MADE and fix.branch:
        tail = f" — '{textsafe.plain(fix.branch, 120)}' removes {it} from {base} once merged"
        return tail if fix.published else tail + "; saw fix --pr opens the pull request"
    if fix.state in (BaseState.NOTHING_TO_FIX, BaseState.SUSPICIOUS_ONLY):
        carries = "carries it" if it == "it" else f"holds {it}"
        return f" — {base} no longer {carries}; update from {base}"
    return ""


def _hold_line(hold: HistoryHold, fix: BaseFix, it: str = "it") -> str:
    """Say where one place still stores what was found and what removes it. Takes the hold, the
    base fix and the word for what it stores. Returns the line."""
    name = textsafe.plain(hold.name, 120)
    carries = "carries it" if it == "it" else f"holds {it}"
    if hold.remedy is Remedy.NAMED_ONLY:
        return f"stash entry {name} {carries}"
    if hold.remedy is Remedy.FIX_PR:
        subject = ("the commit you are on" if hold.where == "head" else f"branch '{name}'")
        return (f"{subject} is also on '{textsafe.plain(fix.base, 120)}'" + _fix_pr_tail(fix, it))
    if hold.where == "head":
        where = ("is not on '" + textsafe.plain(fix.base, 120) + "'" if hold.on_remote
                 else "is only on this machine")
        return f"the commit you are on {where} — saw fix amend removes {it} from your commits"
    return f"branch '{name}' {carries} — saw fix amend removes {it}"


def _taken_out_lines(found: Arrivals, fix: BaseFix, detail: bool) -> list[str]:
    """Say where the files the operator chose to take out are still stored. Takes the arrivals, the
    base fix and whether paths may be named. Returns the lines."""
    if not found.taken_out_held:
        return []
    lines = [_INDENT + "files you chose to take out are still stored:"]
    for hold in found.taken_out_held:
        line = _HOLD_INDENT + _hold_line(hold, fix, "them")
        lines.append(f"{line} ({_paths(hold.paths)})" if detail else line)
    return lines


def _arrival_lines(found: Arrivals, detail: bool) -> list[str]:
    """Say what is left to the operator about files added beside a payload. Takes the arrivals and
    whether paths may be named. Returns the lines."""
    lines = []
    if found.files:
        line = (f"{len(found.files)} file(s) added in the same commit as the malware have no "
                "finding of their own and are your decision — run saw fix in this repository, "
                "on a terminal, to decide them")
        lines.append(f"{line} ({_paths(found.files)})" if detail else line)
    if found.first_commits:
        lines.append("the malware is in this repository's first commit — review that commit's "
                     "other files yourself")
    if found.unread_records:
        line = ("an earlier list of files for you to decide could not be read — review the commits "
                "that brought the malware yourself, then delete it")
        lines.append(f"{line} ({_paths(found.unread_records)})" if detail else line)
    if found.not_saved:
        lines.append("your answers about those files could not be saved — you will be asked again")
    if found.unread:
        lines.append("git could not read what else was added with the malware — check the "
                     "repository with `git fsck`, then run this again")
    return lines


def render_fix_verdict(verdict: FixVerdict, detail: bool = False) -> str:
    """Render the operator's account of one repository's run. Takes the verdict and whether paths
    may be named. Returns the text."""
    lines = [verdict.base_fix.summary, _INDENT + _checkout_line(verdict, detail)]
    lines += [_INDENT + textsafe.plain(n, 300) for n in verdict.checkout_detail.notes]
    if verdict.history.holds:
        if verdict.checkout is not Checkout.CLEANED:
            lines.append(_INDENT + "your history still carries it:")
        for hold in verdict.history.holds:
            line = _HOLD_INDENT + _hold_line(hold, verdict.base_fix)
            lines.append(f"{line} ({_paths(hold.paths)})" if detail else line)
    if verdict.history.unread:
        lines.append(_INDENT + "git could not say what your history holds, so it is not called "
                     "clean")
    lines += _taken_out_lines(verdict.arrivals, verdict.base_fix, detail)
    lines += [_INDENT + line for line in _arrival_lines(verdict.arrivals, detail)]
    return "\n".join(lines)
