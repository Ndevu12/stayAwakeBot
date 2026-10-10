#!/usr/bin/env python3
"""What the watcher still has open for the user, and what happened since the last report: one
answer read by every way saw tells them."""
from __future__ import annotations

from dataclasses import dataclass

from stayawake.bots.security import watchrecord
from stayawake.bots.security.watchevents import (
    ENDED, LEFT, NOT_READ, NOT_REMEMBERED, PASS_FAILED, RETURNED, UNNAMED)

STALE_AFTER_SECONDS = 600
CAME_BACK, NOT_STOPPED, NOT_CHECKING, NOT_SHOWN = (
    "came-back", "not-stopped", "not-checking", "not-shown")
DEAL_WITH_IT = "Run `saw harden`, then `saw audit` to find what brings it back."
LINE_FOR = {
    CAME_BACK: "Code stopped here before came back and has not been dealt with. " + DEAL_WITH_IT,
    NOT_STOPPED: "Code was running here that could not be stopped. Run `saw harden`.",
    NOT_CHECKING: "This machine has not checked itself recently. Run `saw watch status`.",
    NOT_SHOWN: "Notifications could not be shown on this machine; saw tells you here instead.",
}
URGENT = frozenset({CAME_BACK, NOT_STOPPED, NOT_CHECKING})
QUIET_DAY = "Nothing was running that should not be."


@dataclass(frozen=True)
class Matter:
    """One thing the user still has to know about: what it is, the line that says it, and whether
    every command says it until it is dealt with."""
    kind: str
    line: str
    urgent: bool


def still_open(record: dict, *, now: float, placed: bool,
               placed_since: float | None) -> list[Matter]:
    """Decide what the user still has to know. Takes the watcher's record with any acknowledgement
    applied, the time now, whether the watcher is placed and when. Returns the open matters, most
    urgent first: code that came back and code that could not be stopped stay open until a pass no
    longer sees them or `saw harden` deals with them; a watcher that stopped checking and
    notifications that could not be shown are open only while the watcher is placed."""
    open_ = []
    if "unacknowledged" in record:
        open_.append(CAME_BACK)
    if "not_stopped" in record:
        open_.append(NOT_STOPPED)
    if placed and stale(record, now, placed_since):
        open_.append(NOT_CHECKING)
    if placed and "undelivered" in record:
        open_.append(NOT_SHOWN)
    return [Matter(kind, LINE_FOR[kind], kind in URGENT) for kind in open_]


def stale(record: dict, now: float, placed_since: float | None = None) -> bool:
    """Tell whether the watcher has stopped completing passes. Takes the record, the time now and
    when the watcher was placed, if known. Returns True when the last pass is too old or is dated
    in the future, or when there is none and the placement is too old, dated in the future or not
    known."""
    last = record.get("last_good")
    if not watchrecord.is_time(last):
        return placed_since is None or not 0 <= now - placed_since <= STALE_AFTER_SECONDS
    return not 0 <= now - last <= STALE_AFTER_SECONDS


def what_happened(since: dict) -> list[str]:
    """Say what happened since the last report. Takes the event counts. Returns one sentence per
    kind of event that happened, worst first."""
    said = []
    if since.get(RETURNED):
        said.append(f"Code stopped before came back {_times(since[RETURNED])}.")
    if since.get(LEFT):
        said.append(f"Code could not be stopped {_times(since[LEFT])}.")
    if since.get(ENDED):
        said.append(f"Code running here was stopped {_times(since[ENDED])}.")
    if since.get(UNNAMED):
        said.append("Something ran here that this machine could not identify "
                    f"{_times(since[UNNAMED])}.")
    unchecked = since.get(NOT_READ, 0) + since.get(PASS_FAILED, 0)
    if unchecked:
        said.append(f"This machine could not check itself {_times(unchecked)}.")
    if since.get(NOT_REMEMBERED):
        said.append(f"Its record could not be kept {_times(since[NOT_REMEMBERED])}.")
    return said


def since_heading(record: dict) -> str:
    """Name the period the counts cover. Takes the record. Returns the heading."""
    return "Since the last report:" if record.get("daily_for") else "Since saw started watching:"


def _times(n: int) -> str:
    """Say a count of occurrences. Takes the count. Returns `once` or `N times`."""
    return "once" if n == 1 else f"{n} times"
