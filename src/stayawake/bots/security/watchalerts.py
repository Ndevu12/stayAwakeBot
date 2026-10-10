#!/usr/bin/env python3
"""When the watcher tells the user something, and what it says: a notification for what matters,
repeated until it is dealt with, and one report a day."""
from __future__ import annotations

from dataclasses import dataclass

from stayawake.bots.security.watch import (
    ENDED, LEFT, NOT_READ, PASS_FAILED, QUIET, RETURNED, SENTENCE_FOR)

TITLE = "saw"
DAILY_HOUR = 9
REMIND_EVERY_SECONDS = 3600
FAILED_PASSES_BEFORE_TELLING = 10
MOST_PER_HOUR = 6
_EVERY_SECONDS = {RETURNED: 900, LEFT: 900, ENDED: 3600, NOT_READ: 3600}
_WORST_FIRST = (RETURNED, LEFT, "reminder", NOT_READ, ENDED)
_DEAL_WITH_IT = "Take this machine off the network, then run `saw harden`."


@dataclass(frozen=True)
class Alert:
    """One thing to tell the user: its body, whether it is urgent, and what it is about."""
    body: str
    urgent: bool
    about: str
    title: str = TITLE


def decide(record: dict, kinds, now: float, today: str, hour: int) -> tuple[dict, list[Alert]]:
    """Decide what to tell the user after one pass. Takes the watcher's record, the pass's event
    kinds, the time now, today's local date and the local hour. Returns the updated record and the
    alerts to send, worst first."""
    rec = dict(record)
    since = dict(rec.get("since") or {})
    sent = dict(rec.get("sent") or {})
    for kind in kinds:
        if kind != QUIET:
            since[kind] = since.get(kind, 0) + 1
    failed = NOT_READ in kinds or PASS_FAILED in kinds
    rec["failures"] = rec.get("failures", 0) + 1 if failed else 0
    if not failed:
        rec["last_good"] = now
    if RETURNED in kinds and not rec.get("unacknowledged"):
        rec["unacknowledged"] = now

    due = []
    for kind in (RETURNED, LEFT, ENDED):
        if kind in kinds and now - sent.get(kind, float("-inf")) >= _EVERY_SECONDS[kind]:
            due.append(kind)
    if (failed and rec["failures"] >= FAILED_PASSES_BEFORE_TELLING
            and now - sent.get(NOT_READ, float("-inf")) >= _EVERY_SECONDS[NOT_READ]):
        due.append(NOT_READ)
    if (rec.get("unacknowledged") and RETURNED not in due
            and now - (rec.get("reminded") or rec["unacknowledged"]) >= REMIND_EVERY_SECONDS):
        due.append("reminder")

    recent = [t for t in rec.get("recent") or [] if now - t < 3600]
    alerts = []
    for about in sorted(due, key=_WORST_FIRST.index):
        if len(recent) >= MOST_PER_HOUR:
            break
        alerts.append(_alert(about, since))
        recent.append(now)
        sent[NOT_READ if about == NOT_READ else about] = now
        if about == "reminder":
            rec["reminded"] = now

    if hour >= DAILY_HOUR and rec.get("daily_for") != today:
        alerts.append(daily_report(since, rec.get("unacknowledged")))
        rec["daily_for"] = today
        since = {}
    rec.update(since=since, sent=sent, recent=recent)
    return rec, alerts


def _alert(about: str, since: dict) -> Alert:
    """Build the alert for one kind of event. Takes the kind and the counts since the last report.
    Returns the alert."""
    if about == RETURNED:
        return Alert("Code stopped here before is running again. " + _DEAL_WITH_IT, True, about)
    if about == "reminder":
        return Alert("Code stopped here before came back and has not been dealt with. "
                     + _DEAL_WITH_IT, True, about)
    if about == LEFT:
        return Alert(SENTENCE_FOR[LEFT], True, about)
    if about == NOT_READ:
        return Alert(SENTENCE_FOR[PASS_FAILED], False, about)
    times = since.get(ENDED, 1)
    return Alert(f"{SENTENCE_FOR[ENDED]} {_times(times)} since the last report. "
                 "Run `saw watch status`.", False, about)


def daily_report(since: dict, unacknowledged) -> Alert:
    """Build the day's report. Takes the event counts since the last report and whether code that
    came back is still not dealt with. Returns the alert, sent on quiet days too."""
    parts = []
    if since.get(ENDED):
        parts.append(f"Code running here was stopped {_times(since[ENDED])}.")
    if since.get(RETURNED):
        parts.append(f"Code stopped before came back {_times(since[RETURNED])}.")
    if since.get(LEFT):
        parts.append(f"Something could not be stopped {_times(since[LEFT])}.")
    unchecked = since.get(NOT_READ, 0) + since.get(PASS_FAILED, 0)
    if unchecked:
        parts.append(f"This machine could not check itself {_times(unchecked)}.")
    if not parts:
        return Alert("Daily report: this machine checked itself since the last report. Nothing was "
                     "running that should not be.", False, "daily")
    tail = _DEAL_WITH_IT if unacknowledged else "Run `saw watch status`."
    return Alert("Daily report: " + " ".join(parts) + " " + tail, bool(unacknowledged), "daily")


SAVE_QUIET_EVERY_SECONDS = 300


def teller(notifier, *, load, save, clock, local):
    """Build what tells the user after each pass. Takes the notifier, the record's load and save,
    the clock and a function giving the local time. Returns a callable taking a pass's event kinds;
    it raises when the record could not be written."""
    def tell(kinds) -> None:
        record = load()
        now = clock()
        moment = local(now)
        updated, alerts = decide(record, kinds, now, f"{moment.tm_year:04d}-{moment.tm_mon:02d}-"
                                 f"{moment.tm_mday:02d}", moment.tm_hour)
        for alert in alerts:
            notifier.send(alert.title, alert.body, urgent=alert.urgent)
        quiet = tuple(kinds) == (QUIET,) and not alerts
        if quiet and now - record.get("saved", float("-inf")) < SAVE_QUIET_EVERY_SECONDS:
            return
        updated["saved"] = now
        if not save(updated):
            raise OSError("the watcher's record could not be written")
    return tell


def _times(n: int) -> str:
    """Say a count of occurrences. Takes the count. Returns `once` or `N times`."""
    return "once" if n == 1 else f"{n} times"
