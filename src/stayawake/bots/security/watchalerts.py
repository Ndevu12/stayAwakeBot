#!/usr/bin/env python3
"""When the watcher tells the user something, and what it says: a notification for what matters,
repeated until it is dealt with, and one report a day."""
from __future__ import annotations

from dataclasses import dataclass

from stayawake.bots.security import watchrecord, watchstate
from stayawake.bots.security.watchevents import (
    ENDED, LEFT, NOT_READ, NOT_REMEMBERED, PASS_FAILED, QUIET, RETURNED, SENTENCE_FOR)
from stayawake.bots.security.watchstate import CAME_BACK, DEAL_WITH_IT, NOT_STOPPED
from stayawake.utils import notify

TITLE = "saw"
DAILY_HOUR = 9
URGENT_EVERY_SECONDS = 900
REMIND_EVERY_SECONDS = 3600
INFORM_EVERY_SECONDS = 3600
FAILED_PASSES_BEFORE_TELLING = 10
DAILY = "daily"
_NEW_BODY = {
    CAME_BACK: "Code stopped here before is running again. " + DEAL_WITH_IT,
    NOT_STOPPED: watchstate.LINE_FOR[NOT_STOPPED],
}
_INFORM_BODY = {
    ENDED: SENTENCE_FOR[ENDED] + " Run `saw watch status`.",
    NOT_READ: SENTENCE_FOR[PASS_FAILED],
    NOT_REMEMBERED: SENTENCE_FOR[NOT_REMEMBERED],
}


@dataclass(frozen=True)
class Alert:
    """One thing to tell the user: its body, whether it is urgent, and what it is about."""
    body: str
    urgent: bool
    about: str
    title: str = TITLE


def decide(record: dict, kinds, now: float, today: str, hour: int) -> tuple[dict, list[Alert]]:
    """Count one pass and decide what to tell the user. Takes the watcher's record, the pass's
    event kinds, the time now, today's local date and the local hour. Returns the record with this
    pass counted and the alerts to send, most urgent first; nothing is marked as told until
    `delivered`."""
    rec = _as_of(watchrecord.well_formed(record), now)
    rec.setdefault("epoch", watchrecord.new_epoch())
    rec.setdefault("watching_since", now)
    since = dict(rec.get("since", {}))
    for kind in kinds:
        if kind != QUIET:
            since[kind] = min(since.get(kind, 0) + 1, watchrecord.MOST_COUNT)
    rec["since"] = since
    pending = dict(rec.get("pending", {}))
    failed = NOT_READ in kinds or PASS_FAILED in kinds
    rec["failures"] = min(rec.get("failures", 0) + 1, watchrecord.MOST_COUNT) if failed else 0
    if RETURNED in kinds:
        if rec.get("returns_seen", 0) >= watchrecord.MOST_COUNT:
            rec.update(epoch=watchrecord.new_epoch(), returns_seen=0)
        rec["returns_seen"] = rec.get("returns_seen", 0) + 1
        rec.setdefault("unacknowledged", now)
        pending[CAME_BACK] = True
    if not failed:
        rec["last_good"] = now
        if LEFT in kinds:
            if "not_stopped" not in rec:
                pending[NOT_STOPPED] = True
            rec.setdefault("not_stopped", now)
        else:
            rec.pop("not_stopped", None)
    rec["pending"] = pending

    alerts = []
    urgent = _urgent_due(rec, now)
    if urgent is not None:
        body = _NEW_BODY[urgent] if pending.get(urgent) else watchstate.LINE_FOR[urgent]
        alerts.append(Alert(body, True, urgent))
    if hour >= DAILY_HOUR and rec.get("daily_for") != today:
        alerts.append(daily_report(rec))
    told = rec.get("told", {})
    for kind, due in ((ENDED, ENDED in kinds),
                      (NOT_READ, failed and rec["failures"] >= FAILED_PASSES_BEFORE_TELLING),
                      (NOT_REMEMBERED, NOT_REMEMBERED in kinds)):
        if due and now - told.get(kind, float("-inf")) >= INFORM_EVERY_SECONDS:
            alerts.append(Alert(_INFORM_BODY[kind], False, kind))
    return rec, alerts


def _as_of(rec: dict, now: float) -> dict:
    """Read a record's times against the clock now. Takes the record and the time. Returns it with
    every time of telling dated in the future dropped; a future date never holds an alert back."""
    rec["told"] = {kind: at for kind, at in rec.get("told", {}).items() if at <= now}
    if rec.get("urgent_at", now) > now:
        rec.pop("urgent_at")
    return rec


def _urgent_due(rec: dict, now: float) -> str | None:
    """Choose the urgent alert this pass sends, if any. Takes the record and the time. Returns the
    matter it is about: one that happened and was not yet told first, even if it is over — at once
    unless that kind was told within `URGENT_EVERY_SECONDS`, never held behind another kind; else
    the worst open one due a reminder. Beyond that, at most one every `URGENT_EVERY_SECONDS`, and at
    once after something was dealt with."""
    told = rec.get("told", {})
    pending = [kind for kind in (CAME_BACK, NOT_STOPPED) if rec.get("pending", {}).get(kind)]
    for kind in pending:
        if now - told.get(kind, float("-inf")) >= URGENT_EVERY_SECONDS:
            return kind
    if (now - rec.get("urgent_at", float("-inf")) < URGENT_EVERY_SECONDS
            and not rec.get("window_reopened")):
        return None
    if pending:
        return pending[0]
    open_ = [kind for kind, field in ((CAME_BACK, "unacknowledged"), (NOT_STOPPED, "not_stopped"))
             if field in rec]
    due = [kind for kind in open_
           if now - told.get(kind, float("-inf")) >= REMIND_EVERY_SECONDS]
    return due[0] if due else None


def delivered(record: dict, alerts, now: float, today: str) -> dict:
    """Record the alerts the user was shown. Takes the record from `decide`, the alerts that were
    delivered, the time and today's local date. Returns the record."""
    rec = dict(record)
    told = dict(rec.get("told", {}))
    pending = dict(rec.get("pending", {}))
    for alert in alerts:
        if alert.about == DAILY:
            rec["daily_for"] = today
            rec["since"] = {}
            continue
        told[alert.about] = now
        if alert.urgent:
            rec["urgent_at"] = now
            pending.pop(alert.about, None)
            rec.pop("window_reopened", None)
    rec.update(told=told, pending=pending)
    return rec


def daily_report(record: dict) -> Alert:
    """Build the day's report. Takes the watcher's record. Returns the alert, sent on quiet days
    too, leading with what to do and adding as many facts as fit."""
    said = watchstate.what_happened(record.get("since", {}))
    if "unacknowledged" in record:
        lead = "Daily report: code that came back has not been dealt with. " + DEAL_WITH_IT
    elif "not_stopped" in record:
        lead = "Daily report: " + watchstate.LINE_FOR[NOT_STOPPED]
    elif said:
        lead = "Daily report: run `saw watch status`."
    else:
        return Alert("Daily report: this machine checked itself. " + watchstate.QUIET_DAY,
                     False, DAILY)
    body = lead
    for sentence in said:
        if len(body) + 1 + len(sentence) > notify.TEXT_LIMIT:
            break
        body += " " + sentence
    urgent = "unacknowledged" in record or "not_stopped" in record
    return Alert(body, urgent, DAILY)

