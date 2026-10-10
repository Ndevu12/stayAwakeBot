#!/usr/bin/env python3
"""When the watcher tells the user something, and what it says: a notification for what matters,
repeated until it is dealt with, and one report a day."""
from __future__ import annotations

from dataclasses import dataclass

from stayawake.bots.security import watchrecord
from stayawake.bots.security.watchevents import (
    ENDED, LEFT, NOT_READ, NOT_REMEMBERED, PASS_FAILED, QUIET, RETURNED, SENTENCE_FOR)
from stayawake.utils import notify

TITLE = "saw"
DAILY_HOUR = 9
URGENT_EVERY_SECONDS = 900
REMIND_EVERY_SECONDS = 3600
INFORM_EVERY_SECONDS = 3600
FAILED_PASSES_BEFORE_TELLING = 10
SAVE_QUIET_EVERY_SECONDS = 300
REMINDER, DAILY = "reminder", "daily"
_DEAL_WITH_IT = "Take this machine off the network, then run `saw harden`."
_URGENT_BODY = {
    RETURNED: "Code stopped here before is running again. " + _DEAL_WITH_IT,
    LEFT: SENTENCE_FOR[LEFT],
    REMINDER: "Code stopped here before came back and has not been dealt with. " + _DEAL_WITH_IT,
}
_PENDING = {RETURNED: "returned_unsent", LEFT: "left_unsent"}
QUIET_DAY = "Nothing was running that should not be."
_DELIVERED = (notify.SENT, notify.UNCONFIRMED)


@dataclass(frozen=True)
class Alert:
    """One thing to tell the user: its body, whether it is urgent, and what it is about."""
    body: str
    urgent: bool
    about: str
    title: str = TITLE


def decide(record: dict, kinds, now: float, today: str, hour: int) -> tuple[dict, list[Alert]]:
    """Decide what to tell the user after one pass. Takes the watcher's record, the pass's event
    kinds, the time now, today's local date and the local hour. Returns the record with this pass
    counted, and the alerts to send, worst first; nothing is marked as told until `delivered`."""
    rec = _as_of(watchrecord.well_formed(record), now)
    since = dict(rec.get("since", {}))
    for kind in kinds:
        if kind != QUIET:
            since[kind] = min(since.get(kind, 0) + 1, watchrecord.MOST_COUNT)
    rec["since"] = since
    failed = NOT_READ in kinds or PASS_FAILED in kinds
    rec["failures"] = min(rec.get("failures", 0) + 1, watchrecord.MOST_COUNT) if failed else 0
    if not failed:
        rec["last_good"] = now
    if RETURNED in kinds and not rec.get("unacknowledged"):
        rec["unacknowledged"] = now
    for kind, flag in _PENDING.items():
        if kind in kinds:
            rec[flag] = True

    alerts = []
    urgent = _urgent_due(rec, now)
    if urgent is not None:
        alerts.append(Alert(_URGENT_BODY[urgent], True, urgent))
    sent = rec.get("sent", {})
    if ENDED in kinds and now - sent.get(ENDED, float("-inf")) >= INFORM_EVERY_SECONDS:
        alerts.append(Alert(f"{SENTENCE_FOR[ENDED]} {_times(since.get(ENDED, 1))} since the last "
                            "report. Run `saw watch status`.", False, ENDED))
    if (failed and rec["failures"] >= FAILED_PASSES_BEFORE_TELLING
            and now - sent.get(NOT_READ, float("-inf")) >= INFORM_EVERY_SECONDS):
        alerts.append(Alert(SENTENCE_FOR[PASS_FAILED], False, NOT_READ))
    if (NOT_REMEMBERED in kinds
            and now - sent.get(NOT_REMEMBERED, float("-inf")) >= INFORM_EVERY_SECONDS):
        alerts.append(Alert(SENTENCE_FOR[NOT_REMEMBERED], False, NOT_REMEMBERED))
    if hour >= DAILY_HOUR and rec.get("daily_for") != today:
        alerts.append(daily_report(since, rec.get("unacknowledged")))
    return rec, alerts


def _as_of(rec: dict, now: float) -> dict:
    """Read a record's times against the clock now. Takes the record and the time. Returns it with
    any time of sending dated in the future dropped, and a return dated in the future held at now;
    a future date never holds an alert back."""
    rec["sent"] = {kind: at for kind, at in rec.get("sent", {}).items() if at <= now}
    for name in ("reminded", "acknowledged"):
        if rec.get(name, now) > now:
            rec.pop(name)
    if rec.get("unacknowledged", now) > now:
        rec["unacknowledged"] = now
    return rec


def _urgent_due(rec: dict, now: float) -> str | None:
    """Choose the urgent alert this pass sends, if any. Takes the record and the time. Returns
    what it is about: code that came back, code that could not be stopped, or a reminder; at most
    one every `URGENT_EVERY_SECONDS`, and at once after a return was dealt with."""
    last = rec.get("sent", {}).get("urgent", float("-inf"))
    if now - last < URGENT_EVERY_SECONDS and rec.get("acknowledged", float("-inf")) <= last:
        return None
    for kind in (RETURNED, LEFT):
        if rec.get(_PENDING[kind]):
            return kind
    since_told = rec.get("reminded") or rec.get("unacknowledged")
    if rec.get("unacknowledged") and now - since_told >= REMIND_EVERY_SECONDS:
        return REMINDER
    return None


def delivered(record: dict, alerts, now: float, today: str) -> dict:
    """Record the alerts the user was shown. Takes the record from `decide`, the alerts that were
    delivered, the time and today's local date. Returns the record."""
    rec = dict(record)
    sent = dict(rec.get("sent", {}))
    for alert in alerts:
        if alert.urgent and alert.about != DAILY:
            sent["urgent"] = now
            rec["reminded"] = now
            rec.pop(_PENDING.get(alert.about, ""), None)
        elif alert.about == DAILY:
            rec["daily_for"] = today
            rec["since"] = {}
        else:
            sent[alert.about] = now
    rec["sent"] = sent
    return rec


def facts(since: dict) -> list[str]:
    """Say what happened since the last report. Takes the event counts. Returns one sentence per
    kind of event that happened."""
    said = []
    if since.get(RETURNED):
        said.append(f"Code stopped before came back {_times(since[RETURNED])}.")
    if since.get(LEFT):
        said.append(f"Something could not be stopped {_times(since[LEFT])}.")
    if since.get(ENDED):
        said.append(f"Code running here was stopped {_times(since[ENDED])}.")
    unchecked = since.get(NOT_READ, 0) + since.get(PASS_FAILED, 0)
    if unchecked:
        said.append(f"This machine could not check itself {_times(unchecked)}.")
    if since.get(NOT_REMEMBERED):
        said.append(f"Its record could not be kept {_times(since[NOT_REMEMBERED])}.")
    return said


def daily_report(since: dict, unacknowledged) -> Alert:
    """Build the day's report. Takes the event counts since the last report and whether code that
    came back is still not dealt with. Returns the alert, sent on quiet days too, with what to do
    first and as many facts as fit."""
    said = facts(since)
    if unacknowledged:
        lead = "Daily report: code that came back has not been dealt with. " + _DEAL_WITH_IT
    elif said:
        lead = "Daily report: run `saw watch status`."
    else:
        return Alert("Daily report: this machine checked itself since the last report. " + QUIET_DAY,
                     False, DAILY)
    body = lead
    for sentence in said:
        if len(body) + 1 + len(sentence) > notify.TEXT_LIMIT:
            break
        body += " " + sentence
    return Alert(body, bool(unacknowledged), DAILY)


def teller(notifier, *, load, save, clock, local):
    """Build what tells the user after each pass. Takes the notifier, the record's load and save,
    the clock and a function giving the local time. Returns a callable taking a pass's event kinds;
    it raises when the record could not be written, and keeps the record in memory until it can."""
    held = []

    def tell(kinds) -> None:
        now = clock()
        moment = local(now)
        today = f"{moment.tm_year:04d}-{moment.tm_mon:02d}-{moment.tm_mday:02d}"
        record = held[0] if held else _load_or_empty(load)
        updated, alerts = decide(record, kinds, now, today, moment.tm_hour)
        shown = [a for a in alerts if _send(notifier, a) in _DELIVERED]
        updated = delivered(updated, shown, now, today)
        if len(shown) < len(alerts):
            updated.setdefault("undelivered", now)
        elif alerts:
            updated.pop("undelivered", None)
        saved = record.get("saved")
        recently = watchrecord.is_time(saved) and 0 <= now - saved < SAVE_QUIET_EVERY_SECONDS
        if tuple(kinds) == (QUIET,) and not alerts and recently and not held:
            return
        updated["saved"] = now
        held[:] = [] if save(updated) else [updated]
        if held:
            raise OSError("the watcher's record could not be written")
    return tell


def _load_or_empty(load) -> dict:
    """Read the record, never failing. Takes the loader. Returns the record, or an empty one."""
    try:
        return load()
    except Exception:
        return {}


def _send(notifier, alert: Alert) -> str:
    """Send one alert, never failing. Takes the notifier and the alert. Returns the delivery
    state."""
    try:
        return notifier.send(alert.title, alert.body, urgent=alert.urgent).state
    except Exception:
        return notify.FAILED


def _times(n: int) -> str:
    """Say a count of occurrences. Takes the count. Returns `once` or `N times`."""
    return "once" if n == 1 else f"{n} times"
