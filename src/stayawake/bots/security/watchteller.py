#!/usr/bin/env python3
"""Telling the user after each pass: read the record, apply `saw harden`'s acknowledgement, decide,
send what fits, and keep the record."""
from __future__ import annotations

from stayawake.bots.security import watchack, watchalerts, watchrecord
from stayawake.bots.security.watchevents import QUIET
from stayawake.utils import notify

SAVE_QUIET_EVERY_SECONDS = 300
MOST_SENT_PER_PASS = 2
FIRST_BACKOFF_SECONDS = 60
LONGEST_BACKOFF_SECONDS = 3600
_DELIVERED = (notify.SENT, notify.UNCONFIRMED)


def teller(notifier, *, load, save, clock, local, acknowledged=lambda: None):
    """Build what tells the user after each pass. Takes the notifier, the record's load and save,
    the clock, a function giving the local time, and one reading `saw harden`'s acknowledgement.
    Returns a callable taking a pass's event kinds; it raises when the record could not be
    written, and keeps the record in memory until it can."""
    held = []

    def tell(kinds) -> None:
        now = clock()
        moment = local(now)
        today = f"{moment.tm_year:04d}-{moment.tm_mon:02d}-{moment.tm_mday:02d}"
        record = watchack.settled(held[0] if held else _read_or(load, {}),
                                  _read_or(acknowledged, None))
        updated, alerts = watchalerts.decide(record, kinds, now, today, moment.tm_hour)
        shown, failed = send_some(notifier, updated, alerts, now)
        updated = watchalerts.delivered(updated, shown, now, today)
        if failed:
            updated.setdefault("undelivered", now)
        elif shown:
            updated.pop("undelivered", None)
        saved = record.get("saved")
        recently = watchrecord.is_time(saved) and 0 <= now - saved < SAVE_QUIET_EVERY_SECONDS
        counting = record.get("failures", 0) != updated.get("failures", 0)
        if tuple(kinds) == (QUIET,) and not alerts and recently and not held and not counting:
            return
        updated["saved"] = now
        held[:] = [] if save(updated) else [updated]
        if held:
            raise OSError("the watcher's record could not be written")
    return tell


def send_some(notifier, record: dict, alerts, now: float) -> tuple[list, bool]:
    """Send up to `MOST_SENT_PER_PASS` alerts, pausing sending after a failure. Takes the
    notifier, the record (its pause is updated in place), the alerts and the time. Returns the
    alerts shown and whether any could not be."""
    if not alerts:
        return [], False
    if _paused(record, now, urgent=any(alert.urgent for alert in alerts)):
        return [], True
    shown = []
    for alert in alerts[:MOST_SENT_PER_PASS]:
        if _send(notifier, alert) not in _DELIVERED:
            pause = min(max(2 * record.get("backoff", 0), FIRST_BACKOFF_SECONDS),
                        LONGEST_BACKOFF_SECONDS)
            record.update(backoff=pause, backoff_until=now + pause)
            return shown, True
        shown.append(alert)
    record.pop("backoff", None)
    record.pop("backoff_until", None)
    return shown, False


def _paused(record: dict, now: float, *, urgent: bool) -> bool:
    """Tell whether sending is paused after a failure. Takes the record, the time and whether an
    urgent alert is waiting. Returns True within the pause; an urgent alert waits no longer than
    `watchalerts.URGENT_EVERY_SECONDS` after the failure, and a pause longer than the longest
    allowed, or a failure dated in the future, is ignored."""
    pause, until = record.get("backoff", 0), record.get("backoff_until", now)
    if not 0 < until - now <= LONGEST_BACKOFF_SECONDS:
        return False
    failed_at = until - pause
    longest = min(pause, watchalerts.URGENT_EVERY_SECONDS) if urgent else pause
    return 0 <= now - failed_at < longest


def _read_or(read, fallback):
    """Read something, never failing. Takes the reader and what to return when it fails. Returns
    what it read, or the fallback."""
    try:
        return read()
    except Exception:
        return fallback


def _send(notifier, alert) -> str:
    """Send one alert, never failing. Takes the notifier and the alert. Returns the delivery
    state."""
    try:
        return notifier.send(alert.title, alert.body, urgent=alert.urgent).state
    except Exception:
        return notify.FAILED
