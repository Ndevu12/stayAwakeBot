#!/usr/bin/env python3
"""Health alerter: single self-updating issue per project — no network."""
from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from stayawake.bots.health import alerter   # noqa: E402

SETTINGS = {"settings": {"consecutive_failures_before_alert": 2,
                         "consecutive_healthy_before_recovery": 2}}


def _down(at, reason="HTTP 503 (expected 200)"):
    return {"name": "A", "url": "https://a", "healthy": False, "reason": reason,
            "status_code": 503, "response_ms": 100, "dns_ms": 12, "checked_at": at}


def _up(at):
    return {"name": "A", "url": "https://a", "healthy": True, "reason": None,
            "status_code": 200, "response_ms": 90, "dns_ms": 12, "checked_at": at}


def _hist(*runs):
    return [{"generated_at": f"t{i}", "urls": [u]} for i, u in enumerate(runs)]


class _Spy:
    """Records github_api calls; configurable existing-issue lookup."""

    def __init__(self, existing=None):
        self.existing = existing
        self.created = []
        self.updated = []
        self.comments = []

    def find_issue_by_marker(self, owner, repo, marker, token, labels=None):
        return self.existing

    def create_issue(self, owner, repo, title, body, token, labels=None):
        self.created.append({"title": title, "body": body})
        return {"number": 99}

    def update_issue(self, owner, repo, number, token, title=None, body=None, state=None):
        self.updated.append({"number": number, "title": title, "body": body, "state": state})
        return {"number": number}

    def add_issue_comment(self, owner, repo, number, body, token):
        self.comments.append({"number": number, "body": body})
        return {"id": 1}


class AlerterTest(unittest.TestCase):
    def setUp(self):
        d = Path(tempfile.mkdtemp())
        self.latest = d / "latest.json"
        self.history = d / "history.json"
        self.latest.write_text(json.dumps({"generated_at": "t", "results": []}))

    def _run(self, history, existing=None):
        self.history.write_text(json.dumps(history))
        spy = _Spy(existing=existing)
        with mock.patch.multiple(
                "stayawake.bots.health.alerter.github_api",
                find_issue_by_marker=spy.find_issue_by_marker,
                create_issue=spy.create_issue,
                update_issue=spy.update_issue,
                add_issue_comment=spy.add_issue_comment), \
             mock.patch("stayawake.bots.health.alerter.load_yaml", return_value=SETTINGS), \
             mock.patch("stayawake.bots.health.alerter.send_slack"), \
             mock.patch.dict("os.environ",
                             {"GITHUB_TOKEN": "t", "GITHUB_REPOSITORY": "o/r"}, clear=False):
            alerter.run(self.latest, self.history)
        return spy

    def test_creates_one_issue_when_down_and_none_exists(self):
        spy = self._run(_hist(_down("t1"), _down("t2")), existing=None)
        self.assertEqual(len(spy.created), 1, "should open exactly one issue")
        self.assertEqual(spy.updated, [])
        body = spy.created[0]["body"]
        self.assertIn("stayawakebot-sentinel:a", body)             # stable marker
        self.assertIn("HTTP 503 (expected 200)", body)             # failing dimension surfaced

    def test_updates_existing_issue_instead_of_duplicating(self):
        spy = self._run(_hist(_down("t1"), _down("t2")), existing={"number": 5})
        self.assertEqual(spy.created, [], "must NOT open a second issue")
        self.assertEqual(len(spy.updated), 1)
        self.assertEqual(spy.updated[0]["number"], 5)
        self.assertIsNone(spy.updated[0]["state"])                 # silent body refresh, not closed

    def test_below_failure_threshold_does_nothing(self):
        spy = self._run(_hist(_up("t0"), _down("t1")), existing=None)   # only 1 consecutive fail
        self.assertEqual(spy.created, [])
        self.assertEqual(spy.updated, [])

    def test_recovery_comments_and_closes_after_debounce(self):
        spy = self._run(_hist(_down("t0"), _down("t1"), _up("t2"), _up("t3")),
                        existing={"number": 5})
        self.assertEqual(len(spy.comments), 1, "should post one recovery comment")
        self.assertIn("Recovered", spy.comments[0]["body"])
        self.assertTrue(any(u["state"] == "closed" for u in spy.updated),
                        "should close the issue on recovery")

    def test_recovery_within_debounce_does_not_close(self):
        spy = self._run(_hist(_down("t0"), _down("t1"), _up("t2")), existing={"number": 5})
        self.assertEqual(spy.comments, [], "one healthy check is within the debounce window")
        self.assertEqual(spy.updated, [])


if __name__ == "__main__":
    unittest.main()
