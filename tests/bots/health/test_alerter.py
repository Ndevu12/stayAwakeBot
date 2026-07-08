#!/usr/bin/env python3
"""Health alerter: the single self-updating 'Availability status' issue is the WHOLE store — no
network, no files. The 2/2 debounce is folded incrementally from the issue's own prior state block
(via core.issue_state); transitions raise Slack/title events."""
from __future__ import annotations

import unittest
from unittest import mock

from stayawake.bots.health import alerter
from stayawake.core import issue_state


def _down(reason="HTTP 503 (expected 200)"):
    return [{"name": "A", "url": "https://a", "healthy": False, "reason": reason,
             "status_code": 503, "response_ms": 100}]


def _up():
    return [{"name": "A", "url": "https://a", "healthy": True, "status_code": 200, "response_ms": 90}]


class FoldDebounceTest(unittest.TestCase):
    """The debounce, folded from prior state (what the issue body persists) — no history file."""

    def _kinds(self, *runs):
        state, kinds = {}, []
        for r in runs:
            state, events = alerter._fold(state, r, fail_threshold=2, recovery_threshold=2)
            kinds.append([e["kind"] for e in events])
        return state, kinds

    def test_debounced_both_ways(self):
        state, kinds = self._kinds(_down(), _down(), _up(), _up())
        self.assertEqual(kinds, [[], ["down"], [], ["recovery"]])

    def test_single_blip_never_alerts(self):
        _, kinds = self._kinds(_up(), _down(), _up())
        self.assertEqual(kinds, [[], [], []])          # one fail < threshold → nothing

    def test_state_round_trips_through_issue_body(self):
        state, _ = self._kinds(_down(), _down())
        _, body = alerter._render(state, _down())
        self.assertEqual(issue_state.parse_state(body), state)   # the issue body IS the store
        self.assertTrue(state["services"]["A"]["alerted"])


class PublishTest(unittest.TestCase):
    ENV = {"GITHUB_TOKEN": "t", "GITHUB_REPOSITORY": "o/r", "SLACK_WEBHOOK_URL": "http://hook"}

    def _publish(self, prev_state, results):
        with mock.patch.object(alerter.issue_state, "load", return_value=(None, prev_state)), \
             mock.patch.object(alerter.issue_state, "save") as sv, \
             mock.patch.object(alerter, "send_slack") as slack, \
             mock.patch.dict("os.environ", self.ENV, clear=False):
            alerter.publish(results, {"consecutive_failures_before_alert": 2,
                                      "consecutive_healthy_before_recovery": 2})
        return sv, slack

    def test_refreshes_one_issue_and_slacks_on_down(self):
        prev = {"services": {"A": {"consec_fail": 1, "consec_heal": 0, "alerted": False}}}
        sv, slack = self._publish(prev, _down())      # 2nd consecutive fail → DOWN
        sv.assert_called_once()                        # exactly one issue write (no per-service dupes)
        self.assertEqual(sv.call_args.kwargs["label"], alerter.LABEL)
        self.assertTrue(sv.call_args.kwargs["title"].startswith("🔴"))
        slack.assert_called_once()

    def test_no_slack_below_threshold(self):
        sv, slack = self._publish({}, _down())         # 1st fail only
        sv.assert_called_once()                        # issue still refreshed silently
        slack.assert_not_called()

    def test_no_token_is_a_safe_noop(self):
        with mock.patch.object(alerter.issue_state, "save") as sv, \
             mock.patch.dict("os.environ", {}, clear=True):
            alerter.publish(_down(), {})               # must not raise, must not write
        sv.assert_not_called()


if __name__ == "__main__":
    unittest.main()
