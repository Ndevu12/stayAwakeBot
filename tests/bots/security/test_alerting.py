#!/usr/bin/env python3
"""Security alerter: issue open/close decision tests.

The alerter is now payload-driven — the `--alert` sinks hand it the in-memory scan
payload directly (no intermediate latest.json on disk).
"""
from __future__ import annotations

import unittest
from unittest import mock


from stayawake.bots.security import alerter                       # noqa: E402

LATEST = {
    "generated_at": "t",
    "summary": {"infected": 1, "findings": 2},
    "results": [
        {"target": "o/infected", "source": "remote", "infected": True, "error": None,
         "summary": {"total": 2, "max_severity": "critical"},
         "findings": [{"severity": "critical", "signature_id": "x", "path": "a"}]},
        {"target": "o/clean", "source": "remote", "infected": False, "error": None,
         "summary": {"total": 0, "max_severity": None}, "findings": []},
    ],
}


class TestAlerter(unittest.TestCase):
    def setUp(self):
        self.calls = []

    def _fake_request(self, path, method="GET", token=None, data=None):
        self.calls.append((method, path))
        if "/search/issues" in path:   # one open issue for the now-clean repo
            return {"items": [{"title": "[SECURITY] worm indicators in o/clean", "number": 7}]}
        return {}

    def test_opens_for_infected_and_closes_for_clean(self):
        with mock.patch("stayawake.bots.security.alerter.github_api.request",
                        side_effect=self._fake_request), \
             mock.patch.dict("os.environ",
                             {"GITHUB_TOKEN": "t", "GITHUB_REPOSITORY": "o/r"}, clear=False):
            alerter.sync_github_issues(LATEST)
        self.assertTrue(any(m == "POST" and p.endswith("/issues") for m, p in self.calls),
                        "should open an issue for the infected repo")
        self.assertTrue(any(m == "PATCH" and p.endswith("/issues/7") for m, p in self.calls),
                        "should close the stale issue for the now-clean repo")


if __name__ == "__main__":
    unittest.main()
