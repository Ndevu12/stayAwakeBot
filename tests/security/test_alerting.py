#!/usr/bin/env python3
"""Security alerter (issue open/close decision) + security badge tests."""
from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from stayawakebot.security import alerter                       # noqa: E402
from stayawakebot.adapters.badge import update_security_badge   # noqa: E402

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
        self.f = Path(tempfile.mkdtemp()) / "latest.json"
        self.f.write_text(json.dumps(LATEST))
        self.calls = []

    def _fake_request(self, path, method="GET", token=None, data=None):
        self.calls.append((method, path))
        if "/search/issues" in path:   # one open issue for the now-clean repo
            return {"items": [{"title": "[SECURITY] worm indicators in o/clean", "number": 7}]}
        return {}

    def test_opens_for_infected_and_closes_for_clean(self):
        with mock.patch("stayawakebot.security.alerter.github_api.request",
                        side_effect=self._fake_request), \
             mock.patch("stayawakebot.security.alerter.send_slack"), \
             mock.patch.dict("os.environ",
                             {"GITHUB_TOKEN": "t", "GITHUB_REPOSITORY": "o/r"}, clear=False):
            alerter.run(self.f)
        self.assertTrue(any(m == "POST" and p.endswith("/issues") for m, p in self.calls),
                        "should open an issue for the infected repo")
        self.assertTrue(any(m == "PATCH" and p.endswith("/issues/7") for m, p in self.calls),
                        "should close the stale issue for the now-clean repo")


class TestSecurityBadge(unittest.TestCase):
    def test_clean_vs_findings(self):
        p = Path(tempfile.mkdtemp()) / "README.md"
        p.write_text("# T\n")
        update_security_badge(p, infected=0, findings=0)
        self.assertIn("security-clean-brightgreen", p.read_text())
        update_security_badge(p, infected=2, findings=5)
        txt = p.read_text()
        self.assertIn("security-5%20findings-red", txt)
        self.assertNotIn("security-clean", txt)   # replaced, not duplicated


if __name__ == "__main__":
    unittest.main()
