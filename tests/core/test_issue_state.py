#!/usr/bin/env python3
"""core.issue_state — the reusable 'GitHub issue as a durable, file-less state store'. No network."""
from __future__ import annotations

import unittest
from unittest import mock

from stayawake.core import issue_state as ist


class TestStateBlock(unittest.TestCase):
    def test_round_trips_inside_a_human_body(self):
        state = {"services": {"svc": {"consec_fail": 2, "alerted": True}}}
        body = f"## Dashboard\n| a | b |\n\n{ist.state_comment(state)}"
        self.assertEqual(ist.parse_state(body), state)

    def test_absent_or_corrupt_block_is_empty_not_a_crash(self):
        self.assertEqual(ist.parse_state("no block here"), {})
        self.assertEqual(ist.parse_state("<!-- state:{bad -->"), {})   # malformed → {}
        self.assertEqual(ist.parse_state("<!-- state:[1,2] -->"), {})  # non-object → {}
        self.assertEqual(ist.parse_state(None), {})


class TestLoadSave(unittest.TestCase):
    def test_load_returns_lowest_numbered_match_and_its_state(self):
        issues = [{"number": 9, "body": "m " + ist.state_comment({"v": 2})},
                  {"number": 7, "body": "m " + ist.state_comment({"v": 1})}]
        with mock.patch.object(ist.github_api, "list_open_issues", return_value=issues):
            issue, state = ist.load("o", "r", "m", "t", label="L")
        self.assertEqual((issue["number"], state), (7, {"v": 1}))

    def test_save_updates_primary_and_closes_duplicates(self):
        issues = [{"number": 7, "body": "m"}, {"number": 9, "body": "m"}]   # overlapping-run dupe
        with mock.patch.object(ist.github_api, "list_open_issues", return_value=issues), \
             mock.patch.object(ist.github_api, "update_issue") as up, \
             mock.patch.object(ist.github_api, "create_issue") as cr:
            ist.save("o", "r", "m", "t", title="T", body="B", label="L")
        up.assert_any_call("o", "r", 7, "t", title="T", body="B")     # primary refreshed
        up.assert_any_call("o", "r", 9, "t", state="closed")          # duplicate self-healed
        cr.assert_not_called()

    def test_save_creates_when_none_exists(self):
        with mock.patch.object(ist.github_api, "list_open_issues", return_value=[]), \
             mock.patch.object(ist.github_api, "create_issue") as cr:
            ist.save("o", "r", "m", "t", title="T", body="B", label="L")
        cr.assert_called_once_with("o", "r", "T", "B", "t", labels=["L"])


if __name__ == "__main__":
    unittest.main()
