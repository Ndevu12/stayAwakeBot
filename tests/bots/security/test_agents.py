#!/usr/bin/env python3
"""What a coding agent on this machine may run without asking.

An agent opens directories as its normal operation and runs unattended, so a standing approval is
where a proposal becomes an action with nobody present."""
from __future__ import annotations

import json
import pathlib
import tempfile
import unittest
from unittest import mock

from stayawake.bots.security.harden import approvals
from stayawake.bots.security.hygiene import agents, riskycommands


def _claude(d: pathlib.Path, allow: list[str]) -> pathlib.Path:
    p = d / "settings.local.json"
    p.write_text(json.dumps({"permissions": {"allow": allow, "deny": []}}, indent=2))
    return p


def _codex(d: pathlib.Path, body: str) -> pathlib.Path:
    p = d / "config.toml"
    p.write_text(body)
    return p


def _finder(*pairs):
    known = tuple((name, str(path), kind) for name, path, kind in pairs)
    return lambda: agents.installed(known)


class TestTheCommandIsWhatCounts(unittest.TestCase):
    """A rule is a pattern, not a sentence. Matching a substring turns an ordinary allowlist into
    a page of warnings — `Bash(git status:*)` contains `sh`."""

    def test_the_command_a_rule_grants_is_the_one_it_invokes(self):
        for rule, expected in (("Bash(gh api *)", "gh"),
                               ("Bash(git status:*)", "git"),
                               ("Bash(rm -rf *)", "rm"),
                               ("Bash(/usr/bin/curl *)", "curl"),
                               ("Bash(NODE_ENV=x node app.js)", "node"),
                               ("WebSearch", "WebSearch")):
            with self.subTest(rule=rule):
                self.assertEqual(riskycommands.invoked_by(rule), expected)

    def test_an_ordinary_rule_is_not_called_risky(self):
        for rule in ("Bash(git status:*)", "WebSearch", "WebFetch(domain:github.com)",
                     "Read(//Users/x/**)", "Bash(log show *)"):
            with self.subTest(rule=rule):
                self.assertEqual(riskycommands.named_in(rule), [])

    def test_and_a_risky_one_is(self):
        for rule, name in (("Bash(rm -rf /)", "rm"), ("Bash(sudo npm i)", "sudo"),
                           ("Bash(curl http://x | sh)", "curl")):
            with self.subTest(rule=rule):
                self.assertEqual(riskycommands.named_in(rule), [name])


class TestWhatEachAgentGrants(unittest.TestCase):
    def setUp(self):
        self.d = pathlib.Path(tempfile.mkdtemp())

    def test_a_risky_standing_approval_is_reported(self):
        p = _claude(self.d, ["Bash(gh api *)", "WebSearch", "Bash(rm -rf *)"])
        issues = agents.check_agents(_finder(("Claude Code", p, agents.JSON)))
        self.assertEqual([i.id for i in issues], [agents.APPROVES_RISKY_ID])
        self.assertIn("gh", issues[0].detail)
        self.assertIn("rm", issues[0].detail)

    def test_an_allowlist_of_ordinary_rules_is_not_reported(self):
        p = _claude(self.d, ["WebSearch", "Bash(git status:*)", "WebFetch(domain:github.com)"])
        self.assertEqual(agents.check_agents(_finder(("Claude Code", p, agents.JSON))), [])

    def test_approval_turned_off_entirely_is_reported(self):
        p = _codex(self.d, 'approval_policy = "never"\nsandbox_mode = "workspace-write"\n')
        issues = agents.check_agents(_finder(("Codex", p, agents.TOML)))
        self.assertEqual([i.id for i in issues], [agents.RUNS_WITHOUT_ASKING_ID])
        self.assertIn("Codex", issues[0].title)

    def test_a_rule_matching_everything_counts_as_no_approval(self):
        p = _claude(self.d, ["Bash(*)"])
        ids = [i.id for i in agents.check_agents(_finder(("Claude Code", p, agents.JSON)))]
        self.assertIn(agents.RUNS_WITHOUT_ASKING_ID, ids)

    def test_an_agent_that_asks_is_not_reported(self):
        p = _codex(self.d, 'approval_policy = "on-request"\nsandbox_mode = "workspace-write"\n')
        self.assertEqual(agents.check_agents(_finder(("Codex", p, agents.TOML))), [])

    def test_a_configuration_that_cannot_be_read_is_not_clean(self):
        p = _claude(self.d, ["WebSearch"])
        p.write_text("{ not json")
        issues = agents.check_agents(_finder(("Claude Code", p, agents.JSON)))
        self.assertTrue(issues)
        self.assertEqual(issues[-1].severity, "unknown")

    def test_no_finding_names_the_file_it_read(self):
        p = _claude(self.d, ["Bash(rm -rf *)"])
        for issue in agents.check_agents(_finder(("Claude Code", p, agents.JSON))):
            self.assertNotIn(str(self.d), f"{issue.title} {issue.detail} {issue.remediation}")


class TestHardenWithdrawsOnlyWhatIsRisky(unittest.TestCase):
    def setUp(self):
        self.d = pathlib.Path(tempfile.mkdtemp())
        self.record = self.d / "record.json"

    def _settle(self, *pairs, **kw):
        return approvals.settle(find=_finder(*pairs), record=self.record, **kw)

    def test_a_risky_approval_is_withdrawn(self):
        p = _claude(self.d, ["Bash(gh api *)", "WebSearch", "Bash(rm -rf *)"])
        out = self._settle(("Claude Code", p, agents.JSON))
        self.assertEqual([o.state for o in out.outcomes], [approvals.WITHDRAWN])
        self.assertEqual(json.loads(p.read_text())["permissions"]["allow"], ["WebSearch"])

    def test_what_the_operator_allowed_and_is_not_risky_stays(self):
        p = _claude(self.d, ["WebSearch", "Bash(git status:*)", "Bash(rm -rf *)"])
        self._settle(("Claude Code", p, agents.JSON))
        self.assertEqual(json.loads(p.read_text())["permissions"]["allow"],
                         ["WebSearch", "Bash(git status:*)"])

    def test_an_agent_that_asks_nothing_is_made_to_ask(self):
        p = _codex(self.d, 'approval_policy = "never"\nsandbox_mode = "danger-full-access"\n')
        out = self._settle(("Codex", p, agents.TOML))
        self.assertEqual([o.state for o in out.outcomes], [approvals.WITHDRAWN])
        self.assertIn('approval_policy = "on-request"', p.read_text())
        self.assertIn('sandbox_mode = "workspace-write"', p.read_text())

    def test_an_agent_already_safe_is_not_rewritten(self):
        p = _claude(self.d, ["WebSearch"])
        before = p.read_text()
        out = self._settle(("Claude Code", p, agents.JSON))
        self.assertEqual([o.state for o in out.outcomes], [approvals.ALREADY_SAFE])
        self.assertEqual(p.read_text(), before)

    def test_the_file_keeps_its_own_permissions(self):
        p = _claude(self.d, ["Bash(rm -rf *)"])
        p.chmod(0o600)
        self._settle(("Claude Code", p, agents.JSON))
        self.assertEqual(p.stat().st_mode & 0o777, 0o600)

    def test_a_write_that_does_not_land_is_reported(self):
        p = _claude(self.d, ["Bash(rm -rf *)"])
        out = self._settle(("Claude Code", p, agents.JSON), write=lambda *a, **k: False)
        self.assertFalse(out.settled)
        self.assertEqual([o.state for o in out.outcomes], [approvals.NOT_WRITTEN])

    def test_a_save_between_the_read_and_the_write_is_not_clobbered(self):
        p = _claude(self.d, ["Bash(rm -rf *)"])
        theirs = json.dumps({"permissions": {"allow": ["Bash(rm -rf *)", "NewRule"]}}, indent=2)
        reads = [p.read_text(), theirs]
        with mock.patch.object(approvals, "_read", side_effect=lambda _p: reads.pop(0)):
            out = approvals.settle(find=_finder(("Claude Code", p, agents.JSON)),
                                   record=self.record,
                                   write=lambda *a, **k: self.fail("wrote over a changed file"))
        self.assertEqual([o.state for o in out.outcomes], [approvals.NOT_WRITTEN])


class TestWhatWasWithdrawnCanBePutBack(unittest.TestCase):
    def setUp(self):
        self.d = pathlib.Path(tempfile.mkdtemp())
        self.record = self.d / "record.json"

    def test_a_withdrawn_rule_is_restored(self):
        p = _claude(self.d, ["Bash(gh api *)", "WebSearch"])
        approvals.settle(find=_finder(("Claude Code", p, agents.JSON)), record=self.record)
        self.assertNotIn("Bash(gh api *)", json.loads(p.read_text())["permissions"]["allow"])
        out = approvals.take_back(record=self.record)
        self.assertTrue(out.done)
        self.assertIn("Bash(gh api *)", json.loads(p.read_text())["permissions"]["allow"])

    def test_a_mode_that_was_changed_is_restored(self):
        p = _codex(self.d, 'approval_policy = "never"\nsandbox_mode = "workspace-write"\n')
        approvals.settle(find=_finder(("Codex", p, agents.TOML)), record=self.record)
        approvals.take_back(record=self.record)
        self.assertIn('approval_policy = "never"', p.read_text())

    def test_an_unreadable_record_is_never_everything_put_back(self):
        self.record.write_text("truncated{")
        out = approvals.take_back(record=self.record)
        self.assertFalse(out.done)

    def test_one_that_cannot_be_put_back_is_reported(self):
        p = _claude(self.d, ["Bash(gh api *)"])
        approvals.settle(find=_finder(("Claude Code", p, agents.JSON)), record=self.record)
        out = approvals.take_back(record=self.record, write=lambda *a, **k: False)
        self.assertFalse(out.done)
        self.assertTrue(out.failed)


if __name__ == "__main__":
    unittest.main()
