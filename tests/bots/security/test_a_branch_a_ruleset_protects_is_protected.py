#!/usr/bin/env python3
"""A branch a ruleset protects is not reported as unprotected; what that protection does not require is still reported,
and `saw guard check` reads the same answer."""
from __future__ import annotations

import unittest
from unittest import mock

from stayawake.bots.security import guard, hygiene
from stayawake.bots.security.guard import Freshness, GateProbe, StrixRef
from stayawake.lib.adapters import github_api
from stayawake.lib.adapters.github_api import ApiRead

_STRIX = StrixRef(".github/workflows/worm-scan.yml", "strix", "v0.1.4", "tag")
_BLOG_WF = """name: Worm scan
on: { push: { branches: [main] }, pull_request: {} }
jobs:
  strix:
    runs-on: ubuntu-latest
    steps:
      - uses: Ndevu12/strix@v0.1.4
"""


def _rules(*checks):
    """This repository's own ruleset on main, as GitHub returns it, with `checks` required."""
    plain = ("deletion", "non_fast_forward", "required_linear_history", "required_signatures", "code_scanning",
             "code_quality")
    rules = [{"type": kind, "ruleset_source_type": "Repository", "ruleset_id": 1} for kind in plain]
    rules.append({"type": "pull_request", "parameters": {"required_approving_review_count": 1}})
    rules.append({"type": "required_status_checks",
                  "parameters": {"required_status_checks": [{"context": c} for c in ("pin-freshness", *checks)]}})
    return ApiRead(value=rules)


def _audit(classic, rules, probe=GateProbe(ref=_STRIX)):
    with mock.patch.object(github_api, "get_branch_protection", return_value=classic), \
            mock.patch.object(github_api, "get_branch_rules", return_value=rules), \
            mock.patch("stayawake.bots.security.guard.probe_remote_gate", return_value=probe):
        return hygiene.check_branch_protection("o/r", "tok")


class TestARulesetProtectsTheBranch(unittest.TestCase):
    def test_a_ruleset_that_requires_the_gate_is_clean(self):
        self.assertEqual(_audit(None, _rules("strix")), [])

    def test_a_ruleset_that_does_not_require_the_gate_names_that_gap_and_where_to_add_it(self):
        issues = _audit(None, _rules())
        self.assertEqual([i.id for i in issues], ["worm-guard-not-required"])
        self.assertIn("is protected by a ruleset", issues[0].detail)
        self.assertIn("the ruleset that protects it", issues[0].remediation)

    def test_a_ruleset_without_a_strix_workflow_is_held_to_a_worm_check(self):
        self.assertEqual([i.id for i in _audit(None, _rules(), GateProbe())], ["worm-guard-not-required"])
        self.assertEqual(_audit(None, _rules("Worm Guard — block infected merges"), GateProbe()), [])

    def test_branch_protection_and_a_ruleset_together_require_what_either_requires(self):
        classic = {"required_status_checks": {"contexts": ["build"]}}
        self.assertEqual(_audit(classic, _rules("strix")), [])
        issues = _audit(classic, _rules())
        self.assertIn("protected by branch protection and a ruleset", issues[0].detail)


class TestWhatWasTrueBeforeStillIs(unittest.TestCase):
    def test_branch_protection_alone_is_read_as_before(self):
        self.assertEqual(_audit({"required_status_checks": {"contexts": ["strix"]}}, ApiRead(value=[])), [])
        issues = _audit({"required_status_checks": {"contexts": ["build"]}}, ApiRead(value=[]))
        self.assertEqual([i.id for i in issues], ["worm-guard-not-required"])
        self.assertIn("protected by branch protection", issues[0].detail)

    def test_a_branch_nothing_protects_is_unprotected(self):
        self.assertEqual([i.id for i in _audit(None, ApiRead(value=[]))], ["branch-unprotected"])

    def test_rules_that_could_not_be_read_count_as_none(self):
        for cause in ("forbidden", "network", "not_found", "rate_limited"):
            with self.subTest(cause=cause):
                self.assertEqual([i.id for i in _audit(None, ApiRead(cause=cause))], ["branch-unprotected"])
                self.assertEqual(_audit({"required_status_checks": {"contexts": ["strix"]}}, ApiRead(cause=cause)), [])

    def test_a_rule_without_its_checks_requires_none(self):
        for rules in ([{"type": "required_status_checks"}], [{"type": "required_status_checks", "parameters": None}],
                      [{"type": "required_status_checks", "parameters": {"required_status_checks": [{"name": "strix"}]}}],
                      ["strix", {"context": "strix"}, {"type": 7}]):
            with self.subTest(rules=rules):
                self.assertNotEqual(_audit(None, ApiRead(value=rules)), [])


class TestTheGuardReadsTheSameAnswer(unittest.TestCase):
    def _check(self, classic, rules):
        with mock.patch.object(guard.detect, "_remote_workflows", return_value=guard.RemoteRead({"w.yml": _BLOG_WF})), \
                mock.patch.object(github_api, "get_branch_protection", return_value=classic), \
                mock.patch.object(github_api, "get_branch_rules", return_value=rules), \
                mock.patch.object(guard.detect, "freshness", return_value=Freshness("fresh", "v0.1.4")):
            return guard.check(slug="o/r", token="t")

    def test_a_ruleset_that_requires_the_gate_reads_required_and_says_so(self):
        status = self._check(None, _rules("strix"))
        self.assertTrue(status.required)
        self.assertIn("main is protected by a ruleset, which requires “strix”", guard.render(status))

    def test_a_ruleset_that_does_not_require_the_gate_reads_not_required(self):
        self.assertFalse(self._check(None, _rules()).required)


class TestTheRulesAreReadInFull(unittest.TestCase):
    def _read(self, pages):
        calls = []

        def answer(path, token=None):
            calls.append(path)
            return pages[len(calls) - 1]
        with mock.patch.object(github_api, "_do_request", side_effect=answer):
            return github_api.get_branch_rules("o", "r", "release/1#x", "t"), calls

    def test_every_page_is_read(self):
        full = ApiRead(value=[{"type": "deletion"}] * 100)
        read, calls = self._read([full, ApiRead(value=[{"type": "pull_request"}])])
        self.assertEqual(len(read.value), 101)
        self.assertEqual(calls[0], "/repos/o/r/rules/branches/release/1%23x?per_page=100&page=1")

    def test_a_page_that_cannot_be_read_leaves_the_rules_unread(self):
        read, _ = self._read([ApiRead(value=[{"type": "deletion"}] * 100), ApiRead(cause="network")])
        self.assertEqual(read.cause, "network")

    def test_an_answer_that_is_not_a_list_leaves_the_rules_unread(self):
        read, _ = self._read([ApiRead(value={"message": "x"})])
        self.assertIsNotNone(read.cause)

    def test_more_rules_than_are_read_leave_the_rules_unread(self):
        read, calls = self._read([ApiRead(value=[{"type": "deletion"}] * 100)] * 10)
        self.assertIsNotNone(read.cause)
        self.assertEqual(len(calls), 10)


class TestAGateThatCouldNotBeCheckedIsNeverClean(unittest.TestCase):
    def _checked(self, classic, rules, cause):
        from stayawake.bots.security.hygiene.outcome import run_probe
        with mock.patch.object(github_api, "get_branch_protection", return_value=classic), \
                mock.patch.object(github_api, "get_branch_rules", return_value=rules), \
                mock.patch("stayawake.bots.security.guard.probe_remote_gate", return_value=GateProbe(cause=cause)):
            return run_probe("branch protection", lambda: hygiene.check_branch_protection("o/r", "tok"))

    def test_workflows_that_could_not_be_read_leave_the_requirement_unknown_whatever_protects_the_branch(self):
        from stayawake.bots.security.hygiene.outcome import CHECKED_CLEAN, UNKNOWN
        classic = {"required_status_checks": {"contexts": ["build"]}}
        for label, protection in (
            ("a ruleset that only stops deletion", (None, ApiRead(value=[{"type": "deletion"}]))),
            ("a ruleset that requires another check", (None, _rules())),
            ("a ruleset with only a merge queue", (None, ApiRead(value=[{"type": "merge_queue"}]))),
            ("branch protection alone", (classic, ApiRead(value=[]))),
            ("both", (classic, _rules())),
        ):
            for cause in ("rate_limited", "forbidden", "network"):
                with self.subTest(label=label, cause=cause):
                    outcome = self._checked(*protection, cause)
                    self.assertNotEqual(outcome.state, CHECKED_CLEAN)
                    self.assertEqual(outcome.state, UNKNOWN)
                    self.assertEqual([i.id for i in outcome.issues], ["worm-guard-requirement-unchecked"])
                    self.assertIn("could not be checked", outcome.issues[0].title)

    def test_a_branch_nothing_protects_is_unprotected_whether_or_not_the_workflows_could_be_read(self):
        outcome = self._checked(None, ApiRead(value=[]), "network")
        self.assertEqual([i.id for i in outcome.issues], ["branch-unprotected"])


def _saw_audit(classic, rules, cause, *argv, slug="o/r", token="tok"):
    """Run `saw audit --repo <slug>` with only the branch protection check, GitHub answering as given."""
    import contextlib
    import io
    from stayawake import cli
    out = io.StringIO()
    with mock.patch.object(github_api, "get_branch_protection", return_value=classic), \
            mock.patch.object(github_api, "get_branch_rules", return_value=rules), \
            mock.patch("stayawake.bots.security.guard.probe_remote_gate", return_value=GateProbe(cause=cause)), \
            mock.patch("stayawake.lib.auth.resolve_token", return_value=(token, None)), \
            mock.patch("stayawake.bots.security.hygiene.audit_checks",
                       return_value=[("branch protection", lambda: hygiene.check_branch_protection(slug, token))]), \
            contextlib.redirect_stdout(out), contextlib.redirect_stderr(io.StringIO()):
        code = cli.main(["audit", "--repo", slug, "--no-stream", *argv])
    return code, out.getvalue()


class TestWhatAuditSaysWhenTheGateCouldNotBeChecked(unittest.TestCase):
    _PROTECTIONS = (
        ("a ruleset that only stops deletion", None, ApiRead(value=[{"type": "deletion"}])),
        ("a ruleset that requires another check", None, _rules()),
        ("branch protection alone", {"required_status_checks": {"contexts": ["build"]}}, ApiRead(value=[])),
        ("both", {"required_status_checks": {"contexts": ["build"]}}, _rules()),
    )

    def test_it_says_the_gate_could_not_be_checked_and_never_that_nothing_was_found(self):
        for label, classic, rules in self._PROTECTIONS:
            for cause in ("rate_limited", "forbidden", "network"):
                with self.subTest(label=label, cause=cause):
                    _code, text = _saw_audit(classic, rules, cause)
                    self.assertIn("Not checked", text)
                    self.assertIn("Whether o/r@main requires the worm gate could not be checked", text)
                    self.assertIn("Run `saw audit --repo o/r` again once GitHub can be read.", text)
                    self.assertNotIn("no issues found", text)

    def test_the_fail_flag_fails_when_the_gate_could_not_be_checked(self):
        for label, classic, rules in self._PROTECTIONS:
            with self.subTest(label=label):
                self.assertEqual(_saw_audit(classic, rules, "network", "-f")[0], 1)

    def test_a_gate_that_was_checked_and_is_required_still_passes_the_fail_flag(self):
        code, text = _saw_audit(None, _rules("Worm Guard — block infected merges"), None, "-f")
        self.assertEqual(code, 0)
        self.assertIn("no issues found", text)


class TestARepositoryThatCouldNotBeLookedUpIsNotChecked(unittest.TestCase):
    def test_without_a_token_it_says_so_and_the_fail_flag_fails(self):
        code, text = _saw_audit(None, ApiRead(value=[]), None, "-f", token=None)
        self.assertEqual(code, 1)
        self.assertIn("Whether o/r@main requires the worm gate could not be checked", text)
        self.assertIn("No GitHub token was available to read o/r", text)
        self.assertNotIn("no issues found", text)

    def test_a_name_that_is_not_owner_and_name_says_so_and_the_fail_flag_fails(self):
        for slug in ("justaname", "owner/", "/name"):
            with self.subTest(slug=slug):
                code, text = _saw_audit(None, ApiRead(value=[]), None, "-f", slug=slug)
                self.assertEqual(code, 1)
                self.assertIn(f"is not a repository name of the form OWNER/NAME", text)
                self.assertNotIn("no issues found", text)


class TestTheStrongerHeadlineStillLeads(unittest.TestCase):
    def _headline(self, *ids):
        return hygiene.render([hygiene.HygieneIssue(id=i, severity="unknown", title="T", detail="D", remediation="F")
                               for i in ids]).splitlines()[0]

    def test_unverified_start_up_entries_lead_over_a_result_not_known(self):
        from stayawake.bots.security.hygiene.models import SURFACE_UNREADABLE_ID
        for other in ("git-credentials-unread", "cached-github-keychain-unread", "editors-not-examined",
                      "worm-guard-requirement-unchecked"):
            with self.subTest(other=other):
                self.assertEqual(self._headline(other, SURFACE_UNREADABLE_ID),
                                 "Local security hygiene: no findings, but the persistence surface is UNVERIFIED.")

    def test_a_check_that_did_not_run_leads_as_before(self):
        from stayawake.bots.security.hygiene.models import BLOCKED_ID, SURFACE_UNREADABLE_ID
        self.assertEqual(self._headline(BLOCKED_ID, SURFACE_UNREADABLE_ID),
                         "Local security hygiene: nothing was found, and some checks did not run.")


class TestEveryResultNotKnownIsShown(unittest.TestCase):
    def test_a_credential_store_that_could_not_be_read_is_shown_and_does_not_fail_the_fail_flag(self):
        unread = hygiene.HygieneIssue(id="git-credentials-unread", severity="unknown",
                                      title="The git credential file was not read",
                                      detail="Whether it stores a github.com credential is not known.",
                                      remediation="Run the audit again once your git credential file is readable.")
        text = hygiene.render([unread])
        for words in ("Not checked", "The git credential file was not read",
                      "Whether it stores a github.com credential is not known."):
            with self.subTest(words=words):
                self.assertIn(words, text)
        self.assertNotIn("no issues found", text)
        import contextlib
        import io
        from stayawake import cli
        with mock.patch("stayawake.lib.auth.resolve_token", return_value=(None, None)), \
                mock.patch("stayawake.bots.security.hygiene.audit_checks",
                           return_value=[("credentials", lambda: [unread])]), \
                contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(cli.main(["audit", "--no-stream", "-f"]), 0)


class TestAnAnswerInAShapeGitHubDoesNotDescribeCountsAsUnread(unittest.TestCase):
    def test_a_ruleset_whose_checks_are_not_a_list_counts_as_no_ruleset(self):
        for checks in (5, "strix", {"context": "strix"}):
            rules = ApiRead(value=[{"type": "required_status_checks", "parameters": {"required_status_checks": checks}}])
            with self.subTest(checks=checks):
                self.assertEqual([i.id for i in _audit(None, rules)], ["branch-unprotected"])
                self.assertFalse(TestTheGuardReadsTheSameAnswer()._check(None, rules).required)

    def test_branch_protection_whose_checks_are_not_a_list_counts_as_none(self):
        for classic in ({"required_status_checks": {"contexts": 5}}, {"required_status_checks": {"checks": "strix"}},
                        {"required_status_checks": "strix"}):
            with self.subTest(classic=classic):
                self.assertEqual([i.id for i in _audit(classic, ApiRead(value=[]))], ["branch-unprotected"])
                self.assertEqual([i.id for i in _audit(classic, _rules("strix"))], [])


class TestBranchProtectionIsReadForTheBranchNamed(unittest.TestCase):
    def test_a_branch_name_with_characters_a_web_address_reserves_is_quoted(self):
        for branch, quoted in (("rel#1", "rel%231"), ("x?y", "x%3Fy"), ("release/1", "release/1")):
            asked = []

            def answer(request, timeout=None, context=None):
                asked.append(request.full_url)
                raise OSError("offline")
            with self.subTest(branch=branch), mock.patch.object(github_api.urllib.request, "urlopen", side_effect=answer):
                github_api.get_branch_protection("o", "r", branch, "t")
                self.assertEqual(asked, [f"https://api.github.com/repos/o/r/branches/{quoted}/protection"])


if __name__ == "__main__":
    unittest.main()
