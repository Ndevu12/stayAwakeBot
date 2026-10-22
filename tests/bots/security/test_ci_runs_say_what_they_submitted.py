#!/usr/bin/env python3
"""`saw fix --pr` and `saw guard drift` say what they submitted to GitHub: a pull request GitHub
refused names the setting that refused it, `--json` reports what each repository's fix or drift
check came to, and a drift run that could not file its issue says so and fails."""
from __future__ import annotations

import contextlib
import io
import json
import unittest
import urllib.error
from email.message import Message
from pathlib import Path
from unittest import mock

from stayawake import cli
from stayawake.bots.security import guard, pr, remediator
from stayawake.bots.security.guard import GuardStatus, SawGuardRef
from stayawake.bots.security.guard.provision import SetupResult, _render_setup_submit
from stayawake.bots.security.models import Finding, ScanResult, Severity
from stayawake.bots.security.pr.fix import _remediation_of
from stayawake.bots.security.pr.fix_verdict import (BaseFix, BaseState, Checkout, FixVerdict,
                                                     remediation_record)
from stayawake.bots.security.pr.render import _render_submit
from stayawake.bots.security.remediation import Change
from stayawake.core import proposal
from stayawake.core.identity import classify_pr_refusal
from stayawake.core.proposal import SubmitResult
from stayawake.lib.adapters import github_api
from stayawake.lib.adapters.github_api import ApiRead
from stayawake.lib.git.write.push import PushResult
from tests.bots.security.test_pr import _checkout_reads, _line, _patch_git

_ACTIONS_MAY_NOT = json.dumps({
    "message": "GitHub Actions is not permitted to create or approve pull requests.",
    "documentation_url": "https://docs.github.com/rest/pulls/pulls#create-a-pull-request"})
_SETTING = "Allow GitHub Actions to create and approve pull requests"


def _refused(status: int, body: str):
    """Make urlopen refuse every call the way GitHub does. Takes the status and response body."""
    def refuse(req, **_):
        raise urllib.error.HTTPError(req.full_url, status, "refused", Message(),
                                     io.BytesIO(body.encode()))
    return refuse


class TestARefusedPullRequestNamesTheSetting(unittest.TestCase):
    def test_githubs_refusal_reaches_the_submission_with_its_reason(self):
        with mock.patch.object(github_api, "list_open_pulls", return_value=[]), \
             mock.patch.object(github_api.urllib.request, "urlopen",
                               side_effect=_refused(403, _ACTIONS_MAY_NOT)), \
             contextlib.redirect_stderr(io.StringIO()):
            read = github_api.open_or_update_pr("o", "r", head_branch="b", base="main",
                                                     title="t", body="b", token="tok")
        self.assertEqual(read.cause, "forbidden")
        self.assertEqual(classify_pr_refusal(read.cause, read.detail),
                         "actions-may-not-open-pull-requests")

    def test_an_open_pull_request_is_still_reported_when_its_text_could_not_be_refreshed(self):
        with mock.patch.object(github_api, "list_open_pulls",
                               return_value=[{"number": 8, "html_url": "u"}]), \
             mock.patch.object(github_api.urllib.request, "urlopen",
                               side_effect=_refused(403, '{"message": "Forbidden"}')), \
             contextlib.redirect_stderr(io.StringIO()):
            read = github_api.open_or_update_pr("o", "r", head_branch="b", base="main",
                                                     title="t", body="b", token="tok")
        self.assertEqual((read.cause, read.value["number"], read.value["action"]),
                         (None, 8, "updated"))

    def test_a_pushed_branch_github_will_not_open_records_why(self):
        refused = ApiRead(cause="forbidden", status=403, detail=_ACTIONS_MAY_NOT)
        with mock.patch.object(proposal.gitutil, "push_branch_result",
                               return_value=PushResult(True, "")), \
             mock.patch.object(proposal.github_api, "open_or_update_pr", return_value=refused):
            res = proposal.submit_change_pr(Path("."), "o/r", "main", branch="security/x",
                                            title="t", body="b", token="tok")
        self.assertEqual((res.kind, res.pr_reason),
                         ("pr-create-failed", "actions-may-not-open-pull-requests"))

    def test_saw_fix_names_the_setting(self):
        res = SubmitResult("pr-create-failed", pr_reason="actions-may-not-open-pull-requests")
        self.assertIn(_SETTING, _render_submit(res, slug="o/r", base="main", partial=False))

    def test_saw_guard_setup_names_the_setting(self):
        res = SubmitResult("pr-create-failed", pr_reason="actions-may-not-open-pull-requests")
        self.assertIn(_SETTING, _render_setup_submit(SetupResult(submit=res, slug="o/r"),
                                                     color=False))

    def test_any_other_refusal_keeps_its_line(self):
        for reason in ("forbidden", "network", None):
            with self.subTest(reason=reason):
                line = _render_submit(SubmitResult("pr-create-failed", pr_reason=reason),
                                      slug="o/r", base="main", partial=False)
                self.assertIn("PR API call failed", line)
                self.assertNotIn(_SETTING, line)

    def test_a_forbidden_refusal_with_another_message_is_not_the_setting(self):
        self.assertEqual(classify_pr_refusal("forbidden", '{"message": "Resource not accessible"}'),
                         "forbidden")


class TestWhatEachFixCameTo(unittest.TestCase):
    def test_each_submission_is_named_with_its_cause(self):
        cases = [
            (SubmitResult("pr", number=4, url="u"), ("pr", "")),
            (SubmitResult("fork-pr", number=5, url="u", fork_slug="me/r"), ("fork-pr", "")),
            (SubmitResult("floor", patch_path=Path("p.patch"), push_reason="workflow_scope"),
             ("patch", "workflow_scope")),
            (SubmitResult("floor", issue_note="filed issue #3", push_reason="forbidden"),
             ("issue", "forbidden")),
            (SubmitResult("floor", push_reason="network"), ("failed", "network")),
            (SubmitResult("pr-create-failed", pr_reason="actions-may-not-open-pull-requests"),
             ("failed", "actions-may-not-open-pull-requests")),
            (SubmitResult("fork-pr-create-failed"), ("failed", "unknown")),
            (SubmitResult("fork-not-ready", fork_slug="me/r"), ("failed", "fork-not-ready")),
        ]
        for res, expected in cases:
            with self.subTest(kind=res.kind):
                self.assertEqual(_remediation_of(res), expected)

    def _record(self, fix: BaseFix) -> dict:
        return remediation_record("o/r", FixVerdict("o/r", fix, Checkout.CLEAN))

    def test_an_opened_pull_request_is_reported_with_its_number(self):
        record = self._record(BaseFix(BaseState.PR_OPENED, "", pull_request=4, published=True,
                                      remediation="pr", pull_request_url="u"))
        self.assertEqual(record, {"repository": "o/r", "remediation": "pr", "cause": "",
                                  "pull_request": 4, "url": "u", "partial": False, "branch": "",
                                  "base": "", "removed": [], "history_holds_payload": False,
                                  "needs_review": []})

    def test_a_repository_with_nothing_to_fix_is_skipped(self):
        for state in (BaseState.NOTHING_TO_FIX, BaseState.SUSPICIOUS_ONLY):
            with self.subTest(state=state):
                self.assertEqual(self._record(BaseFix(state, ""))["remediation"], "skipped")

    def test_a_branch_never_pushed_is_reported_as_prepared(self):
        self.assertEqual(self._record(BaseFix(BaseState.PREPARED, "", branch="b"))["remediation"],
                         "prepared")

    def test_a_run_that_stopped_is_failed(self):
        record = self._record(BaseFix(BaseState.ABORTED, ""))
        self.assertEqual((record["remediation"], record["cause"]), ("failed", "aborted"))

    def test_a_repository_that_never_reached_a_verdict_is_failed(self):
        record = remediation_record("o/r", None)
        self.assertEqual(record["remediation"], "failed")
        self.assertNotIn("uncommitted", record)
        self.assertEqual(record["needs_review"], [])

    def test_a_prepared_fix_names_its_branches_and_what_it_could_not_save(self):
        from stayawake.bots.security.pr.fix import _CheckoutSeen, _verdict
        from stayawake.bots.security.pr.fix_verdict import History, HistoryHold, Remedy, render_fix_verdict
        from stayawake.bots.security.remediation.preserve import NO_IDENTITY, Preserved
        saved = Preserved(reason=NO_IDENTITY, blocked=True, files=2)
        seen = _CheckoutSeen(
            Checkout.CLEANED,
            history=History(holds=(HistoryHold("branch", "feature", ("a.js",), Remedy.AMEND),)),
            removed=(".vscode/tasks.json",),
            preserved=saved)
        verdict = _verdict("o/r", BaseFix(BaseState.PARTIAL, "o/r: PARTIAL", "main",
                                          "security/auto-clean-main"), seen,
                           review=("Manual review needed (inspect before running any command):",))
        record = remediation_record("o/r", verdict)
        self.assertEqual(record["remediation"], "prepared")
        self.assertIs(record["partial"], True)
        self.assertEqual((record["branch"], record["base"]), ("security/auto-clean-main", "main"))
        self.assertEqual(record["removed"], [".vscode/tasks.json"])
        self.assertEqual(record["uncommitted"],
                         {"branch": "", "files": 2, "withheld": 0, "unsaved": 0, "unread": 0,
                          "reason": NO_IDENTITY})
        self.assertIs(record["history_holds_payload"], True)
        self.assertTrue(any("feature" in line for line in record["needs_review"]))
        self.assertIn("Manual review needed (inspect before running any command):",
                      record["needs_review"])
        rendered = render_fix_verdict(verdict)
        self.assertIn("feature", rendered)
        for line in record["needs_review"]:
            if line.startswith("Manual review"):
                continue
            self.assertIn(line, rendered)

    def test_a_fix_with_nothing_to_save_names_the_clean_up_branch_only(self):
        record = self._record(BaseFix(BaseState.PREPARED, "", base="main",
                                      branch="security/auto-clean-main"))
        self.assertNotIn("uncommitted", record)
        self.assertEqual(record["branch"], "security/auto-clean-main")
        self.assertIs(record["partial"], False)
        self.assertIs(record["history_holds_payload"], False)


class TestAFixRunRecordsItsSubmission(unittest.TestCase):
    def _submit(self, created: ApiRead):
        finding = Finding("x", "code-loader", Severity.CRITICAL, "postcss.config.mjs", "loader",
                          remediation="strip-appended-payload")
        infected = ScanResult("owner/repo", "local", [finding])
        clean = ScanResult("owner/repo", "local", [])
        scans = [infected, clean, clean]
        change = [Change("strip-payload", "postcss.config.mjs")]
        with _patch_git(), _checkout_reads(infected), \
             mock.patch.object(pr.fix, "scan_target",
                               side_effect=lambda *a, **k: scans.pop(0) if scans else clean), \
             mock.patch.object(pr.remediation, "plan", return_value=change), \
             mock.patch.object(pr.remediation, "apply", return_value=change), \
             mock.patch.object(pr.github_api, "list_open_pulls", return_value=[]), \
             mock.patch.object(pr.github_api, "add_labels"), \
             mock.patch.object(pr.github_api, "remove_label"), \
             mock.patch.object(pr.github_api, "create_pull", return_value=created), \
             contextlib.redirect_stderr(io.StringIO()):
            return pr.submit_fix_pr(Path("/repo"), object(), {}, [], token="t")

    def test_an_opened_pull_request_is_recorded(self):
        verdict = self._submit(ApiRead(value={"number": 99, "html_url": "u"}))
        self.assertEqual(remediation_record("owner/repo", verdict),
                         {"repository": "owner/repo", "remediation": "pr", "cause": "",
                          "pull_request": 99, "url": "u", "partial": False,
                          "branch": "security/auto-clean-main", "base": "main", "removed": [],
                          "history_holds_payload": False, "decisions": [],
                          "needs_review": [
                              "your checkout is not clean — 1 confirmed file(s) are still in it; "
                              "the installed tree was left, because your uncommitted work could "
                              "not be held: git could not list the working tree"]})

    def test_a_pull_request_actions_may_not_open_is_recorded_with_the_setting(self):
        verdict = self._submit(ApiRead(cause="forbidden", status=403, detail=_ACTIONS_MAY_NOT))
        record = remediation_record("owner/repo", verdict)
        self.assertEqual((record["remediation"], record["cause"]),
                         ("failed", "actions-may-not-open-pull-requests"))
        self.assertIn(_SETTING, _line(verdict))

    def _manual(self, filed: str | None):
        finding = Finding("x", "exfil", Severity.CRITICAL, "telemetry.js", "exfil",
                          remediation="manual")
        infected = ScanResult("owner/repo", "local", [finding])
        with _patch_git(), _checkout_reads(infected), \
             mock.patch.object(pr.fix, "scan_target", return_value=infected), \
             mock.patch.object(pr.remediation, "plan", return_value=[]), \
             mock.patch.object(pr.remediation, "apply", return_value=[]), \
             mock.patch.object(proposal, "file_dedup_issue", return_value=filed):
            return remediation_record("owner/repo",
                                      pr.submit_fix_pr(Path("/repo"), object(), {}, [], token="t"))

    def test_findings_that_need_a_person_are_recorded_as_an_issue_when_one_is_filed(self):
        self.assertEqual(self._manual("opened issue #3 (u)")["remediation"], "issue")
        record = self._manual(None)
        self.assertEqual((record["remediation"], record["cause"]), ("failed", "issue-not-filed"))


class TestSawFixJson(unittest.TestCase):
    def _fix(self, outcomes):
        out, err = io.StringIO(), io.StringIO()
        with mock.patch.object(remediator, "_resolve_config", return_value={"settings": {}}), \
             mock.patch.object(remediator, "load_signatures", return_value={}), \
             mock.patch.object(remediator, "_fix_local", return_value=outcomes), \
             contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            rc = remediator.fix(pr=True, paths=["."], no_stream=True, json_out=True)
        return rc, out.getvalue(), err.getvalue()

    def test_stdout_holds_only_what_each_repository_came_to(self):
        refused = FixVerdict("o/r", BaseFix(
            BaseState.PR_FAILED, "o/r: refused", branch="security/x", published=True,
            remediation="failed", cause="actions-may-not-open-pull-requests"), Checkout.CLEAN)
        outcomes = [remediator._graded_fix(lambda: refused, "o/r"),
                    remediator._graded_fix(lambda: (_ for _ in ()).throw(OSError("disk")), "o/s")]
        _rc, out, err = self._fix(outcomes)
        self.assertEqual(json.loads(out)["results"], [
            {"repository": "o/r", "remediation": "failed",
             "cause": "actions-may-not-open-pull-requests", "pull_request": None, "url": "",
             "partial": False, "branch": "security/x", "base": "", "removed": [],
             "history_holds_payload": False, "needs_review": []},
            {"repository": "o/s", "remediation": "failed", "cause": "error",
             "pull_request": None, "url": "", "partial": False, "branch": "", "base": "",
             "removed": [], "history_holds_payload": False, "needs_review": []}])
        self.assertIn("Processed 2 repositories", err)

    def test_nothing_to_fix_still_prints_a_report(self):
        _rc, out, _err = self._fix([])
        self.assertEqual(json.loads(out), {"schema_version": 1, "results": []})

    def test_the_flag_reaches_the_fix(self):
        with mock.patch.object(remediator, "fix", return_value=0) as fix:
            cli.main(["fix", "--pr", "--json", "."])
        self.assertTrue(fix.call_args.kwargs["json_out"])

    def test_amend_refuses_the_flag(self):
        with mock.patch.object(remediator, "amend", return_value=0) as amend, \
             contextlib.redirect_stderr(io.StringIO()):
            rc = cli.main(["fix", "amend", "--json", "."])
        self.assertNotEqual(rc, 0)
        amend.assert_not_called()


class TestDriftSaysWhenItCouldNotFileItsIssue(unittest.TestCase):
    _REF = SawGuardRef(workflow=".github/workflows/saw-guard.yml", job="saw-guard", ref="a" * 40,
                       pin="sha")

    def _status(self, state):
        return GuardStatus(present=True, ref=self._REF,
                           fresh=guard.Freshness(state, "v0.1.5", "latest v0.1.5"))

    def _drift(self, state, *, existing=None, created=None, updated=None):
        comments = []
        issues = [{"number": existing, "title": guard.pindrift.DRIFT_TITLE}] if existing else []
        with mock.patch.object(guard.pindrift.detect, "check", return_value=self._status(state)), \
             mock.patch.object(guard.pindrift, "_resolve_slug", return_value=("o", "r")), \
             mock.patch.object(guard.pindrift.github_api, "list_open_issues", return_value=issues), \
             mock.patch.object(guard.pindrift.github_api, "create_issue", return_value=created), \
             mock.patch.object(guard.pindrift.github_api, "update_issue", return_value=updated), \
             mock.patch.object(guard.pindrift.github_api, "add_issue_comment",
                               side_effect=lambda *a, **k: comments.append(a) or {}):
            outcome = guard.drift_one(repo=".", token="t")
        return outcome, comments

    def test_an_issue_github_refused_to_open_is_not_reported_opened(self):
        outcome, _ = self._drift("behind", created=None)
        self.assertEqual(outcome.action, "failed")
        self.assertIn("could not open the drift issue", guard.render_drift(outcome))

    def test_an_issue_github_refused_to_update_is_not_reported_updated(self):
        outcome, _ = self._drift("behind", existing=12, updated=None)
        self.assertEqual((outcome.action, outcome.issue), ("failed", 12))
        self.assertIn("could not update the drift issue #12", guard.render_drift(outcome))

    def test_an_issue_github_refused_to_close_is_not_reported_closed(self):
        outcome, comments = self._drift("fresh", existing=12, updated=None)
        self.assertEqual(outcome.action, "failed")
        self.assertIn("could not close the drift issue #12", guard.render_drift(outcome))
        self.assertEqual(comments, [])

    def test_issues_github_took_are_reported_as_before(self):
        self.assertEqual(self._drift("behind", created={"number": 7})[0].action, "opened")
        self.assertEqual(self._drift("behind", existing=12, updated={"number": 12})[0].action,
                         "refreshed")
        self.assertEqual(self._drift("fresh", existing=12, updated={"number": 12})[0].action,
                         "closed")

    def _sweep(self, outcome, *, json_out=False):
        out, err = io.StringIO(), io.StringIO()
        with mock.patch.object(guard.sweep, "_guard_config", return_value={}), \
             mock.patch.object(guard.sweep.resolution, "resolve_remote",
                               return_value=(["o/r"], "tok", "env")), \
             mock.patch.object(guard.sweep, "latest_saw_guard",
                               return_value=guard.LatestSawGuard("v1")), \
             mock.patch.object(guard.sweep, "drift_one", return_value=outcome), \
             contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            rc = guard.drift_targets(remote=True, slugs=["o/r"], no_stream=True, json_out=json_out)
        return rc, out.getvalue(), err.getvalue()

    def test_a_run_that_could_not_file_an_issue_fails_and_counts_it(self):
        rc, out, _ = self._sweep(guard.DriftOutcome("o/r", "behind", "failed",
                                                    "could not open the drift issue"))
        self.assertNotEqual(rc, 0)
        self.assertIn("1 issue(s) not filed", out)

    def test_a_repository_it_could_not_check_fails_the_run(self):
        rc, _, _ = self._sweep(guard.DriftOutcome("o/r", "error", detail="rate limited"))
        self.assertNotEqual(rc, 0)

    def test_a_stale_pin_with_its_issue_filed_passes(self):
        rc, _, _ = self._sweep(guard.DriftOutcome("o/r", "behind", "opened", "behind", 7))
        self.assertEqual(rc, 0)

    def test_json_reports_each_repository_on_stdout_and_progress_on_stderr(self):
        rc, out, err = self._sweep(guard.DriftOutcome("o/r", "behind", "opened", "behind", 7),
                                   json_out=True)
        self.assertEqual(rc, 0)
        self.assertEqual(json.loads(out), {"schema_version": 1, "results": [
            {"repository": "o/r", "state": "behind", "issue_action": "opened", "issue": 7,
             "detail": "behind"}]})
        self.assertIn("Checked 1 repository", err)

    def test_the_flag_reaches_the_drift_run(self):
        with mock.patch.object(guard, "drift_targets", return_value=0) as drift:
            cli.main(["guard", "drift", "--json"])
        self.assertTrue(drift.call_args.kwargs["json_out"])


if __name__ == "__main__":
    unittest.main()
