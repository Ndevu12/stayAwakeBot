#!/usr/bin/env python3
"""PR submission: slug parsing + duplicate-PR avoidance (no real git/network)."""
from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock


from stayawake.bots.security import pr                              # noqa: E402
from stayawake.bots.security.models import Finding, Severity, ScanResult  # noqa: E402
from stayawake.bots.security.remediation import Change             # noqa: E402


class TestSlug(unittest.TestCase):
    def test_parses_ssh_and_https(self):
        self.assertEqual(pr.slug_from_url("git@github.com:Ndevu12/stayAwakeBot.git"), "Ndevu12/stayAwakeBot")
        self.assertEqual(pr.slug_from_url("https://github.com/Ndevu12/stayAwakeBot"), "Ndevu12/stayAwakeBot")
        self.assertIsNone(pr.slug_from_url("git@gitlab.com:x/y.git"))


def _fake_git(cwd, *args, **kwargs):   # **kwargs tolerates _git(..., env=…) on push
    cp = SimpleNamespace(returncode=0, stdout="", stderr="")
    if args[:2] == ("remote", "get-url"):
        cp.stdout = "git@github.com:owner/repo.git"
    elif args[:1] == ("symbolic-ref",):
        cp.stdout = "refs/remotes/origin/main"
    return cp


class TestNoDuplicatePr(unittest.TestCase):
    def _run(self, existing_pulls):
        finding = Finding("x", "code-loader", Severity.CRITICAL, "postcss.config.mjs",
                          "loader", remediation="strip-appended-payload")
        infected = ScanResult("owner/repo", "local", [finding])
        clean = ScanResult("owner/repo", "local", [])
        # First scan finds the payload; the post-apply re-scan(s) come back clean.
        scans = [infected, clean, clean]
        with mock.patch.object(pr, "_git", side_effect=_fake_git), \
             mock.patch.object(pr, "scan_target",
                               side_effect=lambda *a, **k: scans.pop(0) if scans else clean), \
             mock.patch.object(pr.remediation, "plan",
                               return_value=[Change("strip-payload", "postcss.config.mjs")]), \
             mock.patch.object(pr.remediation, "apply",
                               return_value=[Change("strip-payload", "postcss.config.mjs")]), \
             mock.patch.object(pr.github_api, "list_open_pulls", return_value=existing_pulls), \
             mock.patch.object(pr.github_api, "update_issue", return_value={"number": 7}) as update, \
             mock.patch.object(pr.github_api, "add_labels"), \
             mock.patch.object(pr.github_api, "remove_label"), \
             mock.patch.object(pr.github_api, "create_pull",
                               return_value={"number": 99, "html_url": "u"}) as create:
            outcome = pr.submit_fix_pr(Path("/repo"), object(), {}, [], token="t")
        return outcome, create, update

    def test_opens_pr_when_none_exists(self):
        outcome, create, _ = self._run(existing_pulls=[])
        create.assert_called_once()
        self.assertIn("opened PR #99", outcome)

    def test_updates_not_duplicates_when_pr_open(self):
        outcome, create, update = self._run(existing_pulls=[{"number": 7, "html_url": "u7"}])
        create.assert_not_called()                       # <-- no duplicate PR
        update.assert_called_once()                      # rolling PR body refreshed each run (#1183)
        self.assertIn("updated existing PR #7", outcome)

    def test_aborts_when_nothing_safe_and_payload_survives(self):
        # applied == 0 AND the tree is still infected → NO PR (unchanged: nothing safe to ship).
        finding = Finding("x", "code-loader", Severity.CRITICAL, "evil.cjs",
                          "loader", remediation="strip-appended-payload")
        infected = ScanResult("owner/repo", "local", [finding])
        with mock.patch.object(pr, "_git", side_effect=_fake_git), \
             mock.patch.object(pr, "scan_target", return_value=infected), \
             mock.patch.object(pr.remediation, "plan",
                               return_value=[Change("strip-payload", "evil.cjs")]), \
             mock.patch.object(pr.remediation, "apply", return_value=[]), \
             mock.patch.object(pr.remediation, "quarantine_residual", return_value=[]), \
             mock.patch.object(pr.github_api, "list_open_pulls", return_value=[]), \
             mock.patch.object(pr.github_api, "list_open_issues", return_value=[]), \
             mock.patch.object(pr.github_api, "create_issue",
                               return_value={"number": 9, "html_url": "iu"}), \
             mock.patch.object(pr.github_api, "create_pull") as create:
            outcome = pr.submit_fix_pr(Path("/repo"), object(), {}, [], token="t")
        create.assert_not_called()                         # no fix PR
        self.assertIn("ABORTED", outcome)


class TestPartialFix(unittest.TestCase):
    """#1183: a safe fix is SHIPPED even when a confirmed finding can't be auto-recovered, but the
    tree is never presented as clean — partial PR + label + non-zero exit, residual listed."""

    # A confirmed code-loader (deferred to git-recovery/manual) and a confirmed exfil finding
    # (remediation: manual, NOT a code-loader) — both must count as still-infecting.
    _LOADER = Finding("x", "code-loader", Severity.CRITICAL, "postcss.config.mjs",
                      "loader", remediation="strip-appended-payload")
    _EXFIL = Finding("x", "exfil", Severity.CRITICAL, "telemetry.js",
                     "shai-hulud", remediation="manual")
    _SAFE = Change("strip-gitignore", ".gitignore")

    def _run(self, *, residual, applied=(_SAFE,), existing_pulls=(),
             create_pull_result={"number": 42, "html_url": "u"}):
        # `applied` is what apply() safely applied; `residual` stays infected across every re-scan.
        infected = ScanResult("owner/repo", "local", list(residual))
        with mock.patch.object(pr, "_git", side_effect=_fake_git), \
             mock.patch.object(pr, "scan_target", return_value=infected), \
             mock.patch.object(pr.remediation, "plan", return_value=list(applied)), \
             mock.patch.object(pr.remediation, "apply", return_value=list(applied)), \
             mock.patch.object(pr.remediation, "quarantine_residual", return_value=[]), \
             mock.patch.object(pr.github_api, "list_open_pulls", return_value=list(existing_pulls)), \
             mock.patch.object(pr.github_api, "update_issue", return_value={"number": 7}) as update, \
             mock.patch.object(pr.github_api, "add_labels") as add_labels, \
             mock.patch.object(pr.github_api, "remove_label") as remove_label, \
             mock.patch.object(pr.github_api, "list_open_issues", return_value=[]), \
             mock.patch.object(pr.github_api, "create_issue",
                               return_value={"number": 9, "html_url": "iu"}) as create_issue, \
             mock.patch.object(pr.github_api, "create_pull", return_value=create_pull_result) as create:
            outcome = pr.submit_fix_pr(Path("/repo"), object(), {}, [], token="t")
        return SimpleNamespace(outcome=outcome, create=create, update=update, add_labels=add_labels,
                               remove_label=remove_label, create_issue=create_issue)

    def test_codeloader_residual_ships_partial(self):
        r = self._run(residual=[self._LOADER])
        r.create.assert_called_once()                       # a PR IS opened (not aborted)
        kw = r.create.call_args.kwargs
        self.assertIn("PARTIAL", kw["title"])               # title says partial
        self.assertIn("PARTIAL", kw["body"])
        self.assertIn("postcss.config.mjs", kw["body"])     # the residual is listed
        self.assertIn("strip-gitignore", kw["body"])        # the safe fix is listed as applied
        r.add_labels.assert_called_once()
        self.assertEqual(r.add_labels.call_args.args[3], [pr.PARTIAL_LABEL])
        self.assertIn("PARTIAL", r.outcome)                 # → remediator counts needs-review

    def test_confirmed_non_codeloader_residual_ships_partial(self):
        # Verifier-2 fix: a confirmed exfil (remediation: manual, category != code-loader) must
        # block — never demoted to "suspicious" or "already clean".
        r = self._run(residual=[self._EXFIL])
        r.create.assert_called_once()
        self.assertIn("PARTIAL", r.create.call_args.kwargs["title"])
        self.assertIn("telemetry.js", r.create.call_args.kwargs["body"])
        self.assertIn("PARTIAL", r.outcome)

    def test_confirmed_non_codeloader_alone_files_issue_and_aborts(self):
        # Confirmed exfil ALONE (nothing safely applied) → no PR, but FILE a manual-review issue,
        # then abort (never "already clean"). Gate stays red (outcome carries ABORTED).
        r = self._run(residual=[self._EXFIL], applied=())
        r.create.assert_not_called()                        # no fix PR (nothing to commit)
        r.create_issue.assert_called_once()                 # but a manual-review issue IS filed
        self.assertIn("ABORTED", r.outcome)
        self.assertIn("#9", r.outcome)                      # the filed issue is reported
        self.assertNotIn("already clean", r.outcome)

    def test_nothing_fixable_dedups_issue(self):
        # A re-run with an existing open issue must not open a duplicate (idempotent notify).
        with mock.patch.object(pr, "_git", side_effect=_fake_git), \
             mock.patch.object(pr, "scan_target",
                               return_value=ScanResult("owner/repo", "local", [self._EXFIL])), \
             mock.patch.object(pr.remediation, "plan", return_value=[]), \
             mock.patch.object(pr.remediation, "apply", return_value=[]), \
             mock.patch.object(pr.remediation, "quarantine_residual", return_value=[]), \
             mock.patch.object(pr.github_api, "list_open_issues",
                               return_value=[{"number": 3}]), \
             mock.patch.object(pr.github_api, "create_issue") as create_issue:
            outcome = pr.submit_fix_pr(Path("/repo"), object(), {}, [], token="t")
        create_issue.assert_not_called()                    # existing issue → no duplicate
        self.assertIn("ABORTED", outcome)
        self.assertIn("already tracks", outcome)

    def test_partial_marked_even_when_pr_api_fails_after_push(self):
        # Verifier-1 fix: push succeeds but create_pull returns None → the outcome STILL carries
        # PARTIAL via the single choke point (no fallback path silently passes clean).
        r = self._run(residual=[self._LOADER], create_pull_result=None)
        self.assertIn("PARTIAL", r.outcome)

    def test_partial_updates_existing_pr_idempotently(self):
        r = self._run(residual=[self._LOADER], existing_pulls=[{"number": 7, "html_url": "u7"}])
        r.create.assert_not_called()                        # no duplicate
        r.update.assert_called_once()                       # title/body refreshed each run
        self.assertIn("PARTIAL", r.update.call_args.kwargs["title"])
        r.add_labels.assert_called_once()
        self.assertIn("updated existing PR #7", r.outcome)

    def test_pr_body_neutralizes_injection(self):
        # A malicious path/reason/action cannot inject active Markdown/HTML: every attacker field
        # is _code-wrapped, so dangerous sequences appear ONLY inside code spans, never bare.
        evil = "src/[CLICK](https://evil.example)/x`.js\n## PWNED"
        m = pr.remediation.Manual(
            evil, "s`ig", "residual",
            "run `git checkout abc -- src/[CLICK](https://evil.example)`.js` <img src=x onerror=1> ‮evil",
            1)
        body = pr._pr_body("owner/repo", [Change("strip-gitignore", ".gitignore")], manual=[m])
        # _sanitize turns interior backticks into a look-alike, so spans stay balanced; a
        # single-backtick split alternates OUTSIDE(even)/INSIDE(odd) code spans.
        self.assertEqual(body.count("`") % 2, 0, "unbalanced code spans → a span was left open")
        outside = "".join(body.split("`")[0::2])
        for bad in ("](", "<img", "onerror", "evil.example", "PWNED", "‮"):
            self.assertNotIn(bad, outside, f"{bad!r} injected OUTSIDE a code span")
        self.assertIn("PARTIAL", body)

    def test_issue_body_neutralizes_injection(self):
        # The read-only issue fallback (#1183 invariant #5 covers "PR/issue body") must escape
        # attacker paths/signatures the same way — a backtick is a legal filename char.
        f = Finding("s`ig", "code-loader", Severity.CRITICAL,
                    "app`[CLICK](http://evil.example)`x.js", "d", remediation="strip-appended-payload")
        body = pr._issue_body("owner/repo", [f])
        self.assertEqual(body.count("`") % 2, 0, "unbalanced code spans in the issue body")
        outside = "".join(body.split("`")[0::2])
        for bad in ("](", "evil.example", "<img"):
            self.assertNotIn(bad, outside, f"{bad!r} injected OUTSIDE a code span in the issue body")

    def test_outcome_carries_manual_guidance(self):
        # #1184: the fix outcome (streamed to the operator) includes the per-finding guidance,
        # not just a count — here the notify-only (nothing-fixable) abort.
        r = self._run(residual=[self._EXFIL], applied=())
        self.assertIn("Manual review needed", r.outcome)
        self.assertIn("telemetry.js", r.outcome)


class TestManualReviewGuidance(unittest.TestCase):
    """#1184: per-finding manual-review guidance for the CLI stream — location + reason + the
    inspect-before-running command, safely (no injection), bounded, payload-free."""

    def _m(self, path, reason="legit-changes",
           action="recover yourself and review: `git checkout abc1234 -- p`.", line=5):
        return pr.remediation.Manual(path, "sig", reason, action, line)

    def test_surfaces_location_reason_command(self):
        block = pr.manual_review_lines([self._m("postcss.config.mjs")])
        self.assertIn("postcss.config.mjs:5", block)     # location
        self.assertIn("legit-changes", block)            # reason code
        self.assertIn("git checkout abc1234", block)     # the recommended command

    def test_all_reason_codes_render(self):
        from stayawake.bots.security.models import (
            LEGIT_CHANGES, BORN_INFECTED, UNTRACKED, NO_VCS, INTRINSIC_MATCH, INSPECT_FAILED)
        ms = [self._m(f"f{i}.js", reason=r, action=f"do {r}")
              for i, r in enumerate((LEGIT_CHANGES, BORN_INFECTED, UNTRACKED, NO_VCS,
                                     INTRINSIC_MATCH, INSPECT_FAILED))]
        block = pr.manual_review_lines(ms)
        for r in (LEGIT_CHANGES, BORN_INFECTED, UNTRACKED, NO_VCS, INTRINSIC_MATCH, INSPECT_FAILED):
            self.assertIn(r, block)

    def test_neutralizes_injection(self):
        # A crafted path/action with newlines + BOTH Actions workflow-command forms (`::cmd::`, which
        # the runner parses at line-start, and the legacy `##[cmd]`, matched ANYWHERE) + bidi must not
        # survive as an interpretable command.
        block = pr.manual_review_lines([self._m(
            "x\n::error::pwn‮.js##[group]", action="a\r##[set-output name=x] ::warning::z")])
        self.assertNotIn("##[", block)                    # legacy ##[cmd] (IndexOf anywhere) defanged
        for ln in block.splitlines():
            self.assertFalse(ln.lstrip().startswith("::"), f"::cmd injection: {ln!r}")

    def test_bounded(self):
        block = pr.manual_review_lines([self._m(f"f{i}.js") for i in range(40)], limit=10)
        self.assertIn("…and 30 more", block)

    def test_empty_for_no_residual(self):
        self.assertEqual(pr.manual_review_lines([]), "")


class TestReadOnlyFallback(unittest.TestCase):
    """When the fix branch can't be pushed (no write access), the remediation ladder
    must still produce something: a patch artifact AND a de-duplicated notify issue."""

    def _run(self, existing_issues, out):
        finding = Finding("x", "code-loader", Severity.CRITICAL, "postcss.config.mjs",
                          "loader", remediation="strip-appended-payload")
        scans = [ScanResult("owner/repo", "local", [finding]),   # worktree scan: infected
                 ScanResult("owner/repo", "local", []),          # post-apply re-scan: clean
                 ScanResult("owner/repo", "local", [])]

        def fake_git(cwd, *args, **kwargs):   # **kwargs tolerates _git(..., env=…) on push
            cp = SimpleNamespace(returncode=0, stdout="", stderr="")
            if args[:2] == ("remote", "get-url"):
                cp.stdout = "git@github.com:owner/repo.git"
            elif args[:1] == ("symbolic-ref",):
                cp.stdout = "refs/remotes/origin/main"
            elif args[:1] == ("push",):
                cp.returncode = 1                       # <-- read-only: push rejected
            elif args[:1] == ("format-patch",):
                cp.stdout = "From abc\nSubject: fix\n\npatch-body\n"
            return cp

        with mock.patch.object(pr, "_git", side_effect=fake_git), \
             mock.patch.object(pr, "scan_target",
                               side_effect=lambda *a, **k: scans.pop(0) if scans else scans), \
             mock.patch.object(pr.remediation, "plan",
                               return_value=[Change("strip-payload", "postcss.config.mjs")]), \
             mock.patch.object(pr.remediation, "apply",
                               return_value=[Change("strip-payload", "postcss.config.mjs")]), \
             mock.patch.object(pr.github_api, "get_authenticated_user", return_value=None), \
             mock.patch.object(pr.github_api, "list_open_pulls", return_value=[]), \
             mock.patch.object(pr.github_api, "create_pull") as create_pull, \
             mock.patch.object(pr.github_api, "list_open_issues", return_value=existing_issues), \
             mock.patch.object(pr.github_api, "create_issue",
                               return_value={"number": 5, "html_url": "iu"}) as create_issue:
            outcome = pr.submit_fix_pr(Path("/repo"), object(), {}, [], token="t",
                                       patches_dir=out)
        return outcome, create_pull, create_issue

    def test_saves_patch_and_opens_issue(self):
        out = Path(tempfile.mkdtemp())
        outcome, create_pull, create_issue = self._run([], out)
        create_pull.assert_not_called()                  # no PR opened
        create_issue.assert_called_once()                # notify issue opened
        self.assertIn("patch", outcome.lower())
        self.assertIn("issue #5", outcome)
        patch_file = out / "owner-repo.patch"
        self.assertTrue(patch_file.is_file(), "fix must be saved as a patch on push failure")
        self.assertIn("patch-body", patch_file.read_text(encoding="utf-8"))

    def test_issue_is_deduplicated(self):
        out = Path(tempfile.mkdtemp())
        outcome, _, create_issue = self._run([{"number": 9}], out)
        create_issue.assert_not_called()                 # an open issue exists ⇒ no duplicate
        self.assertIn("#9", outcome)


class TestForkPr(unittest.TestCase):
    """Fork → cross-fork PR rung: when we can't push to upstream but can fork, push the
    fix to a fork under the authenticated user and open a cross-fork PR. All edge cases
    fall through to the patch/issue floor."""

    def _run(self, *, user=None, fork=None, repo_ready=True, fork_push_ok=True,
             existing_fork_pulls=None, created_pr=None):
        finding = Finding("x", "code-loader", Severity.CRITICAL, "postcss.config.mjs",
                          "loader", remediation="strip-appended-payload")
        scans = [ScanResult("up/repo", "local", [finding]),
                 ScanResult("up/repo", "local", []),
                 ScanResult("up/repo", "local", [])]

        def fake_git(cwd, *args, **kwargs):
            cp = SimpleNamespace(returncode=0, stdout="", stderr="")
            if args[:2] == ("remote", "get-url"):
                cp.stdout = "git@github.com:up/repo.git"
            elif args[:1] == ("symbolic-ref",):
                cp.stdout = "refs/remotes/origin/main"
            elif args[:1] == ("push",):
                url = next((a for a in args if ".git" in a), "")
                if "up/repo.git" in url:
                    cp.returncode = 1                    # upstream push rejected (no write)
                else:
                    cp.returncode = 0 if fork_push_ok else 1   # push to the fork
            elif args[:1] == ("format-patch",):
                cp.stdout = "patch-body\n"
            return cp

        out = Path(tempfile.mkdtemp())
        with mock.patch.object(pr, "_git", side_effect=fake_git), \
             mock.patch.object(pr.time, "sleep", return_value=None), \
             mock.patch.object(pr, "scan_target",
                               side_effect=lambda *a, **k: scans.pop(0) if scans else scans), \
             mock.patch.object(pr.remediation, "plan",
                               return_value=[Change("strip-payload", "postcss.config.mjs")]), \
             mock.patch.object(pr.remediation, "apply",
                               return_value=[Change("strip-payload", "postcss.config.mjs")]), \
             mock.patch.object(pr.github_api, "get_authenticated_user", return_value=user), \
             mock.patch.object(pr.github_api, "create_fork", return_value=fork), \
             mock.patch.object(pr.github_api, "get_repo",
                               return_value=({"x": 1} if repo_ready else None)), \
             mock.patch.object(pr.github_api, "list_open_pulls",
                               return_value=existing_fork_pulls or []), \
             mock.patch.object(pr.github_api, "create_pull", return_value=created_pr) as create_pull, \
             mock.patch.object(pr.github_api, "update_issue", return_value={"number": 1}), \
             mock.patch.object(pr.github_api, "add_labels"), \
             mock.patch.object(pr.github_api, "remove_label"), \
             mock.patch.object(pr.github_api, "list_open_issues", return_value=[]), \
             mock.patch.object(pr.github_api, "create_issue",
                               return_value={"number": 1, "html_url": "iu"}) as create_issue:
            outcome = pr.submit_fix_pr(Path("/repo"), object(), {}, [], token="t", patches_dir=out)
        return outcome, create_pull, create_issue, out

    def test_opens_cross_fork_pr(self):
        outcome, create_pull, create_issue, _ = self._run(
            user={"login": "me"}, fork={"full_name": "me/repo"},
            created_pr={"number": 11, "html_url": "fu"})
        self.assertIn("opened fork PR #11", outcome)
        create_pull.assert_called_once()
        self.assertEqual(create_pull.call_args.kwargs["head"], "me:security/auto-clean")
        create_issue.assert_not_called()                 # fork PR succeeded → no issue floor

    def test_dedup_existing_fork_pr(self):
        outcome, create_pull, _, _ = self._run(
            user={"login": "me"}, fork={"full_name": "me/repo"},
            existing_fork_pulls=[{"number": 4, "html_url": "fu"}])
        create_pull.assert_not_called()                  # already an open fork PR
        self.assertIn("updated existing fork PR #4", outcome)

    def test_own_repo_falls_back_to_floor(self):
        # token belongs to the upstream owner → a fork is pointless → patch/issue floor
        outcome, create_pull, create_issue, out = self._run(
            user={"login": "up"}, fork={"full_name": "up/repo"})
        create_pull.assert_not_called()
        create_issue.assert_called_once()
        self.assertTrue((out / "up-repo.patch").is_file())

    def test_cannot_fork_falls_back_to_floor(self):
        outcome, _, create_issue, out = self._run(user={"login": "me"}, fork=None)
        create_issue.assert_called_once()                # forking not permitted → floor
        self.assertTrue((out / "up-repo.patch").is_file())

    def test_fork_not_ready_reports_retry(self):
        outcome, create_pull, create_issue, _ = self._run(
            user={"login": "me"}, fork={"full_name": "me/repo"}, repo_ready=False)
        self.assertIn("wasn't ready", outcome)
        create_pull.assert_not_called()
        create_issue.assert_not_called()                 # reported; not the floor

    def test_fork_push_failure_falls_back_to_floor(self):
        outcome, _, create_issue, out = self._run(
            user={"login": "me"}, fork={"full_name": "me/repo"}, fork_push_ok=False)
        create_issue.assert_called_once()                # couldn't push to fork → floor
        self.assertTrue((out / "up-repo.patch").is_file())


if __name__ == "__main__":
    unittest.main()
