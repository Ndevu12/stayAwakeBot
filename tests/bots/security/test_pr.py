#!/usr/bin/env python3
"""PR submission: slug parsing + duplicate-PR avoidance (no real git/network).

Git is faked at the TYPED-helper seam (`pr.gitutil.*`) — `commit_fix` returns a `CommitResult`,
`push_branch` a bool, etc. — not at a raw-subprocess boundary. `_patch_git` installs sensible
defaults so a test only names the behaviour it cares about (a push that fails, a slug)."""
from __future__ import annotations

import contextlib
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock


from stayawake.bots.security import pr                              # noqa: E402
from stayawake.core import proposal                        # noqa: E402
from stayawake.bots.security.models import Finding, Severity, ScanResult  # noqa: E402
from stayawake.bots.security.remediation import Change             # noqa: E402
from stayawake.lib.git.write.commit import CommitResult          # noqa: E402
from stayawake.lib.git.write.push import PushResult              # noqa: E402


# Default behaviour for every typed git helper `_build_fix`/`submit_fix_pr` touch: the happy
# path (a real repo with a clean origin, a signed commit that lands, a push that succeeds).
def _git_defaults() -> dict:
    return dict(
        origin_slug=lambda repo: "owner/repo",
        default_branch=lambda repo: "main",
        ref_exists=lambda repo, ref: True,
        add_worktree=lambda repo, path, branch, baseref: True,
        remove_worktree=lambda repo, path: True,
        stage_all=lambda repo: True,
        unstage_cached=lambda repo, spec: True,
        tracked_under=lambda repo, spec: [],
        fetch=lambda repo, remote, ref: True,
        commit_fix=lambda repo, msg: CommitResult(committed=True, signed=True),
        format_patch=lambda repo, ref="HEAD": None,
        push_branch=lambda repo, slug, branch, token, **kw: True,
    )


@contextlib.contextmanager
def _patch_git(**overrides):
    """Patch pr.gitutil's typed helpers with the happy-path defaults, plus any overrides.

    `push_branch` overrides are auto-wrapped into `push_branch_result` (PushResult) so AuthZ
    classification tests keep the old bool seam.
    """
    cfg = {**_git_defaults(), **overrides}
    push_fn = cfg.get("push_branch")

    def _as_result(repo, slug, branch, token, **kw):
        ok = bool(push_fn(repo, slug, branch, token, **kw)) if push_fn else True
        return PushResult(ok, "" if ok else "mocked push failure")

    cfg.setdefault("push_branch_result", _as_result)
    with contextlib.ExitStack() as stack:
        for name, fn in cfg.items():
            stack.enter_context(mock.patch.object(pr.gitutil, name, fn))
        yield


class TestSlug(unittest.TestCase):
    def test_parses_ssh_and_https(self):
        # slug parsing now lives in core.git.query (flat-exported); pr reaches it via gitutil.
        self.assertEqual(pr.gitutil.slug_from_url("git@github.com:Ndevu12/stayAwakeBot.git"),
                         "Ndevu12/stayAwakeBot")
        self.assertEqual(pr.gitutil.slug_from_url("https://github.com/Ndevu12/stayAwakeBot"),
                         "Ndevu12/stayAwakeBot")
        self.assertIsNone(pr.gitutil.slug_from_url("git@gitlab.com:x/y.git"))


class TestNoDuplicatePr(unittest.TestCase):
    def _run(self, existing_pulls):
        finding = Finding("x", "code-loader", Severity.CRITICAL, "postcss.config.mjs",
                          "loader", remediation="strip-appended-payload")
        infected = ScanResult("owner/repo", "local", [finding])
        clean = ScanResult("owner/repo", "local", [])
        # First scan finds the payload; the post-apply re-scan(s) come back clean.
        scans = [infected, clean, clean]
        with _patch_git(), \
             mock.patch.object(pr.fix, "scan_target",
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
        with _patch_git(), \
             mock.patch.object(pr.fix, "scan_target", return_value=infected), \
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
    # A confirmed evil-merge (#1360 PR2): keyed to a merge SHA (path), with the introduced files in
    # `related_paths` — history guidance always names the commit; working-tree recovery is a
    # separate act keyed to those files when they still carry the payload.
    _EVIL_MERGE = Finding("evil-merge-loader", "evil-merge", Severity.CRITICAL, "96dcbd397c",
                          "smuggled loader", remediation="manual", vector="evil-merge",
                          related_paths=("tailwind.config.js",), commit_sha="96dcbd397c")
    _SAFE = Change("strip-gitignore", ".gitignore")

    def _run(self, *, residual, applied=(_SAFE,), existing_pulls=(),
             create_pull_result={"number": 42, "html_url": "u"}):
        # `applied` is what apply() safely applied; `residual` stays infected across every re-scan.
        infected = ScanResult("owner/repo", "local", list(residual))
        with _patch_git(), \
             mock.patch.object(pr.fix, "scan_target", return_value=infected), \
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

    def test_evil_merge_gets_history_provenance_guidance(self):
        # A confirmed evil-merge is keyed to a merge COMMIT, not a file — the generic "remove/recover
        # manually" is nonsensical. It must get history-provenance guidance: name the SHA + files and
        # state that `saw fix` never rewrites history (a maintainer decision). Liveness is UNKNOWN
        # here (no real merge in the fake worktree), so it must not claim the tree is clean.
        r = self._run(residual=[self._EVIL_MERGE], applied=())
        self.assertIn("ABORTED", r.outcome)                     # confirmed → needs-review, exit 1
        self.assertIn("96dcbd397c", r.outcome)                  # location is the merge SHA
        self.assertIn("tailwind.config.js", r.outcome)          # the introduced file is named
        self.assertIn("never rewrites history", r.outcome)      # the load-bearing safety guidance
        self.assertNotIn("remove/recover manually", r.outcome)  # NOT the generic file action
        self.assertIn("do not treat the tree as clean", r.outcome)
        self.assertNotIn("the tree is clean but the commit persists", r.outcome)

    def test_evil_merge_gone_from_tree_is_history_only(self):
        from stayawake.lib.git.merge.liveness import GONE
        with mock.patch.object(pr.fix, "introduced_liveness", return_value=GONE), \
             mock.patch.object(pr.remediation, "classify_recovery") as classify:
            r = self._run(residual=[self._EVIL_MERGE], applied=())
        classify.assert_not_called()
        self.assertIn("ABORTED", r.outcome)
        self.assertIn("96dcbd397c", r.outcome)
        self.assertIn("tailwind.config.js", r.outcome)
        self.assertIn("never rewrites history", r.outcome)
        self.assertIn("the tree is clean but the commit persists", r.outcome)

    def test_evil_merge_changed_file_is_not_rewritten(self):
        from stayawake.lib.git.merge.liveness import CHANGED
        with mock.patch.object(pr.fix, "introduced_liveness", return_value=CHANGED), \
             mock.patch.object(pr.remediation, "classify_recovery") as classify:
            r = self._run(residual=[self._EVIL_MERGE], applied=())
        classify.assert_not_called()
        self.assertIn("ABORTED", r.outcome)
        self.assertIn("do not treat the tree as clean", r.outcome)
        self.assertNotIn("the tree is clean but the commit persists", r.outcome)

    def test_evil_merge_live_file_is_offered_on_the_review_branch(self):
        # When the introduced file still carries the payload, `saw fix` must recover that file
        # onto the review branch — not report a history-only "tree is clean".
        from stayawake.lib.git.merge.liveness import PRESENT
        sug = pr.remediation.Suggested(
            "tailwind.config.js", "evil-merge-loader", "merge-clean-recovered",
            "review the restored file before merging", "diff", "clean\n", 1, apply_mode="restore")
        infected = ScanResult("owner/repo", "local", [self._EVIL_MERGE])
        with _patch_git(), \
             mock.patch.object(pr.fix, "scan_target", return_value=infected), \
             mock.patch.object(pr.fix, "introduced_liveness", return_value=PRESENT), \
             mock.patch.object(pr.remediation, "plan", return_value=[]), \
             mock.patch.object(pr.remediation, "apply", return_value=[]), \
             mock.patch.object(pr.remediation, "quarantine_residual", return_value=[]), \
             mock.patch.object(pr.remediation, "classify_recovery", return_value=sug) as classify, \
             mock.patch.object(pr.remediation, "apply_suggested", return_value=True) as applyer, \
             mock.patch.object(pr.github_api, "list_open_pulls", return_value=[]), \
             mock.patch.object(pr.github_api, "add_labels"), \
             mock.patch.object(pr.github_api, "remove_label"), \
             mock.patch.object(pr.github_api, "list_open_issues", return_value=[]), \
             mock.patch.object(pr.github_api, "create_issue",
                               return_value={"number": 9, "html_url": "iu"}), \
             mock.patch.object(pr.github_api, "create_pull",
                               return_value={"number": 55, "html_url": "u"}) as create:
            outcome = pr.submit_fix_pr(Path("/repo"), object(), {}, [], token="t")
        classify.assert_called()
        self.assertEqual(classify.call_args.args[1].path, "tailwind.config.js")
        applyer.assert_called_once()
        create.assert_called_once()
        body = create.call_args.kwargs["body"]
        self.assertIn("PARTIAL", outcome)
        self.assertIn("tailwind.config.js", outcome)
        self.assertIn("96dcbd397c", body)
        self.assertIn("still carries it in the working tree", body)
        self.assertNotIn("the tree is clean but the commit persists", body)
        self.assertIn("never rewrites history", body)

    def test_heuristic_evil_merge_live_file_is_offered_for_review(self):
        # Heuristic grade on the merge does not skip recovering a live introduced file; the
        # restore is review-required, never a trusted auto-apply.
        from stayawake.lib.git.merge.liveness import PRESENT
        heuristic = Finding("evil-merge", "evil-merge", Severity.HIGH, "96dcbd397c",
                            "smuggled loader", remediation="manual", vector="evil-merge",
                            confidence="heuristic", related_paths=("postcss.config.mjs",),
                            commit_sha="96dcbd397c")
        sug = pr.remediation.Suggested(
            "postcss.config.mjs", "evil-merge", "merge-clean-recovered",
            "review the restored file before merging", "diff", "clean\n", 1, apply_mode="restore")
        infected = ScanResult("owner/repo", "local", [heuristic])
        with _patch_git(), \
             mock.patch.object(pr.fix, "scan_target", return_value=infected), \
             mock.patch.object(pr.fix, "introduced_liveness", return_value=PRESENT), \
             mock.patch.object(pr.remediation, "plan", return_value=[]), \
             mock.patch.object(pr.remediation, "apply", return_value=[]), \
             mock.patch.object(pr.remediation, "quarantine_residual", return_value=[]), \
             mock.patch.object(pr.remediation, "classify_recovery", return_value=sug) as classify, \
             mock.patch.object(pr.remediation, "apply_suggested", return_value=True) as applyer, \
             mock.patch.object(pr.github_api, "list_open_pulls", return_value=[]), \
             mock.patch.object(pr.github_api, "add_labels"), \
             mock.patch.object(pr.github_api, "remove_label"), \
             mock.patch.object(pr.github_api, "create_issue"), \
             mock.patch.object(pr.github_api, "create_pull",
                               return_value={"number": 55, "html_url": "u"}) as create:
            outcome = pr.submit_fix_pr(Path("/repo"), object(), {}, [], token="t")
        classify.assert_called()
        self.assertEqual(classify.call_args.args[1].path, "postcss.config.mjs")
        applyer.assert_called_once()
        create.assert_called_once()
        self.assertIn("PARTIAL", outcome)
        self.assertIn("postcss.config.mjs", outcome)

    def test_evil_merge_history_note_survives_a_clean_rescan(self):
        # Restoring the live file can make a later scan look clean; the merge commit is still
        # there and the operator must still be told `saw fix` never rewrites history.
        from stayawake.lib.git.merge.liveness import PRESENT
        sug = pr.remediation.Suggested(
            "tailwind.config.js", "evil-merge-loader", "merge-clean-recovered",
            "review the restored file before merging", "diff", "clean\n", 1, apply_mode="restore")
        infected = ScanResult("owner/repo", "local", [self._EVIL_MERGE])
        clean = ScanResult("owner/repo", "local", [])
        scans = [infected, infected, clean]
        with _patch_git(), \
             mock.patch.object(pr.fix, "scan_target",
                               side_effect=lambda *a, **k: scans.pop(0) if scans else clean), \
             mock.patch.object(pr.fix, "introduced_liveness", return_value=PRESENT), \
             mock.patch.object(pr.remediation, "plan", return_value=[]), \
             mock.patch.object(pr.remediation, "apply", return_value=[]), \
             mock.patch.object(pr.remediation, "quarantine_residual", return_value=[]), \
             mock.patch.object(pr.remediation, "classify_recovery", return_value=sug), \
             mock.patch.object(pr.remediation, "apply_suggested", return_value=True), \
             mock.patch.object(pr.github_api, "list_open_pulls", return_value=[]), \
             mock.patch.object(pr.github_api, "add_labels"), \
             mock.patch.object(pr.github_api, "remove_label"), \
             mock.patch.object(pr.github_api, "list_open_issues", return_value=[]), \
             mock.patch.object(pr.github_api, "create_issue"), \
             mock.patch.object(pr.github_api, "create_pull",
                               return_value={"number": 55, "html_url": "u"}) as create:
            outcome = pr.submit_fix_pr(Path("/repo"), object(), {}, [], token="t")
        body = create.call_args.kwargs["body"]
        self.assertIn("PARTIAL", outcome)
        self.assertIn("96dcbd397c", body)
        self.assertIn("never rewrites history", body)

    def test_failed_merge_restore_does_not_block_file_recovery(self):
        # A live merge file that cannot be restored from the merge must not prevent a
        # first-parent recovery of the same path (the file is also a code-loader finding).
        from stayawake.lib.git.merge.liveness import PRESENT
        loader = Finding("x", "code-loader", Severity.CRITICAL, "tailwind.config.js",
                         "loader", remediation="strip-appended-payload")
        merge_manual = pr.remediation.Manual(
            "tailwind.config.js", "evil-merge-loader", "born-infected", "no merge parent")
        rec = pr.remediation.Recovery(
            "tailwind.config.js", "abc1234", "clean", "diff", "clean\n")

        def classify(_wt, finding, *_a, **_k):
            if getattr(finding, "vector", None) == "evil-merge":
                return merge_manual
            return rec

        infected = ScanResult("owner/repo", "local", [self._EVIL_MERGE, loader])
        with _patch_git(), \
             mock.patch.object(pr.fix, "scan_target", return_value=infected), \
             mock.patch.object(pr.fix, "introduced_liveness", return_value=PRESENT), \
             mock.patch.object(pr.remediation, "plan", return_value=[]), \
             mock.patch.object(pr.remediation, "apply", return_value=[]), \
             mock.patch.object(pr.remediation, "quarantine_residual", return_value=[]), \
             mock.patch.object(pr.remediation, "classify_recovery", side_effect=classify), \
             mock.patch.object(pr.remediation, "apply_recovery", return_value=True) as recover, \
             mock.patch.object(pr.github_api, "list_open_pulls", return_value=[]), \
             mock.patch.object(pr.github_api, "add_labels"), \
             mock.patch.object(pr.github_api, "remove_label"), \
             mock.patch.object(pr.github_api, "list_open_issues", return_value=[]), \
             mock.patch.object(pr.github_api, "create_issue",
                               return_value={"number": 9, "html_url": "iu"}), \
             mock.patch.object(pr.github_api, "create_pull",
                               return_value={"number": 55, "html_url": "u"}):
            pr.submit_fix_pr(Path("/repo"), object(), {}, [], token="t")
        recover.assert_called_once()
        self.assertEqual(recover.call_args.args[1].path, "tailwind.config.js")

    def test_nothing_fixable_dedups_issue(self):
        # A re-run with an existing open issue must not open a duplicate (idempotent notify).
        with _patch_git(), \
             mock.patch.object(pr.fix, "scan_target",
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

    def test_computed_strip_ships_partial_review_required(self):
        # #1209 (Option B): a code-loader with no git ancestor → a computed Suggested strip that IS
        # applied (a separate commit) but is NOT git-corroborated. The PR is OPENED (computed is
        # shippable, not aborted), marked PARTIAL, carries the review-required section, and the
        # outcome carries PARTIAL so the run counts as needs-review until a human reviews & merges.
        infected = ScanResult("owner/repo", "local", [self._LOADER])
        clean = ScanResult("owner/repo", "local", [])
        # scans: initial (loader found) → trusted-tier quarantine rescan (clean, nothing auto-fixable)
        # → final residual rescan AFTER the computed strip is applied (clean).
        scans = [infected, clean, clean]
        sug = pr.remediation.Suggested("postcss.config.mjs", "loader", pr.remediation.NO_VCS,
                                       "review the kept code before merging", "diff", "clean\n", 1)
        with _patch_git(), \
             mock.patch.object(pr.fix, "scan_target",
                               side_effect=lambda *a, **k: scans.pop(0) if scans else clean), \
             mock.patch.object(pr.remediation, "plan", return_value=[]), \
             mock.patch.object(pr.remediation, "apply", return_value=[]), \
             mock.patch.object(pr.remediation, "quarantine_residual", return_value=[]), \
             mock.patch.object(pr.remediation, "classify_recovery", return_value=sug), \
             mock.patch.object(pr.remediation, "apply_suggested", return_value=True) as applyer, \
             mock.patch.object(pr.github_api, "list_open_pulls", return_value=[]), \
             mock.patch.object(pr.github_api, "add_labels") as add_labels, \
             mock.patch.object(pr.github_api, "remove_label"), \
             mock.patch.object(pr.github_api, "list_open_issues", return_value=[]), \
             mock.patch.object(pr.github_api, "create_issue", return_value={"number": 9, "html_url": "iu"}), \
             mock.patch.object(pr.github_api, "create_pull",
                               return_value={"number": 55, "html_url": "u"}) as create:
            outcome = pr.submit_fix_pr(Path("/repo"), object(), {}, [], token="t")
        applyer.assert_called_once()                            # the computed strip WAS applied
        create.assert_called_once()                             # a PR IS opened (computed is shippable)
        kw = create.call_args.kwargs
        self.assertIn("PARTIAL", kw["title"])                  # not a trusted-clean fix
        self.assertIn("Computed strip applied", kw["body"])    # the review-required section
        self.assertIn("postcss.config.mjs", kw["body"])
        add_labels.assert_called_once()                        # partial label applied
        self.assertIn("PARTIAL", outcome)                      # → remediator counts needs-review

    def test_pr_body_neutralizes_injection(self):
        # A malicious path/reason/action cannot inject active Markdown/HTML: every attacker field
        # is _code-wrapped, so dangerous sequences appear ONLY inside code spans, never bare.
        evil = "src/[CLICK](https://evil.example)/x`.js\n## PWNED"
        m = pr.remediation.Manual(
            evil, "s`ig", "residual",
            "run `git checkout abc -- src/[CLICK](https://evil.example)`.js` <img src=x onerror=1> ‮evil",
            1)
        body = pr.render._pr_body("owner/repo", [Change("strip-gitignore", ".gitignore")], manual=[m])
        # _sanitize turns interior backticks into a look-alike, so spans stay balanced; a
        # single-backtick split alternates OUTSIDE(even)/INSIDE(odd) code spans.
        self.assertEqual(body.count("`") % 2, 0, "unbalanced code spans → a span was left open")
        outside = "".join(body.split("`")[0::2])
        for bad in ("](", "<img", "onerror", "evil.example", "PWNED", "‮"):
            self.assertNotIn(bad, outside, f"{bad!r} injected OUTSIDE a code span")
        self.assertIn("PARTIAL", body)

    def test_pr_body_renders_computed_strip_applied(self):
        # #1209 (Option B): a computed strip that WAS applied on the branch (a separate commit)
        # renders in its own "Computed strip applied — REVIEW before merging" section, distinct from
        # the manual checklist, with location + reason + the review guidance. The tree stays PARTIAL
        # (not git-corroborated) so a human must review before merge.
        sug = pr.remediation.Suggested(
            "next.config.mjs", "loader-fromcharcode-127", pr.remediation.NO_VCS,
            "saw applied a computed payload-only strip to the review branch…",
            "diff-preview", "export default config;\n", 1)
        body = pr.render._pr_body("owner/repo", [Change("strip-gitignore", ".gitignore")], computed=[sug])
        self.assertIn("Computed strip applied", body)
        self.assertIn("concealment seam", body)                        # tells the operator where/how
        self.assertIn("next.config.mjs:1", body)
        self.assertIn("PARTIAL", body)                                 # not git-corroborated → review

    def test_pr_body_computed_strip_is_injection_safe(self):
        # A computed strip from a crafted path/reason/action cannot inject active Markdown/HTML —
        # same code-span discipline as the manual list: every attacker field is `textsafe.code`-
        # wrapped, and no raw diff is embedded in the body (it lives in the commit).
        sug = pr.remediation.Suggested(
            "src/[X](http://evil.example)`.js", "s`ig", pr.remediation.LEGIT_CHANGES,
            "run `x` <img src=x onerror=1> ‮evil [CLICK](http://evil.example)", "d", "x", 2)
        body = pr.render._pr_body("owner/repo", [Change("recover", "a.mjs")], computed=[sug])
        self.assertEqual(body.count("`") % 2, 0, "unbalanced code spans → a span was left open")
        outside = "".join(body.split("`")[0::2])
        for bad in ("](", "<img", "onerror", "evil.example", "‮"):
            self.assertNotIn(bad, outside, f"{bad!r} injected OUTSIDE a code span")

    def test_issue_body_neutralizes_injection(self):
        # The read-only issue fallback (#1183 invariant #5 covers "PR/issue body") must escape
        # attacker paths/signatures the same way — a backtick is a legal filename char.
        f = Finding("s`ig", "code-loader", Severity.CRITICAL,
                    "app`[CLICK](http://evil.example)`x.js", "d", remediation="strip-appended-payload")
        body = pr.render._issue_body("owner/repo", [f])
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


class TestSigningWarning(unittest.TestCase):
    """The saw-fix signing fix: when the fix commit can't be signed in the worktree, commit_fix
    lands it UNSIGNED (never a phantom empty branch) and the outcome carries a ⚠ warning."""

    _SAFE = Change("strip-gitignore", ".gitignore")

    def _run_pr(self, commit_result):
        clean = ScanResult("owner/repo", "local", [])
        scans = [ScanResult("owner/repo", "local", []), clean, clean]
        with _patch_git(commit_fix=lambda repo, msg: commit_result), \
             mock.patch.object(pr.fix, "scan_target",
                               side_effect=lambda *a, **k: scans.pop(0) if scans else clean), \
             mock.patch.object(pr.remediation, "plan", return_value=[self._SAFE]), \
             mock.patch.object(pr.remediation, "apply", return_value=[self._SAFE]), \
             mock.patch.object(pr.github_api, "list_open_pulls", return_value=[]), \
             mock.patch.object(pr.github_api, "add_labels"), \
             mock.patch.object(pr.github_api, "remove_label"), \
             mock.patch.object(pr.github_api, "create_pull",
                               return_value={"number": 5, "html_url": "u"}):
            return pr.submit_fix_pr(Path("/repo"), object(), {}, [], token="t")

    def test_unsigned_commit_warns_but_still_opens_pr(self):
        outcome = self._run_pr(CommitResult(committed=True, signed=False))
        self.assertIn("opened PR #5", outcome)              # the fix DID land + PR opened
        self.assertIn("UNSIGNED", outcome)                  # …but the operator is warned

    def test_signed_commit_no_warning(self):
        outcome = self._run_pr(CommitResult(committed=True, signed=True))
        self.assertIn("opened PR #5", outcome)
        self.assertNotIn("UNSIGNED", outcome)

    def test_commit_failure_aborts_no_phantom_branch(self):
        # Even the unsigned retry failed → NOTHING is reported as prepared; the run aborts.
        outcome = self._run_pr(CommitResult(committed=False, signed=False))
        self.assertNotIn("opened PR", outcome)
        self.assertIn("could not commit", outcome)

    def test_prepare_fix_warns_on_unsigned(self):
        # `saw fix` (local, no push): the ⚠ note reaches the operator who will push manually.
        clean = ScanResult("owner/repo", "local", [])
        scans = [ScanResult("owner/repo", "local", []), clean, clean]
        with _patch_git(commit_fix=lambda repo, msg: CommitResult(committed=True, signed=False)), \
             mock.patch.object(pr.fix, "scan_target",
                               side_effect=lambda *a, **k: scans.pop(0) if scans else clean), \
             mock.patch.object(pr.remediation, "plan", return_value=[self._SAFE]), \
             mock.patch.object(pr.remediation, "apply", return_value=[self._SAFE]):
            outcome = pr.prepare_fix(Path("/repo"), object(), {}, [])
        self.assertIn("prepared 1 change", outcome)
        self.assertIn("UNSIGNED", outcome)


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
        with _patch_git(push_branch=lambda repo, slug, branch, token, **kw: False,   # read-only
                        format_patch=lambda repo, ref="HEAD": "From abc\nSubject: fix\n\npatch-body\n"), \
             mock.patch.object(pr.fix, "scan_target",
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

        # Upstream push (slug 'up/repo') is rejected; the fork push succeeds iff fork_push_ok.
        def fake_push(repo, slug, branch, token, **kw):
            return slug != "up/repo" and fork_push_ok

        out = Path(tempfile.mkdtemp())
        with _patch_git(origin_slug=lambda repo: "up/repo", push_branch=fake_push,
                        format_patch=lambda repo, ref="HEAD": "patch-body\n"), \
             mock.patch.object(proposal.time, "sleep", return_value=None), \
             mock.patch.object(pr.fix, "scan_target",
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
        self.assertEqual(create_pull.call_args.kwargs["head"], "me:security/auto-clean-main")
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


class TestFixPartialInvariant(unittest.TestCase):
    """Pin the load-bearing `_Fix.partial` tripwire (#1209/#1290) directly at the property, where a
    future simplifier edits — a small unit guard beside the end-to-end
    `test_computed_strip_ships_partial_review_required`. `partial` MUST stay
    `bool(manual) OR bool(computed)`: after a computed strip the post-strip rescan can report the tree
    CLEAN (empty `manual`), so a reduction to `bool(manual)` would let a not-git-corroborated tree go
    green (exit 0). These cases fail if the `computed` arm is ever dropped."""

    def _fix(self, *, computed=(), manual=()):
        return pr.fix._Fix(base="main", branch="security/auto-clean-main",
                           applied=[], computed=computed, manual=manual)

    def test_computed_only_is_partial_even_when_manual_empty(self):
        # THE tripwire: rescan-clean (manual empty) + a computed strip present → still needs-review.
        self.assertTrue(self._fix(computed=("strip",), manual=()).partial)

    def test_manual_only_is_partial(self):
        self.assertTrue(self._fix(computed=(), manual=("residual",)).partial)

    def test_both_is_partial(self):
        self.assertTrue(self._fix(computed=("strip",), manual=("residual",)).partial)

    def test_neither_is_not_partial(self):
        # A fully trusted-clean fix (no computed strip, no residual manual) is NOT partial.
        self.assertFalse(self._fix(computed=(), manual=()).partial)


class TestSuspiciousOnlyDisclosed(unittest.TestCase):
    """#1360: a repo whose ONLY findings are HEURISTIC (suspicious) — nothing confirmed, nothing
    auto-fixable — must be DISCLOSED and deferred to review, NEVER reported 'already clean'. `saw
    scan`/`saw hook` flag such a repo; `saw fix` calling it clean is a self-contradiction that erodes
    trust. It must also stay exit 0 (no ABORTED/PARTIAL/error marker), consistent with a suspicious
    `saw scan`, and must NOT file a manual-review issue (a heuristic is not asserted malware)."""

    # An evil-merge (history, heuristic) + an obfuscated-source-file (heuristic) — the exact GEOFINDA
    # shape from the issue. `confidence="heuristic"` is what keeps them out of the blocking set.
    _EVIL_MERGE = Finding("evil-merge", "git-history", Severity.HIGH, "96dcbd397c",
                          "merge-introduced loader hunk", confidence="heuristic", vector="evil-merge")
    _OBFUSCATED = Finding("obfuscated-source-file", "obfuscation", Severity.MEDIUM,
                          ".claude/skills/run/driver.mjs", "dynamic-exec sink", confidence="heuristic")

    def _no_op_remediation(self):
        # Heuristics are never planned/applied/recovered — every remediation seam is a no-op, so the
        # build falls through to the suspicious-only return.
        return [
            mock.patch.object(pr.remediation, "plan", return_value=[]),
            mock.patch.object(pr.remediation, "apply", return_value=[]),
            mock.patch.object(pr.remediation, "quarantine_residual", return_value=[]),
        ]

    def _submit(self, findings):
        scan = ScanResult("owner/repo", "local", list(findings))
        with _patch_git(), \
             mock.patch.object(pr.fix, "scan_target", return_value=scan), \
             mock.patch.object(pr.github_api, "list_open_pulls", return_value=[]), \
             mock.patch.object(pr.github_api, "list_open_issues", return_value=[]), \
             mock.patch.object(pr.github_api, "create_issue",
                               return_value={"number": 9, "html_url": "iu"}) as create_issue, \
             mock.patch.object(pr.github_api, "create_pull") as create_pull, \
             contextlib.ExitStack() as stack:
            for p in self._no_op_remediation():
                stack.enter_context(p)
            outcome = pr.submit_fix_pr(Path("/repo"), object(), {}, [], token="t")
        return SimpleNamespace(outcome=outcome, create_pull=create_pull, create_issue=create_issue)

    def _prepare(self, findings):
        scan = ScanResult("owner/repo", "local", list(findings))
        with _patch_git(), \
             mock.patch.object(pr.fix, "scan_target", return_value=scan), \
             contextlib.ExitStack() as stack:
            for p in self._no_op_remediation():
                stack.enter_context(p)
            return pr.prepare_fix(Path("/repo"), object(), {}, [])

    def test_submit_discloses_not_clean(self):
        r = self._submit([self._EVIL_MERGE, self._OBFUSCATED])
        self.assertNotIn("already clean", r.outcome)         # the #1360 lie is gone
        self.assertIn("suspicious", r.outcome.lower())       # discloses the heuristic findings
        self.assertIn("2 suspicious", r.outcome)             # both counted
        self.assertIn("saw scan", r.outcome)                 # points at review
        self.assertIn("evil-merge", r.outcome)               # the signature is listed

    def test_submit_stays_exit_zero(self):
        # remediator.fix keys needs-review (exit 1) off these substrings — none may appear.
        r = self._submit([self._EVIL_MERGE, self._OBFUSCATED])
        for marker in ("ABORTED", "PARTIAL", ": error"):
            self.assertNotIn(marker, r.outcome)

    def test_submit_does_not_file_issue_or_pr(self):
        # A heuristic is not asserted malware: no PR (nothing to fix) and no over-alarming issue.
        r = self._submit([self._EVIL_MERGE])
        r.create_pull.assert_not_called()
        r.create_issue.assert_not_called()

    def test_prepare_discloses_not_clean(self):
        outcome = self._prepare([self._EVIL_MERGE, self._OBFUSCATED])
        self.assertNotIn("already clean", outcome)
        self.assertIn("suspicious", outcome.lower())
        self.assertNotIn("ABORTED", outcome)

    def test_singular_plural(self):
        self.assertIn("1 suspicious (heuristic) finding —", self._submit([self._EVIL_MERGE]).outcome)

    def test_truly_clean_still_reports_already_clean(self):
        # The genuinely-empty tree keeps the old wording — only suspicious-bearing repos change.
        r = self._submit([])
        self.assertIn("already clean", r.outcome)
        self.assertNotIn("suspicious", r.outcome.lower())


if __name__ == "__main__":
    unittest.main()
