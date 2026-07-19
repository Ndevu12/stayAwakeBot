#!/usr/bin/env python3
"""Tests for `saw guard` detection/grading (#1229) — the read-only `guard check` engine.

Network is mocked; the detection/grading logic is exercised offline against a fixture modelled on
the real `Ndevu12/ndevuspace-blog` gate (filename `worm-scan.yml`, job `strix`, `@v0.1.4`)."""
from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest import mock

from stayawake.bots.security import guard
from stayawake.bots.security.guard import (Freshness, GuardStatus, StrixRef, classify_pin,
                             _context_required, find_strix)

BLOG_WF = """name: Worm scan
on: { push: { branches: [main] }, pull_request: {} }
permissions: { contents: write, pull-requests: write }
jobs:
  strix:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with: { fetch-depth: 0 }
      - uses: Ndevu12/strix@v0.1.4
        with: { remediate: pr }
"""


class TestClassifyPin(unittest.TestCase):
    def test_sha(self):
        self.assertEqual(classify_pin("93fe465d7b0266c6010778999b73b591ae082f3e"), "sha")

    def test_exact_tag(self):
        self.assertEqual(classify_pin("v0.1.4"), "tag")

    def test_floating(self):
        for r in ("v0", "v1", "main", "some-branch"):
            self.assertEqual(classify_pin(r), "floating", r)


class TestFindStrix(unittest.TestCase):
    def test_finds_blog_gate_by_action_ref(self):
        r = find_strix({".github/workflows/worm-scan.yml": BLOG_WF})
        self.assertIsNotNone(r)
        self.assertEqual(r.job, "strix")             # job id → the status-check context (no `name:`)
        self.assertEqual(r.ref, "v0.1.4")
        self.assertEqual(r.pin, "tag")
        self.assertEqual(r.workflow, ".github/workflows/worm-scan.yml")

    def test_filename_agnostic(self):
        r = find_strix({".github/workflows/anything-else.yaml": BLOG_WF})
        self.assertIsNotNone(r)
        self.assertEqual(r.job, "strix")

    def test_job_name_overrides_id_as_context(self):
        wf = "jobs:\n  scan:\n    name: Worm Guard\n    steps:\n      - uses: Ndevu12/strix@v0\n"
        r = find_strix({"x.yml": wf})
        self.assertEqual(r.job, "Worm Guard")        # a `name:` is the status context, not the id
        self.assertEqual(r.pin, "floating")

    def test_sha_pin_and_trailing_comment(self):
        wf = ("jobs:\n  g:\n    steps:\n      - uses: "
              "Ndevu12/strix@93fe465d7b0266c6010778999b73b591ae082f3e # v0.1.4\n")
        r = find_strix({"x.yml": wf})
        self.assertEqual(r.pin, "sha")
        self.assertEqual(r.ref, "93fe465d7b0266c6010778999b73b591ae082f3e")

    def test_no_strix_ref(self):
        wf = "jobs:\n  g:\n    steps:\n      - uses: actions/checkout@v4\n"
        self.assertIsNone(find_strix({"x.yml": wf}))

    def test_malformed_yaml_is_skipped_not_fatal(self):
        r = find_strix({"bad.yml": "{{{ not: [valid", "good.yml": BLOG_WF})
        self.assertIsNotNone(r)

    def test_first_by_sorted_path(self):
        r = find_strix({"b.yml": BLOG_WF, "a.yml": BLOG_WF})
        self.assertEqual(r.workflow, "a.yml")


class TestContextRequired(unittest.TestCase):
    def test_legacy_contexts(self):
        self.assertTrue(_context_required({"required_status_checks": {"contexts": ["strix"]}}, "strix"))

    def test_checks_array(self):
        self.assertTrue(_context_required(
            {"required_status_checks": {"checks": [{"context": "strix"}]}}, "strix"))

    def test_missing_context(self):
        self.assertFalse(_context_required({"required_status_checks": {"contexts": ["build"]}}, "strix"))

    def test_none_protection(self):
        self.assertFalse(_context_required(None, "strix"))


class TestFreshness(unittest.TestCase):
    def _rel(self, tag):
        return mock.patch.object(guard.github_api, "latest_release", return_value={"tag_name": tag})

    def test_tag_behind(self):
        with self._rel("v0.1.5"):
            f = guard.freshness(StrixRef("w", "j", "v0.1.4", "tag"))
        self.assertEqual(f.state, "behind")
        self.assertEqual(f.latest_tag, "v0.1.5")

    def test_tag_fresh(self):
        with self._rel("v0.1.4"):
            self.assertEqual(guard.freshness(StrixRef("w", "j", "v0.1.4", "tag")).state, "fresh")

    def test_sha_fresh(self):
        sha = "a" * 40
        with self._rel("v0.1.4"), \
             mock.patch.object(guard.github_api, "ref_commit_sha", return_value=sha):
            self.assertEqual(guard.freshness(StrixRef("w", "j", sha, "sha")).state, "fresh")

    def test_sha_behind(self):
        with self._rel("v0.1.4"), \
             mock.patch.object(guard.github_api, "ref_commit_sha", return_value="b" * 40):
            self.assertEqual(guard.freshness(StrixRef("w", "j", "a" * 40, "sha")).state, "behind")

    def test_floating_is_not_stale(self):
        with self._rel("v0.1.4"):
            self.assertEqual(guard.freshness(StrixRef("w", "j", "v0", "floating")).state, "floating")

    def test_unknown_when_api_unreachable(self):
        with mock.patch.object(guard.github_api, "latest_release", return_value=None):
            self.assertEqual(guard.freshness(StrixRef("w", "j", "v0.1.4", "tag")).state, "unknown")


class TestCheck(unittest.TestCase):
    def _repo_with(self, text):
        d = Path(tempfile.mkdtemp())
        (d / ".github/workflows").mkdir(parents=True)
        (d / ".github/workflows/worm-scan.yml").write_text(text, encoding="utf-8")
        return d

    def test_local_present(self):
        s = guard.check(repo=self._repo_with(BLOG_WF), offline=True)
        self.assertTrue(s.present)
        self.assertEqual(s.ref.job, "strix")
        self.assertIsNone(s.required)                # local: enforcement not checked

    def test_local_absent(self):
        self.assertFalse(guard.check(repo=Path(tempfile.mkdtemp()), offline=True).present)

    def test_remote_required_uses_derived_context(self):
        with mock.patch.object(guard, "_remote_workflows", return_value={"w.yml": BLOG_WF}), \
             mock.patch.object(guard.github_api, "get_branch_protection",
                               return_value={"required_status_checks": {"contexts": ["strix"]}}), \
             mock.patch.object(guard, "freshness", return_value=Freshness("fresh", "v0.1.4")):
            s = guard.check(slug="o/r", token="t")
        self.assertTrue(s.present)
        self.assertTrue(s.required)

    def test_remote_fuzzy_worm_does_not_satisfy_strix_context(self):
        # The #1230 point: require the ACTUAL job context (strix), not a name containing "worm".
        with mock.patch.object(guard, "_remote_workflows", return_value={"w.yml": BLOG_WF}), \
             mock.patch.object(guard.github_api, "get_branch_protection",
                               return_value={"required_status_checks": {"contexts": ["Worm Guard"]}}), \
             mock.patch.object(guard, "freshness", return_value=Freshness("fresh", "v0.1.4")):
            s = guard.check(slug="o/r", token="t")
        self.assertFalse(s.required)

    def test_remote_unreadable_is_error(self):
        with mock.patch.object(guard, "_remote_workflows", return_value=None):
            s = guard.check(slug="o/r", token="t")
        self.assertFalse(s.present)
        self.assertIsNotNone(s.error)


class TestHealthy(unittest.TestCase):
    """GuardStatus.healthy — the -f/--fail policy, a domain property (not CLI logic)."""

    def _status(self, **kw):
        base = dict(present=True, ref=StrixRef("w", "strix", "a" * 40, "sha"),
                    fresh=Freshness("fresh", "v0.1.4"), required=True, branch="main")
        base.update(kw)
        return GuardStatus(**base)

    def test_healthy(self):
        self.assertTrue(self._status().healthy)

    def test_absent(self):
        self.assertFalse(self._status(present=False, ref=None).healthy)

    def test_floating_pin(self):
        self.assertFalse(self._status(ref=StrixRef("w", "strix", "v0", "floating")).healthy)

    def test_behind(self):
        self.assertFalse(self._status(fresh=Freshness("behind", "v0.1.5")).healthy)

    def test_not_required(self):
        self.assertFalse(self._status(required=False).healthy)

    def test_local_unchecked_required_is_ok(self):
        self.assertTrue(self._status(required=None).healthy)


class TestRender(unittest.TestCase):
    def test_absent_report(self):
        self.assertIn("No Strix gate found", guard.render(GuardStatus(present=False)))

    def test_present_report_is_plain_without_color(self):
        s = GuardStatus(present=True, ref=StrixRef("wf.yml", "strix", "a" * 40, "sha"),
                        fresh=Freshness("fresh", "v0.1.4"), required=True, branch="main")
        out = guard.render(s, color=False)
        self.assertIn("Strix gate found", out)
        self.assertIn("pinned to a commit SHA", out)
        self.assertIn("required", out)
        self.assertNotIn("\033[", out)                 # color off → no ANSI escapes

    def test_color_on_emits_ansi(self):
        self.assertIn("\033[", guard.render(GuardStatus(present=False), color=True))

    def test_required_line_only_for_remote(self):
        local = GuardStatus(present=True, ref=StrixRef("wf.yml", "strix", "a" * 40, "sha"),
                            fresh=Freshness("fresh", "v0.1.4"), required=None, branch=None)
        self.assertNotIn("required", guard.render(local))    # no branch → local → no enforcement line


SHA = "a" * 40


class TestResolvePin(unittest.TestCase):
    def test_explicit_sha_used_verbatim_no_network(self):
        with mock.patch.object(guard.github_api, "ref_commit_sha") as rcs, \
             mock.patch.object(guard.github_api, "latest_release") as lr:
            pin = guard.resolve_pin(None, ref=SHA)
        self.assertEqual((pin.sha, pin.tag), (SHA, None))
        rcs.assert_not_called()                              # a SHA needs no resolution
        lr.assert_not_called()

    def test_explicit_tag_resolved_to_sha(self):
        with mock.patch.object(guard.github_api, "ref_commit_sha", return_value=SHA):
            pin = guard.resolve_pin("tok", ref="v0.1.4")
        self.assertEqual((pin.sha, pin.tag), (SHA, "v0.1.4"))

    def test_latest_release_resolved(self):
        with mock.patch.object(guard.github_api, "latest_release", return_value={"tag_name": "v9.9.9"}), \
             mock.patch.object(guard.github_api, "ref_commit_sha", return_value=SHA):
            pin = guard.resolve_pin("tok")
        self.assertEqual((pin.sha, pin.tag), (SHA, "v9.9.9"))

    def test_fails_closed_when_unreachable(self):
        # No release / no SHA → None, so setup never emits a floating pin silently.
        with mock.patch.object(guard.github_api, "latest_release", return_value=None):
            self.assertIsNone(guard.resolve_pin("tok"))


class TestPlanSetup(unittest.TestCase):
    PIN = guard.Pin(SHA, "v0.1.4")

    def test_create_when_absent(self):
        p = guard.plan_setup({}, "main", self.PIN)
        self.assertEqual((p.action, p.path), ("create", guard.WORM_GUARD_FILE))
        self.assertEqual(guard.find_strix({p.path: p.content}).pin, "sha")   # emitted file is detectable

    def test_noop_when_already_latest_sha(self):
        wf = guard.render_workflow(self.PIN, "main")
        self.assertEqual(guard.plan_setup({"a.yml": wf}, "main", self.PIN).action, "noop")

    def test_repin_is_surgical_and_filename_agnostic(self):
        existing = ("name: keep-me\non: [push]\njobs:\n  strix:\n    steps:\n"
                    "      - uses: Ndevu12/strix@v0  # old\n")
        p = guard.plan_setup({".github/workflows/worm-scan.yml": existing}, "main", self.PIN)
        self.assertEqual((p.action, p.path), ("repin", ".github/workflows/worm-scan.yml"))
        self.assertIn(f"Ndevu12/strix@{SHA}", p.content)
        self.assertIn("name: keep-me", p.content)                            # rest preserved
        self.assertEqual(guard.find_strix({p.path: p.content}).pin, "sha")

    def test_repin_handles_a_quoted_uses(self):
        # A YAML-quoted ref is detected by find_strix; the rewrite must actually change it (not a
        # silent no-op), normalizing to the conventional unquoted form.
        existing = 'jobs:\n  s:\n    steps:\n      - uses: "Ndevu12/strix@v0"\n'
        p = guard.plan_setup({"wf.yml": existing}, "main", self.PIN)
        self.assertEqual(p.action, "repin")
        self.assertIn(f"Ndevu12/strix@{SHA}", p.content)
        self.assertNotIn('"Ndevu12/strix@v0"', p.content)


def _tmp_repo():
    import subprocess
    d = Path(tempfile.mkdtemp())
    subprocess.run(["git", "init", "-q", str(d)], check=True)
    return d


class TestSetupLocal(unittest.TestCase):
    def _resolve(self):
        return mock.patch.object(guard, "resolve_pin", return_value=guard.Pin(SHA, "v0.1.4"))

    def test_writes_file_into_working_tree(self):
        repo = _tmp_repo()
        with self._resolve(), mock.patch.object(guard.gitutil, "default_branch", return_value="main"):
            res = guard.setup(repo)
        self.assertEqual(res.plan.action, "create")
        self.assertTrue((repo / guard.WORM_GUARD_FILE).is_file())
        self.assertEqual(res.wrote, repo / guard.WORM_GUARD_FILE)

    def test_never_clobbers_an_existing_worm_guard_workflow(self):
        # Regression: a repo running a worm gate by ANOTHER mechanism (a local `uses: ./…/worm-scan`
        # action, undetectable by find_strix) under the conventional worm-guard.yml name must NOT be
        # overwritten by `create`. setup errors and leaves the file byte-for-byte intact.
        repo = _tmp_repo()
        wf = repo / guard.WORKFLOW_DIR
        wf.mkdir(parents=True)
        original = ("name: Worm Guard\non: [pull_request]\njobs:\n  worm-guard:\n"
                    "    steps:\n      - uses: ./.github/actions/worm-scan\n")
        (wf / "worm-guard.yml").write_text(original)
        with self._resolve(), mock.patch.object(guard.gitutil, "default_branch", return_value="main"):
            res = guard.setup(repo)
        self.assertEqual(res.plan.action, "conflict")
        self.assertIsNotNone(res.error)
        self.assertIn("not overwriting", res.error)
        self.assertEqual((wf / "worm-guard.yml").read_text(), original)   # untouched

    def test_dry_run_writes_nothing(self):
        repo = _tmp_repo()
        with self._resolve(), mock.patch.object(guard.gitutil, "default_branch", return_value="main"):
            res = guard.setup(repo, dry_run=True)
        self.assertTrue(res.dry_run)
        self.assertFalse((repo / guard.WORM_GUARD_FILE).exists())

    def test_noop_when_already_pinned(self):
        repo = _tmp_repo()
        wf_dir = repo / guard.WORKFLOW_DIR
        wf_dir.mkdir(parents=True)
        (wf_dir / "worm-guard.yml").write_text(guard.render_workflow(guard.Pin(SHA, "v0.1.4"), "main"))
        with self._resolve(), mock.patch.object(guard.gitutil, "default_branch", return_value="main"):
            res = guard.setup(repo)
        self.assertEqual(res.plan.action, "noop")
        self.assertIsNone(res.wrote)

    def test_fails_closed_when_pin_unresolved(self):
        with mock.patch.object(guard, "resolve_pin", return_value=None):
            res = guard.setup(_tmp_repo())
        self.assertIsNotNone(res.error)
        self.assertIn("--ref", res.error)

    def test_refuses_silent_noop_repin_on_exotic_form(self):
        # Flow-style: find_strix (YAML) sees the gate, but the line-surgical rewrite can't touch it.
        # setup must ERROR (and write nothing), never claim a bump that changed nothing.
        repo = _tmp_repo()
        wf = repo / guard.WORKFLOW_DIR
        wf.mkdir(parents=True)
        (wf / "w.yml").write_text("jobs:\n  s:\n    steps: [{uses: Ndevu12/strix@v0}]\n")
        with self._resolve(), mock.patch.object(guard.gitutil, "default_branch", return_value="main"):
            res = guard.setup(repo)
        self.assertIsNotNone(res.error)
        self.assertIn("manually", res.error)
        self.assertNotIn(SHA, (wf / "w.yml").read_text())               # file untouched


class TestSetupPr(unittest.TestCase):
    """`--pr`: build in a worktree off default and open a rolling PR via the shared proposal ladder."""
    def _run(self, submit, *, signed=True, origin="up/repo"):
        from stayawake.core.git.write.commit import CommitResult
        with mock.patch.object(guard, "resolve_pin", return_value=guard.Pin(SHA, "v0.1.4")), \
             mock.patch.object(guard.gitutil, "default_branch", return_value="main"), \
             mock.patch.object(guard.gitutil, "origin_slug", return_value=origin), \
             mock.patch.object(guard.gitutil, "ref_exists", return_value=False), \
             mock.patch.object(guard.gitutil, "fetch", return_value=True), \
             mock.patch.object(guard.gitutil, "add_worktree", return_value=True), \
             mock.patch.object(guard.gitutil, "remove_worktree", return_value=True), \
             mock.patch.object(guard.gitutil, "stage_all", return_value=True), \
             mock.patch.object(guard.gitutil, "commit_fix",
                               return_value=CommitResult(committed=True, signed=signed)), \
             mock.patch.object(guard.proposal, "submit_change_pr", return_value=submit) as sub:
            res = guard.setup(_tmp_repo(), token="tok", pr=True)
        return res, sub

    def test_opens_pr_via_ladder(self):
        from stayawake.bots.security.proposal import SubmitResult
        res, sub = self._run(SubmitResult("pr", action="opened", number=42, url="u"))
        sub.assert_called_once()
        self.assertEqual(sub.call_args.kwargs["branch"], guard.SETUP_BRANCH)
        self.assertEqual(res.submit.number, 42)
        self.assertIn("guard PR #42", guard.render_setup(res))

    def test_no_origin_errors_before_touching_git(self):
        res, sub = self._run(None, origin=None)
        sub.assert_not_called()
        self.assertIn("no GitHub origin", res.error)

    def test_unsigned_commit_is_surfaced(self):
        from stayawake.bots.security.proposal import SubmitResult
        res, _ = self._run(SubmitResult("pr", action="opened", number=7, url="u"), signed=False)
        self.assertFalse(res.signed)
        self.assertIn("UNSIGNED", guard.render_setup(res))


class TestRenderSetup(unittest.TestCase):
    def test_error(self):
        self.assertIn("boom", guard.render_setup(guard.SetupResult(error="boom")))

    def test_noop(self):
        p = guard.SetupPlan("noop", "wf.yml", new_ref=SHA)
        self.assertIn("already up to date", guard.render_setup(guard.SetupResult(plan=p)))

    def test_local_wrote_warns_against_pushing_main(self):
        p = guard.SetupPlan("create", guard.WORM_GUARD_FILE, content="x", new_ref=SHA)
        out = guard.render_setup(guard.SetupResult(plan=p, wrote=Path("/x")))
        self.assertIn("do NOT push to the default branch", out)

    def test_dry_run_previews_content(self):
        p = guard.SetupPlan("create", guard.WORM_GUARD_FILE, content="THE-FILE", new_ref=SHA)
        out = guard.render_setup(guard.SetupResult(plan=p, dry_run=True))
        self.assertIn("dry run", out)
        self.assertIn("THE-FILE", out)


if __name__ == "__main__":
    unittest.main()
