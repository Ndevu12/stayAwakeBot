#!/usr/bin/env python3
"""Tests for `saw guard` detection/grading (#1229) — the read-only `guard check` engine.

Network is mocked; the detection/grading logic is exercised offline against a fixture modelled on
the real `Ndevu12/ndevuspace-blog` gate (filename `worm-scan.yml`, job `strix`, `@v0.1.4`)."""
from __future__ import annotations

import contextlib
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


class TestFindWormGate(unittest.TestCase):
    """A worm gate is detected by ANY mechanism, not just the Ndevu12/strix action (#1239)."""

    def test_strix_action_wins_and_is_gradeable(self):
        g = guard.find_worm_gate({"w.yml": BLOG_WF})
        self.assertEqual(g.mechanism, "strix")
        self.assertIsNotNone(g.strix)                # carries the StrixRef for pin/freshness grading

    def test_direct_saw_run_step(self):
        for script in ("saw scan .", "pipx run stayawakebot saw scan $GITHUB_WORKSPACE",
                       "python -m pip install stayawakebot && saw audit"):
            wf = f"jobs:\n  g:\n    steps:\n      - run: {script}\n"
            self.assertEqual(guard.find_worm_gate({"w.yml": wf}).mechanism, "saw-run", script)

    def test_local_composite_action_that_runs_saw(self):
        wf = "jobs:\n  g:\n    steps:\n      - uses: ./.github/actions/worm-scan\n"
        reader = lambda uses: "runs:\n  steps:\n    - run: saw scan $GITHUB_WORKSPACE\n"
        g = guard.find_worm_gate({"w.yml": wf}, read_action=reader)
        self.assertEqual((g.mechanism, g.detail), ("local-action", "./.github/actions/worm-scan"))

    def test_local_action_not_resolved_without_reader(self):
        # Without a resolver we can't prove a local action runs saw → not detected (no false claim).
        wf = "jobs:\n  g:\n    steps:\n      - uses: ./.github/actions/worm-scan\n"
        self.assertIsNone(guard.find_worm_gate({"w.yml": wf}))

    def test_local_action_that_does_not_run_saw_is_not_a_gate(self):
        wf = "jobs:\n  g:\n    steps:\n      - uses: ./.github/actions/build\n"
        reader = lambda uses: "runs:\n  steps:\n    - run: npm run build\n"
        self.assertIsNone(guard.find_worm_gate({"w.yml": wf}, read_action=reader))

    def test_ordinary_workflow_is_not_a_gate(self):
        wf = "jobs:\n  g:\n    steps:\n      - run: echo building; make test\n"
        self.assertIsNone(guard.find_worm_gate({"w.yml": wf}))

    def test_saw_scan_only_in_a_comment_is_not_a_gate(self):
        # FP guard: a documentation comment mentioning the scanner must not read as a gate (else
        # setup would wrongly skip installing one).
        wf = ("jobs:\n  g:\n    steps:\n      - run: |\n"
              "          # to check locally, run: saw scan .\n          make build\n")
        self.assertIsNone(guard.find_worm_gate({"w.yml": wf}))


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

    def test_local_gate_by_non_strix_mechanism_is_present_but_ungraded(self):
        # #1239: a repo guarded by a direct `saw` step is present (not falsely "no gate"), but has
        # no StrixRef to grade — check must SAY it's protected and stop advising "add a gate".
        d = self._repo_with("jobs:\n  g:\n    steps:\n      - run: saw scan $GITHUB_WORKSPACE\n")
        s = guard.check(repo=d, offline=True)
        self.assertTrue(s.present)
        self.assertIsNone(s.ref)
        self.assertEqual(s.mechanism, "saw-run")
        out = guard.render(s)
        self.assertIn("Worm gate found", out)
        self.assertNotIn("No worm gate", out)

    def test_remote_required_uses_derived_context(self):
        with mock.patch.object(guard, "_remote_workflows", return_value=guard.RemoteRead({"w.yml": BLOG_WF})), \
             mock.patch.object(guard.github_api, "get_branch_protection",
                               return_value={"required_status_checks": {"contexts": ["strix"]}}), \
             mock.patch.object(guard, "freshness", return_value=Freshness("fresh", "v0.1.4")):
            s = guard.check(slug="o/r", token="t")
        self.assertTrue(s.present)
        self.assertTrue(s.required)

    def test_remote_fuzzy_worm_does_not_satisfy_strix_context(self):
        # The #1230 point: require the ACTUAL job context (strix), not a name containing "worm".
        with mock.patch.object(guard, "_remote_workflows", return_value=guard.RemoteRead({"w.yml": BLOG_WF})), \
             mock.patch.object(guard.github_api, "get_branch_protection",
                               return_value={"required_status_checks": {"contexts": ["Worm Guard"]}}), \
             mock.patch.object(guard, "freshness", return_value=Freshness("fresh", "v0.1.4")):
            s = guard.check(slug="o/r", token="t")
        self.assertFalse(s.required)

    def test_remote_no_ci_is_calm_not_an_error(self):
        # #1243: a 404 on .github/workflows = the repo has no CI — the NORMAL state, NOT a token error.
        with mock.patch.object(guard, "_remote_workflows",
                               return_value=guard.RemoteRead({}, cause="not_found")):
            s = guard.check(slug="o/r", token="t")
        self.assertFalse(s.present)
        self.assertTrue(s.no_ci)
        self.assertIsNone(s.error)                       # NOT an error
        self.assertIn("no CI", guard.render(s))

    def test_remote_real_read_failures_get_distinct_messages(self):
        # #1243: each real cause → its own accurate message (never token-blaming for a 404).
        cases = {
            "unauthorized": "gh auth login",
            "forbidden": "private",
            "network": "network error",
        }
        for cause, needle in cases.items():
            with mock.patch.object(guard, "_remote_workflows",
                                   return_value=guard.RemoteRead({}, cause=cause)):
                s = guard.check(slug="o/r", token="t")
            self.assertFalse(s.present)
            self.assertIsNotNone(s.error, cause)
            self.assertIn(needle, s.error, cause)

    def test_remote_rate_limited_names_the_retry(self):
        with mock.patch.object(guard, "_remote_workflows",
                               return_value=guard.RemoteRead({}, cause="rate_limited", retry_after=42)):
            s = guard.check(slug="o/r", token="t")
        self.assertIn("rate limit", s.error)
        self.assertIn("42s", s.error)


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
        self.assertIn("No worm gate found", guard.render(GuardStatus(present=False)))

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

    def test_refuses_gate_write_through_a_symlinked_ancestor_dir(self):
        # #1218: if `.github/workflows` is a planted symlink escaping the repo, `setup` must NOT write
        # the gate THROUGH it — it refuses, and nothing lands outside the repo.
        import tempfile
        repo = _tmp_repo()
        outside = Path(tempfile.mkdtemp())
        (repo / ".github").mkdir(parents=True, exist_ok=True)
        (repo / ".github" / "workflows").symlink_to(outside, target_is_directory=True)
        with self._resolve(), mock.patch.object(guard.gitutil, "default_branch", return_value="main"):
            res = guard.setup(repo)
        self.assertIn("refusing to write", res.error or "")
        self.assertFalse((outside / "worm-guard.yml").exists())   # never written through the link

    def test_never_clobbers_an_unrecognized_file_at_the_path(self):
        # Regression (#1239 data-loss): a file at the conventional worm-guard.yml path that ISN'T a
        # recognizable worm gate (here a local action whose action.yml we can't resolve to prove it
        # runs saw) must NOT be overwritten by `create`. setup errors, file left byte-for-byte intact.
        repo = _tmp_repo()
        wf = repo / guard.WORKFLOW_DIR
        wf.mkdir(parents=True)
        original = ("name: Worm Guard\non: [pull_request]\njobs:\n  worm-guard:\n"
                    "    steps:\n      - uses: ./.github/actions/worm-scan\n")
        (wf / "worm-guard.yml").write_text(original)   # no action.yml on disk → can't confirm a gate
        with self._resolve(), mock.patch.object(guard.gitutil, "default_branch", return_value="main"):
            res = guard.setup(repo)
        self.assertEqual(res.plan.action, "conflict")
        self.assertIsNotNone(res.error)
        self.assertIn("not overwriting", res.error)
        self.assertEqual((wf / "worm-guard.yml").read_text(), original)   # untouched

    def test_already_guarded_by_another_mechanism_is_present_not_install(self):
        # #1239: a repo genuinely guarded by a local scan action (resolvable — its action.yml runs
        # saw) is 'present' (already guarded), NOT a create/conflict — setup installs no duplicate.
        repo = _tmp_repo()
        (repo / guard.WORKFLOW_DIR).mkdir(parents=True)
        (repo / guard.WORKFLOW_DIR / "ci.yml").write_text(
            "jobs:\n  g:\n    steps:\n      - uses: ./.github/actions/worm-scan\n")
        act = repo / ".github/actions/worm-scan"
        act.mkdir(parents=True)
        (act / "action.yml").write_text("runs:\n  steps:\n    - run: saw scan $GITHUB_WORKSPACE\n")
        with self._resolve(), mock.patch.object(guard.gitutil, "default_branch", return_value="main"):
            res = guard.setup(repo)
        self.assertEqual(res.plan.action, "present")
        self.assertIsNone(res.wrote)                              # nothing installed
        self.assertFalse((repo / guard.WORM_GUARD_FILE).exists())
        self.assertIn("already guarded", guard.render_setup(res))

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
        from stayawake.lib.git.write.commit import CommitResult
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

    def test_pr_plans_against_origin_not_a_dirty_working_tree(self):
        # The bug: `saw guard setup --pr` planned from the WORKING TREE. A worm-guard.yml written by a
        # prior local `setup` (untracked, never on origin) made `--pr` see the gate as already-there and
        # no-op — so it "reported" success while opening no PR. `--pr` must plan against origin's tree.
        from stayawake.bots.security.proposal import SubmitResult
        repo = _tmp_repo()
        wf = Path(repo) / guard.WORM_GUARD_FILE                 # an UNTRACKED gate in the working tree…
        wf.parent.mkdir(parents=True, exist_ok=True)
        wf.write_text("name: Worm Guard\non: pull_request\njobs: {}\n", encoding="utf-8")
        with mock.patch.object(guard, "resolve_pin", return_value=guard.Pin(SHA, "v0.1.4")), \
             mock.patch.object(guard.gitutil, "default_branch", return_value="main"), \
             mock.patch.object(guard.gitutil, "origin_slug", return_value="up/repo"), \
             mock.patch.object(guard.gitutil, "ref_exists", return_value=True), \
             mock.patch.object(guard.gitutil, "fetch", return_value=True), \
             mock.patch.object(guard.gitutil, "list_tree", return_value=[]), \
             mock.patch.object(guard, "_setup_pr",
                               return_value=guard.SetupResult(
                                   plan=guard.SetupPlan("create", guard.WORM_GUARD_FILE, new_ref=SHA),
                                   submit=SubmitResult("pr", action="opened", number=9, url="u"))) as sp:
            res = guard.setup(repo, token="tok", pr=True)
        sp.assert_called_once()                                 # origin has no gate → PR opened, not no-op
        self.assertEqual(res.plan.action, "create")


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


class TestCheckSweep(unittest.TestCase):
    """`saw guard check` sweeps many repos (local discovery / remote #1075 ladder), like scan/fix."""

    def _healthy(self):
        return GuardStatus(present=True, ref=StrixRef("w", "strix", SHA, "sha"),
                           fresh=Freshness("fresh", "v1"), required=True, branch="o/r")

    def _unguarded(self):
        return GuardStatus(present=False)

    def _mocks(self, *, discover=None, resolve=None, check_side=None, check_return=None,
               token=("t", "env")):
        cms = [mock.patch.object(guard, "latest_strix", return_value=guard.LatestStrix("v1", SHA)),
               mock.patch.object(guard.auth, "resolve_token", return_value=token)]
        if discover is not None:
            cms.append(mock.patch.object(guard.resolution, "discover_local_repos", return_value=discover))
        if resolve is not None:
            cms.append(mock.patch.object(guard.resolution, "resolve_remote", return_value=resolve))
        chk = mock.patch.object(guard, "check",
                                side_effect=check_side) if check_side else \
            mock.patch.object(guard, "check", return_value=check_return)
        cms.append(chk)
        return cms

    def test_local_sweep_discovers_and_checks_each(self):
        with self._patch(discover=[Path("/a"), Path("/b")], check_return=self._healthy()) as chk:
            rc = guard.check_targets(paths=["~/dev"], no_stream=True)
        self.assertEqual(rc, 0)
        self.assertEqual(chk.call_count, 2)                     # both discovered repos checked
        self.assertIsNotNone(chk.call_args.kwargs.get("latest"))  # freshness precomputed once, reused

    def test_fail_flag_trips_when_any_unhealthy(self):
        with self._patch(discover=[Path("/a")], check_return=self._unguarded()):
            self.assertEqual(guard.check_targets(paths=["."], fail=True, no_stream=True), 1)
        with self._patch(discover=[Path("/a")], check_return=self._unguarded()):
            self.assertEqual(guard.check_targets(paths=["."], fail=False, no_stream=True), 0)

    def test_remote_sweep_resolves_and_checks_slugs(self):
        with self._patch(resolve=(["o/a", "o/b"], "t", "env"), check_return=self._healthy()) as chk:
            rc = guard.check_targets(remote=True, no_stream=True)
        self.assertEqual(rc, 0)
        self.assertEqual(chk.call_count, 2)
        self.assertIn("slug", chk.call_args.kwargs)            # remote → checked by slug, not path

    def test_remote_invalid_slug_errors(self):
        self.assertEqual(guard.check_targets(remote=True, slugs=["not-a-slug"], no_stream=True), 2)

    def test_remote_empty_returns_zero(self):
        with self._patch(resolve=([], None, None), check_return=self._healthy()):
            self.assertEqual(guard.check_targets(remote=True, no_stream=True), 0)

    def test_missing_explicit_config_exits_2(self):
        self.assertEqual(guard.check_targets(config_path="/no/such/config.yml", no_stream=True), 2)

    def test_one_repo_error_does_not_abort_the_sweep(self):
        with self._patch(discover=[Path("/a"), Path("/b")],
                         check_side=[RuntimeError("boom"), self._healthy()]) as chk:
            rc = guard.check_targets(paths=["."], no_stream=True)   # first raises, second still runs
        self.assertEqual(chk.call_count, 2)
        self.assertEqual(rc, 0)

    @contextlib.contextmanager
    def _patch(self, **kw):
        # Enter every mock; the `check` mock is always last in _mocks() — yield it for assertions.
        with contextlib.ExitStack() as stack:
            chk = None
            for cm in self._mocks(**kw):
                chk = stack.enter_context(cm)
            yield chk


@contextlib.contextmanager
def _fake_clone(path):
    yield path


class TestSetupSweep(unittest.TestCase):
    """`saw guard setup` sweeps many repos: local discovery (write/PR each) or remote (clone → PR)."""

    def _ok(self):
        return guard.SetupResult(plan=guard.SetupPlan("create", "wf", new_ref=SHA), wrote=Path("/x"))

    def test_local_sweep_sets_up_each_discovered_repo(self):
        with mock.patch.object(guard, "resolve_pin", return_value=guard.Pin(SHA, "v0.1.4")), \
             mock.patch.object(guard.resolution, "discover_local_repos",
                               return_value=[Path("/a"), Path("/b")]), \
             mock.patch.object(guard.auth, "resolve_token", return_value=(None, None)), \
             mock.patch.object(guard, "setup", side_effect=lambda *a, **k: self._ok()) as s:
            rc = guard.setup_targets(paths=["."], no_stream=True)
        self.assertEqual(rc, 0)
        self.assertEqual(s.call_count, 2)

    def test_one_repo_error_isolated_but_exits_one(self):
        with mock.patch.object(guard, "resolve_pin", return_value=guard.Pin(SHA, "v0.1.4")), \
             mock.patch.object(guard.resolution, "discover_local_repos",
                               return_value=[Path("/a"), Path("/b")]), \
             mock.patch.object(guard.auth, "resolve_token", return_value=(None, None)), \
             mock.patch.object(guard, "setup", side_effect=[RuntimeError("boom"), self._ok()]) as s:
            rc = guard.setup_targets(paths=["."], no_stream=True)
        self.assertEqual(s.call_count, 2)                    # second repo still attempted
        self.assertEqual(rc, 1)                              # an errored repo → exit 1

    def test_remote_clones_and_sets_up_with_pr_implied(self):
        with mock.patch.object(guard, "resolve_pin", return_value=guard.Pin(SHA, "v0.1.4")), \
             mock.patch.object(guard.resolution, "resolve_remote",
                               return_value=(["o/a", "o/b"], "t", "env")), \
             mock.patch.object(guard.resolution, "cloned_repo",
                               side_effect=lambda *a, **k: _fake_clone(Path("/clone"))), \
             mock.patch.object(guard, "setup", side_effect=lambda *a, **k: self._ok()) as s:
            rc = guard.setup_targets(remote=True, no_stream=True)
        self.assertEqual(rc, 0)
        self.assertEqual(s.call_count, 2)
        self.assertTrue(s.call_args.kwargs.get("pr"))        # a remote repo has no working tree → always PR

    def test_remote_without_token_exits_two(self):
        with mock.patch.object(guard.resolution, "resolve_remote", return_value=(["o/a"], None, None)):
            self.assertEqual(guard.setup_targets(remote=True, no_stream=True), 2)

    def test_remote_clone_failure_is_an_error(self):
        with mock.patch.object(guard, "resolve_pin", return_value=guard.Pin(SHA, "v0.1.4")), \
             mock.patch.object(guard.resolution, "resolve_remote", return_value=(["o/a"], "t", "env")), \
             mock.patch.object(guard.resolution, "cloned_repo",
                               side_effect=lambda *a, **k: _fake_clone(None)), \
             mock.patch.object(guard, "setup") as s:
            rc = guard.setup_targets(remote=True, no_stream=True)
        self.assertEqual(rc, 1)                              # clone failed → error → exit 1
        s.assert_not_called()                                # never setup on a failed clone

    def test_pushed_but_unopened_pr_is_not_counted_as_success(self):
        # The ladder returns a SubmitResult even when the branch pushed but the PR API call failed
        # (or the fork wasn't ready, or there was no write access). That is NOT an opened PR — it must
        # not be tallied as "opened/updated", and the sweep must exit non-zero, not phantom-succeed.
        from stayawake.bots.security.proposal import SubmitResult
        failed = guard.SetupResult(plan=guard.SetupPlan("create", "wf", new_ref=SHA),
                                   submit=SubmitResult("pr-create-failed"))
        with mock.patch.object(guard, "resolve_pin", return_value=guard.Pin(SHA, "v0.1.4")), \
             mock.patch.object(guard.resolution, "resolve_remote", return_value=(["o/a"], "t", "env")), \
             mock.patch.object(guard.resolution, "cloned_repo",
                               side_effect=lambda *a, **k: _fake_clone(Path("/clone"))), \
             mock.patch.object(guard, "setup", side_effect=lambda *a, **k: failed):
            rc = guard.setup_targets(remote=True, no_stream=True)
        self.assertEqual(rc, 1)                              # pushed-but-unopened → failure, not success

    def test_invalid_slug_exits_two(self):
        self.assertEqual(guard.setup_targets(remote=True, slugs=["not-a-slug"], no_stream=True), 2)

    def test_missing_explicit_config_exits_two(self):
        self.assertEqual(guard.setup_targets(config_path="/no/such.yml", no_stream=True), 2)


if __name__ == "__main__":
    unittest.main()
