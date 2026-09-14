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
                             find_strix)
from stayawake.bots.security.guard import detect as guard_detect
from stayawake.bots.security.guard.detect import _context_required  # private: reached at its home

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
        with mock.patch.object(guard.detect, "_remote_workflows", return_value=guard.RemoteRead({"w.yml": BLOG_WF})), \
             mock.patch.object(guard.github_api, "get_branch_protection",
                               return_value={"required_status_checks": {"contexts": ["strix"]}}), \
             mock.patch.object(guard.detect, "freshness", return_value=Freshness("fresh", "v0.1.4")):
            s = guard.check(slug="o/r", token="t")
        self.assertTrue(s.present)
        self.assertTrue(s.required)

    def test_remote_fuzzy_worm_does_not_satisfy_strix_context(self):
        # The #1230 point: require the ACTUAL job context (strix), not a name containing "worm".
        with mock.patch.object(guard.detect, "_remote_workflows", return_value=guard.RemoteRead({"w.yml": BLOG_WF})), \
             mock.patch.object(guard.github_api, "get_branch_protection",
                               return_value={"required_status_checks": {"contexts": ["Worm Guard"]}}), \
             mock.patch.object(guard.detect, "freshness", return_value=Freshness("fresh", "v0.1.4")):
            s = guard.check(slug="o/r", token="t")
        self.assertFalse(s.required)

    def test_remote_no_ci_is_calm_not_an_error(self):
        # #1243: a 404 on .github/workflows = the repo has no CI — the NORMAL state, NOT a token error.
        with mock.patch.object(guard.detect, "_remote_workflows",
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
            with mock.patch.object(guard.detect, "_remote_workflows",
                                   return_value=guard.RemoteRead({}, cause=cause)):
                s = guard.check(slug="o/r", token="t")
            self.assertFalse(s.present)
            self.assertIsNotNone(s.error, cause)
            self.assertIn(needle, s.error, cause)

    def test_remote_rate_limited_names_the_retry(self):
        with mock.patch.object(guard.detect, "_remote_workflows",
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


class TestRenderWorkflow(unittest.TestCase):
    """The installed worm-guard workflow: three least-privilege jobs — a gate that scans and reports,
    a remediation job reachable only on an infected verdict, and a scheduled pin-drift reporter."""

    def setUp(self):
        import yaml
        self.wf = guard.render_workflow(guard.Pin(SHA, "v0.1.4"), "main", "0.11.2")
        self.doc = yaml.safe_load(self.wf)          # must be valid YAML

    def test_the_job_that_scans_cannot_write_to_the_repository(self):
        gate = self.doc["jobs"]["worm-guard"]
        self.assertEqual(gate["permissions"]["contents"], "read")
        strix = gate["steps"][-1]
        self.assertEqual(strix["uses"], f"Ndevu12/strix@{SHA}")
        self.assertEqual(strix["with"]["remediate"], "off")

    def test_no_job_reachable_on_a_clean_run_can_write_contents(self):
        """The property the split exists for: on a run that finds nothing, write exists nowhere."""
        for name, job in self.doc["jobs"].items():
            if str(job.get("if", "")).find("needs.worm-guard.outputs.infected") >= 0:
                continue
            self.assertNotEqual(job.get("permissions", {}).get("contents"), "write", name)

    def test_write_lives_only_behind_the_infected_verdict(self):
        fix = self.doc["jobs"]["remediate"]
        self.assertEqual(fix["permissions"]["contents"], "write")
        self.assertEqual(fix["needs"], "worm-guard")
        self.assertIn("needs.worm-guard.outputs.infected != '0'", fix["if"])
        self.assertNotIn("failure()", fix["if"])
        self.assertEqual(self.doc["jobs"]["worm-guard"]["outputs"]["infected"],
                         "${{ steps.scan.outputs.infected }}")
        self.assertEqual(fix["steps"][-1]["with"]["remediate"], "pr")

    def test_a_cancelled_run_does_not_start_the_job_that_can_push(self):
        self.assertIn("!cancelled()", self.doc["jobs"]["remediate"]["if"])
        self.assertNotIn("always()", self.doc["jobs"]["remediate"]["if"])

    def test_an_infected_verdict_the_count_did_not_carry_still_opens_the_fix(self):
        fix = self.doc["jobs"]["remediate"]
        self.assertEqual(self.doc["jobs"]["worm-guard"]["outputs"]["verdict"],
                         "${{ steps.scan.outputs.verdict }}")
        self.assertIn("needs.worm-guard.outputs.verdict == 'infected'", fix["if"])

    def test_the_remediation_jobs_colour_tracks_remediation_not_the_verdict(self):
        """Red on that job means the fix was not produced — the gate job already carries the verdict."""
        self.assertEqual(self.doc["jobs"]["remediate"]["steps"][-1]["with"]["fail-on"], "never")
        self.assertNotIn("fail-on", self.doc["jobs"]["worm-guard"]["steps"][-1]["with"])

    def test_an_absent_count_does_not_reach_the_job_that_can_push(self):
        self.assertIn("needs.worm-guard.outputs.infected != ''", self.doc["jobs"]["remediate"]["if"])

    def test_the_credential_is_passed_under_the_name_the_action_declares(self):
        fix = self.doc["jobs"]["remediate"]["steps"][-1]
        self.assertEqual(fix["with"]["github-token"],
                         "${{ secrets.GH_SECURITY_TOKEN || github.token }}")
        self.assertNotIn("token", fix["with"])

    def test_a_finding_leaves_the_run(self):
        with_ = self.doc["jobs"]["worm-guard"]["steps"][-1]["with"]
        for key in ("pr-comment", "upload-sarif", "upload-artifact"):
            self.assertTrue(with_[key], key)
        self.assertEqual(self.doc["jobs"]["worm-guard"]["permissions"]["security-events"], "write")

    def test_what_setup_writes_grades_clean(self):
        """The generator and the grader agree — otherwise setup installs what check condemns."""
        ref = guard_detect.find_strix({"w.yml": self.wf})
        self.assertFalse(guard_detect.grade_config(ref).degraded)

    def test_pin_drift_job_is_scheduled_and_only_needs_issues_write(self):
        drift = self.doc["jobs"]["pin-drift"]
        self.assertEqual(drift["permissions"], {"contents": "read", "issues": "write"})
        self.assertIn("saw guard drift", " ".join(s.get("run", "") for s in drift["steps"]))
        self.assertIn("schedule", self.doc[True])   # PyYAML parses `on:` as the bool key True

    def test_jobs_are_event_gated_so_they_do_not_overlap(self):
        self.assertEqual(self.doc["jobs"]["worm-guard"]["if"], "github.event_name != 'schedule'")
        self.assertIn("schedule", self.doc["jobs"]["pin-drift"]["if"])

    def test_every_action_is_pinned_by_commit_sha(self):
        # The file we install lands in someone else's repo, in a job holding `contents: write`. A
        # moving tag on ANY step there executes unreviewed code in that context, so the rule is every
        # `uses:`, not just the Strix one — which is the half `saw guard check` grades. Asserted
        # generically so a step added later cannot reintroduce a tag ref unnoticed.
        uses = [step["uses"] for job in self.doc["jobs"].values()
                for step in job["steps"] if "uses" in step]
        self.assertGreaterEqual(len(uses), 4)          # 2 checkouts + setup-python + strix
        for ref in uses:
            self.assertRegex(ref, r"^[\w.-]+/[\w.-]+@[0-9a-f]{40}$",
                             f"{ref} is not pinned to a commit SHA")

    def test_the_generated_workflow_carries_no_commentary(self):
        """What the gate does belongs in the documentation, not in a file written into someone
        else's repository."""
        self.assertNotIn("#", self.wf)

    def test_every_pinned_action_is_a_bare_commit_sha(self):
        for action in (guard.CHECKOUT_ACTION, guard.SETUP_PYTHON_ACTION):
            self.assertIn(f"{action.repo}@{action.sha}\n", self.wf)
            self.assertNotIn(action.tag, self.wf)

    def test_the_scanner_release_is_pinned_in_every_job_that_installs_it(self):
        """A SHA-pinned action whose first act is an unpinned install is not pinned at all."""
        for job in ("worm-guard", "remediate"):
            self.assertEqual(self.doc["jobs"][job]["steps"][-1]["with"]["version"], "0.11.2")
        drift = self.doc["jobs"]["pin-drift"]["steps"][-1]["run"]
        self.assertIn("pip install stayawakebot==0.11.2", drift)
        self.assertIn("saw guard drift", drift)

    def test_setup_refuses_rather_than_provision_an_unpinned_scanner(self):
        with mock.patch.object(guard.provision, "resolve_pin", return_value=guard.Pin(SHA, "v0.1.4")), \
             mock.patch.object(guard.provision, "resolve_scanner_version", return_value=None):
            res = guard.setup(_tmp_repo())
        self.assertIsNone(res.wrote)
        self.assertIn("newest when it runs", res.error)

    def test_repin_preserves_the_two_job_structure(self):
        # A surgical repin must touch ONLY the strix @ref, leaving the remediate/token/drift intact.
        newpin = guard.Pin("b" * 40, "v0.1.5")
        p = guard.plan_setup({guard.WORM_GUARD_FILE: self.wf}, "main", newpin)
        self.assertEqual(p.action, "repin")
        self.assertIn(f"Ndevu12/strix@{'b' * 40}", p.content)
        self.assertIn("remediate: pr", p.content)
        self.assertIn("secrets.GH_SECURITY_TOKEN", p.content)
        self.assertIn("saw guard drift", p.content)


class TestGuardDrift(unittest.TestCase):
    """`drift_one`: grade one repo (via `detect.check`) → ONE self-closing tracking issue. Recognizes
    a gate by ANY mechanism, and only files issues for the gradeable Strix-action pin."""

    REF = StrixRef(workflow=".github/workflows/worm-guard.yml", job="worm-guard", ref=SHA, pin="sha")

    def _strix(self, state, latest="v0.1.5"):
        return GuardStatus(present=True, ref=self.REF,
                           fresh=guard.Freshness(state, latest, f"latest {latest}"))

    def _run(self, status, *, existing=None):
        calls = {"created": [], "updated": [], "commented": []}
        open_issues = ([{"number": existing, "title": guard.pindrift.DRIFT_TITLE}] if existing else [])
        with mock.patch.object(guard.pindrift.detect, "check", return_value=status), \
             mock.patch.object(guard.pindrift, "_resolve_slug", return_value=("o", "r")), \
             mock.patch.object(guard.pindrift.github_api, "list_open_issues", return_value=open_issues), \
             mock.patch.object(guard.pindrift.github_api, "create_issue",
                               side_effect=lambda *a, **k: calls["created"].append((a, k)) or {"number": 7}), \
             mock.patch.object(guard.pindrift.github_api, "update_issue",
                               side_effect=lambda *a, **k: calls["updated"].append((a, k)) or {}), \
             mock.patch.object(guard.pindrift.github_api, "add_issue_comment",
                               side_effect=lambda *a, **k: calls["commented"].append((a, k)) or {}):
            outcome = guard.drift_one(repo=".", token="t")
        return outcome, calls

    def test_behind_opens_a_new_issue(self):
        o, calls = self._run(self._strix("behind"), existing=None)
        self.assertEqual((o.state, o.action), ("behind", "opened"))
        self.assertEqual(len(calls["created"]), 1)
        self.assertEqual(calls["created"][0][1].get("labels"), [guard.pindrift.DRIFT_LABEL])

    def test_behind_with_existing_issue_refreshes_not_duplicates(self):
        o, calls = self._run(self._strix("behind"), existing=42)
        self.assertEqual(o.action, "refreshed")
        self.assertEqual(calls["created"], [])              # no duplicate
        self.assertEqual(len(calls["updated"]), 1)          # silent body refresh
        self.assertNotIn("state", calls["updated"][0][1])   # refresh, not a close

    def test_fresh_closes_an_open_issue(self):
        o, calls = self._run(self._strix("fresh"), existing=42)
        self.assertEqual(o.action, "closed")
        self.assertEqual(calls["updated"][0][1].get("state"), "closed")
        self.assertEqual(len(calls["commented"]), 1)        # notifies on the close

    def test_fresh_with_no_issue_does_nothing(self):
        o, calls = self._run(self._strix("fresh"), existing=None)
        self.assertEqual((o.state, o.action), ("fresh", "none"))
        self.assertEqual((calls["created"], calls["updated"]), ([], []))

    def test_unknown_never_churns_the_issue(self):
        # a transient releases-API failure must not open OR close anything
        o, calls = self._run(self._strix("unknown"), existing=42)
        self.assertEqual(o.state, "unknown")
        self.assertEqual((calls["created"], calls["updated"], calls["commented"]), ([], [], []))

    def test_non_strix_gate_is_protected_no_issue(self):
        # A repo guarded by a LOCAL action (not Ndevu12/strix) is PROTECTED — recognized (not "no
        # gate"), opens NO issue; its release pin just isn't freshness-trackable.
        st = GuardStatus(present=True, ref=None, mechanism="local-action",
                         gate_file=".github/workflows/worm-guard.yml")
        o, calls = self._run(st)
        self.assertEqual(o.state, "not-strix")
        self.assertEqual((calls["created"], calls["updated"]), ([], []))

    def test_non_strix_gate_closes_a_stale_protection_issue(self):
        # If a repo was flagged unprotected and later gains a (non-Strix) gate, close the issue.
        st = GuardStatus(present=True, ref=None, mechanism="local-action", gate_file="w.yml")
        o, calls = self._run(st, existing=42)
        self.assertEqual(o.action, "closed")
        self.assertEqual(calls["updated"][0][1].get("state"), "closed")

    def test_no_gate_opens_a_protection_issue(self):
        # THE point of "ensure the repo is gated": an UNPROTECTED repo (no gate) files an issue.
        o, calls = self._run(GuardStatus(present=False))
        self.assertEqual((o.state, o.action), ("no-gate", "opened"))
        self.assertEqual(len(calls["created"]), 1)
        self.assertEqual(calls["created"][0][1].get("labels"), [guard.pindrift.DRIFT_LABEL])
        self.assertIn("unprotected", " ".join(str(a) for a in calls["created"][0][0]).lower())

    def test_no_ci_opens_a_protection_issue(self):
        o, calls = self._run(GuardStatus(present=False, no_ci=True))
        self.assertEqual((o.state, o.action), ("no-ci", "opened"))
        self.assertEqual(len(calls["created"]), 1)

    def test_remote_read_error_never_churns(self):
        o, calls = self._run(GuardStatus(present=False, error="rate limited"), existing=42)
        self.assertEqual(o.state, "error")
        self.assertEqual((calls["created"], calls["updated"]), ([], []))


class TestDriftSweep(unittest.TestCase):
    """`drift_targets` — the sweep wiring (like `check_targets`)."""

    def test_no_local_repos_is_calm_zero(self):
        with mock.patch.object(guard.sweep, "_guard_config", return_value={}), \
             mock.patch.object(guard.sweep.resolution, "discover_local_repos", return_value=[]):
            self.assertEqual(guard.drift_targets(no_stream=True), 0)

    def test_remote_sweep_drifts_each_slug(self):
        seen = []
        with mock.patch.object(guard.sweep, "_guard_config", return_value={}), \
             mock.patch.object(guard.sweep.resolution, "resolve_remote",
                               return_value=(["o/a", "o/b"], "tok", "env")), \
             mock.patch.object(guard.sweep, "latest_strix", return_value=guard.LatestStrix("v1")), \
             mock.patch.object(guard.sweep, "drift_one",
                               side_effect=lambda **k: seen.append(k["slug"]) or
                               guard.DriftOutcome(k["slug"], "fresh")):
            rc = guard.drift_targets(remote=True, slugs=["o/a", "o/b"], no_stream=True)
        self.assertEqual(rc, 0)
        self.assertEqual(seen, ["o/a", "o/b"])


def _tmp_repo():
    import subprocess
    d = Path(tempfile.mkdtemp())
    subprocess.run(["git", "init", "-q", str(d)], check=True)
    return d


@contextlib.contextmanager
def _released():
    """Stub both releases setup resolves — the action SHA and the scanner version. Without the
    second, these tests reach the network and pass or fail on whether this machine has one."""
    with mock.patch.object(guard.provision, "resolve_pin", return_value=guard.Pin(SHA, "v0.1.4")), \
         mock.patch.object(guard.provision, "resolve_scanner_version", return_value="0.11.2"):
        yield


class TestSetupLocal(unittest.TestCase):
    def _resolve(self):
        return _released()

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
        with mock.patch.object(guard.provision, "resolve_pin", return_value=None):
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
        from stayawake.core.identity import Decision, Intent
        from stayawake.lib.git.write.commit import CommitResult
        allow = Decision(allowed=True, intent=Intent.OPEN_GUARD_PR)
        with _released(), \
             mock.patch.object(guard.gitutil, "default_branch", return_value="main"), \
             mock.patch.object(guard.gitutil, "origin_slug", return_value=origin), \
             mock.patch.object(guard.gitutil, "ref_exists", return_value=False), \
             mock.patch.object(guard.gitutil, "fetch", return_value=True), \
             mock.patch.object(guard.gitutil, "add_worktree", return_value=True), \
             mock.patch.object(guard.gitutil, "remove_worktree", return_value=True), \
             mock.patch.object(guard.gitutil, "stage_all", return_value=True), \
             mock.patch.object(guard.gitutil, "commit_fix",
                               return_value=CommitResult(committed=True, signed=signed)), \
             mock.patch("stayawake.core.identity.require", return_value=allow), \
             mock.patch.object(guard.proposal, "submit_change_pr", return_value=submit) as sub:
            res = guard.setup(_tmp_repo(), token="tok", pr=True)
        return res, sub

    def test_opens_pr_via_ladder(self):
        from stayawake.core.proposal import SubmitResult
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
        from stayawake.core.proposal import SubmitResult
        res, _ = self._run(SubmitResult("pr", action="opened", number=7, url="u"), signed=False)
        self.assertFalse(res.signed)
        self.assertIn("UNSIGNED", guard.render_setup(res))

    def test_pr_plans_against_origin_not_a_dirty_working_tree(self):
        # The bug: `saw guard setup --pr` planned from the WORKING TREE. A worm-guard.yml written by a
        # prior local `setup` (untracked, never on origin) made `--pr` see the gate as already-there and
        # no-op — so it "reported" success while opening no PR. `--pr` must plan against origin's tree.
        from stayawake.core.proposal import SubmitResult
        repo = _tmp_repo()
        wf = Path(repo) / guard.WORM_GUARD_FILE                 # an UNTRACKED gate in the working tree…
        wf.parent.mkdir(parents=True, exist_ok=True)
        wf.write_text("name: Worm Guard\non: pull_request\njobs: {}\n", encoding="utf-8")
        with _released(), \
             mock.patch.object(guard.gitutil, "default_branch", return_value="main"), \
             mock.patch.object(guard.gitutil, "origin_slug", return_value="up/repo"), \
             mock.patch.object(guard.gitutil, "ref_exists", return_value=True), \
             mock.patch.object(guard.gitutil, "fetch", return_value=True), \
             mock.patch.object(guard.gitutil, "list_tree", return_value=[]), \
             mock.patch.object(guard.provision, "_setup_pr",
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
        cms = [mock.patch.object(guard.sweep, "latest_strix", return_value=guard.LatestStrix("v1", SHA)),
               mock.patch.object(guard.auth, "resolve_token", return_value=token)]
        if discover is not None:
            cms.append(mock.patch.object(guard.resolution, "discover_local_repos", return_value=discover))
        if resolve is not None:
            cms.append(mock.patch.object(guard.resolution, "resolve_remote", return_value=resolve))
        chk = mock.patch.object(guard.sweep, "check",
                                side_effect=check_side) if check_side else \
            mock.patch.object(guard.sweep, "check", return_value=check_return)
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


DEGRADED_WF = """name: Worm guard
on: { push: { branches: [main] }, pull_request: {} }
permissions: {}
jobs:
  worm-guard:
    runs-on: ubuntu-latest
    permissions:
      contents: write
      pull-requests: write
    steps:
      - uses: Ndevu12/strix@%s
        with:
          remediate: pr
          token: ${{ secrets.GH_SECURITY_TOKEN || github.token }}
""" % ("c" * 40)


SILENT_WF = DEGRADED_WF.replace("          remediate: pr\n",
                                "          remediate: pr\n          fail-on: never\n")

REPORT_ONLY_WF = """name: Worm guard
on: { push: { branches: [main] }, pull_request: {} }
permissions: {}
jobs:
  worm-guard:
    runs-on: ubuntu-latest
    permissions:
      contents: read
    steps:
      - uses: Ndevu12/strix@%s
        with:
          fail-on: never
""" % ("c" * 40)


class TestGradeConfig(unittest.TestCase):
    """A gate can be present, SHA-pinned and fresh while discarding its credential and reporting
    nowhere — the shape every repository provisioned before this change is running."""

    def _graded(self, wf):
        return guard_detect.grade_config(find_strix({guard.WORM_GUARD_FILE: wf}))

    def test_an_input_the_action_does_not_declare_is_reported(self):
        self.assertEqual(self._graded(DEGRADED_WF).ignored_inputs, ("token",))

    def test_a_gate_that_neither_delivers_nor_fails_the_merge_reports_nothing(self):
        self.assertTrue(self._graded(SILENT_WF).reports_nothing)

    def test_a_gate_whose_required_check_is_the_delivery_is_healthy(self):
        ref = find_strix({guard.WORM_GUARD_FILE: DEGRADED_WF})
        cfg = guard_detect.grade_config(ref)
        self.assertTrue(cfg.reports_nothing)
        clean = guard_detect.GateConfig(reports_nothing=True)
        self.assertTrue(GuardStatus(present=True, ref=ref, config=clean, required=True).healthy)

    def test_a_gate_that_delivers_nothing_and_is_not_required_is_not_healthy(self):
        ref = find_strix({guard.WORM_GUARD_FILE: DEGRADED_WF})
        clean = guard_detect.GateConfig(reports_nothing=True)
        self.assertFalse(GuardStatus(present=True, ref=ref, config=clean, required=False).healthy)

    def test_a_gate_that_delivers_nothing_and_fails_no_merge_is_not_healthy(self):
        ref = find_strix({guard.WORM_GUARD_FILE: REPORT_ONLY_WF})
        cfg = guard_detect.grade_config(ref)
        self.assertEqual((cfg.ignored_inputs, cfg.standing_write), ((), False))
        self.assertTrue(cfg.report_only and cfg.reports_nothing)
        self.assertFalse(GuardStatus(present=True, ref=ref, config=cfg, required=True).healthy)

    def test_the_same_gate_is_healthy_once_something_carries_the_finding(self):
        wf = REPORT_ONLY_WF.replace("          fail-on: never\n", "          pr-comment: true\n")
        ref = find_strix({guard.WORM_GUARD_FILE: wf})
        cfg = guard_detect.grade_config(ref)
        self.assertTrue(GuardStatus(present=True, ref=ref, config=cfg, required=True).healthy)

    def test_an_unreadable_fail_on_is_not_read_as_report_only(self):
        wf = SILENT_WF.replace("fail-on: never", "fail-on: ${{ vars.WANTED }}")
        cfg = self._graded(wf)
        self.assertFalse(cfg.report_only)
        self.assertIn("fail-on", cfg.unresolved)

    def test_a_job_that_grants_itself_nothing_is_unstated_not_proven_safe(self):
        wf = DEGRADED_WF.replace("permissions: {}\n", "")
        wf = wf.replace("    permissions:\n      contents: write\n"
                        "      pull-requests: write\n", "")
        cfg = self._graded(wf)
        self.assertFalse(cfg.standing_write)
        self.assertTrue(cfg.write_unstated)
        self.assertTrue(cfg.unknown)

    def test_a_configuration_decided_at_run_time_is_reported_as_unknown(self):
        wf = SILENT_WF.replace("          fail-on: never\n",
                               "          pr-comment: ${{ vars.X }}\n")
        ref = find_strix({guard.WORM_GUARD_FILE: wf})
        cfg = guard_detect.grade_config(ref)
        self.assertEqual(cfg.unresolved, ("pr-comment",))
        out = guard.render(GuardStatus(present=True, ref=ref, config=cfg))
        self.assertIn("decided when the workflow runs", out)

    def test_any_one_reporting_input_is_enough(self):
        for key in guard_detect.INPUTS_THAT_REPORT_A_FINDING:
            wf = SILENT_WF.replace("remediate: pr", f"remediate: pr\n          {key}: true")
            self.assertFalse(self._graded(wf).reports_nothing, key)

    def test_a_reporting_input_resolved_at_run_time_is_not_read_as_off(self):
        for key in guard_detect.INPUTS_THAT_REPORT_A_FINDING:
            wf = SILENT_WF.replace("remediate: pr",
                                   f"remediate: pr\n          {key}: ${{{{ vars.WANTED }}}}")
            self.assertFalse(self._graded(wf).reports_nothing, key)

    def test_an_input_key_in_another_case_is_read_as_that_input(self):
        wf = SILENT_WF.replace("          remediate: pr\n", "          Upload-Sarif: true\n")
        graded = self._graded(wf)
        self.assertEqual(graded.ignored_inputs, ("token",))
        self.assertFalse(graded.reports_nothing)

    def test_an_input_the_action_does_not_take_condemns_the_gate_but_licenses_no_rewrite(self):
        wf = SILENT_WF.replace("          fail-on: never\n", "          pr-comment: true\n")
        wf = wf.replace("    permissions:\n      contents: write\n      pull-requests: write",
                        "    permissions:\n      contents: read\n      pull-requests: write")
        graded = self._graded(wf)
        self.assertEqual(graded.ignored_inputs, ("token",))
        self.assertTrue(graded.degraded)
        self.assertFalse(graded.needs_rewriting)

    def test_a_scanning_job_holding_contents_write_is_reported(self):
        self.assertTrue(self._graded(DEGRADED_WF).standing_write)

    def test_write_all_counts_as_standing_write(self):
        wf = DEGRADED_WF.replace("    permissions:\n      contents: write\n"
                                 "      pull-requests: write", "    permissions: write-all")
        self.assertTrue(self._graded(wf).standing_write)

    def test_permissions_absent_is_not_a_claim_either_way(self):
        wf = DEGRADED_WF.replace("    permissions:\n      contents: write\n"
                                 "      pull-requests: write\n", "")
        self.assertFalse(self._graded(wf).standing_write)

    def test_a_degraded_gate_is_not_healthy(self):
        ref = find_strix({guard.WORM_GUARD_FILE: DEGRADED_WF})
        st = GuardStatus(present=True, ref=ref, config=guard_detect.grade_config(ref))
        self.assertFalse(st.healthy)

    def test_the_report_names_each_defect_and_what_fixes_it(self):
        ref = find_strix({guard.WORM_GUARD_FILE: DEGRADED_WF})
        out = guard.render(GuardStatus(present=True, ref=ref,
                                       config=guard_detect.grade_config(ref)))
        for phrase in ("token", "write access on every run", "saw guard setup"):
            self.assertIn(phrase, out)

    def test_the_report_names_a_gate_that_tells_nobody(self):
        ref = find_strix({guard.WORM_GUARD_FILE: SILENT_WF})
        out = guard.render(GuardStatus(present=True, ref=ref,
                                       config=guard_detect.grade_config(ref)))
        self.assertIn("reports nowhere", out)

    def test_write_granted_at_workflow_level_counts_against_the_job_that_inherits_it(self):
        wf = DEGRADED_WF.replace("permissions: {}", "permissions:\n  contents: write")
        wf = wf.replace("    permissions:\n      contents: write\n"
                        "      pull-requests: write\n", "")
        self.assertTrue(self._graded(wf).standing_write)

    def test_a_job_declaring_its_own_permissions_does_not_inherit_the_workflow_grant(self):
        wf = DEGRADED_WF.replace("permissions: {}", "permissions:\n  contents: write")
        wf = wf.replace("    permissions:\n      contents: write\n"
                        "      pull-requests: write\n",
                        "    permissions:\n      contents: read\n")
        self.assertFalse(self._graded(wf).standing_write)


class TestWhichOccurrenceAnswersForTheRepository(unittest.TestCase):
    """Which `uses: Ndevu12/strix` occurrence `saw guard check` answers for."""

    def _rendered(self):
        return guard.render_workflow(guard.Pin("c" * 40, "v0.1.4"), "main", "0.11.2")

    def test_the_generated_gate_answers_with_its_scanning_job(self):
        ref = find_strix({guard.WORM_GUARD_FILE: self._rendered()})
        self.assertEqual(ref.job, "worm-guard")
        self.assertFalse(guard_detect.grade_config(ref).degraded)

    def test_reordering_the_jobs_does_not_change_the_answer(self):
        import yaml
        doc = yaml.safe_load(self._rendered())
        doc["jobs"] = {k: doc["jobs"][k] for k in ("remediate", "pin-drift", "worm-guard")}
        ref = find_strix({guard.WORM_GUARD_FILE: yaml.safe_dump(doc)})
        self.assertEqual(ref.job, "worm-guard")
        self.assertFalse(guard_detect.grade_config(ref).degraded)

    def test_a_degraded_gate_elsewhere_answers_over_a_tidy_one(self):
        ref = find_strix({".github/workflows/ci.yml": DEGRADED_WF,
                          guard.WORM_GUARD_FILE: self._rendered()})
        self.assertEqual(ref.workflow, ".github/workflows/ci.yml")
        self.assertTrue(guard_detect.grade_config(ref).degraded)

    def test_an_occurrence_that_cannot_run_on_a_change_does_not_answer(self):
        manual = DEGRADED_WF.replace("on: { push: { branches: [main] }, pull_request: {} }",
                                     "on: { workflow_dispatch: {} }")
        ref = find_strix({".github/workflows/z-manual.yml": manual,
                          guard.WORM_GUARD_FILE: self._rendered()})
        self.assertEqual(ref.workflow, guard.WORM_GUARD_FILE)

    def test_a_switched_off_job_does_not_condemn_a_healthy_live_gate(self):
        off = DEGRADED_WF.replace("  worm-guard:\n", "  worm-guard:\n    if: false\n")
        ref = find_strix({".github/workflows/a-disabled.yml": off,
                          guard.WORM_GUARD_FILE: self._rendered()})
        self.assertEqual(ref.workflow, guard.WORM_GUARD_FILE)
        self.assertFalse(guard_detect.grade_config(ref).degraded)

    def test_a_tidy_disabled_job_cannot_shield_a_degraded_gate_in_the_same_file(self):
        wf = DEGRADED_WF + self._rendered().split("jobs:\n")[1].split("\n\n")[0].replace(
            "  worm-guard:\n", "  decoy:\n    if: false\n")
        pin = guard.Pin("d" * 40, "v0.1.5")
        plan = guard.plan_setup({guard.WORM_GUARD_FILE: wf}, "main", pin, scanner="0.11.2")
        self.assertEqual(plan.action, "repair")

    def test_every_occurrence_is_still_available(self):
        refs = guard_detect.find_strix_refs({guard.WORM_GUARD_FILE: self._rendered()})
        self.assertEqual([r.job for r in refs], ["worm-guard", "remediate"])


class TestSetupRepairsADegradedGate(unittest.TestCase):
    def test_a_degraded_gate_at_saws_own_path_is_repaired_not_left_alone(self):
        pin = guard.Pin("c" * 40, "v0.1.4")
        plan = guard.plan_setup({guard.WORM_GUARD_FILE: DEGRADED_WF}, "main", pin, scanner="0.11.2")
        import yaml
        self.assertEqual(plan.action, "repair")
        for job in yaml.safe_load(plan.content)["jobs"].values():
            for step in job.get("steps", []):
                with_ = step.get("with") or {}
                self.assertNotIn("token", with_)
        self.assertIn("token", plan.detail)

    def test_the_repaired_gate_grades_clean(self):
        pin = guard.Pin("c" * 40, "v0.1.4")
        plan = guard.plan_setup({guard.WORM_GUARD_FILE: DEGRADED_WF}, "main", pin, scanner="0.11.2")
        ref = find_strix({guard.WORM_GUARD_FILE: plan.content})
        self.assertFalse(guard_detect.grade_config(ref).degraded)

    def test_an_unknown_input_alone_does_not_trigger_a_rewrite(self):
        wf = DEGRADED_WF.replace("      contents: write\n", "      contents: read\n")
        wf = wf.replace("          remediate: pr\n", "          remediate: pr\n          pr-comment: true\n")
        pin = guard.Pin("c" * 40, "v0.1.4")
        plan = guard.plan_setup({guard.WORM_GUARD_FILE: wf}, "main", pin, scanner="0.11.2")
        self.assertNotEqual(plan.action, "repair")

    def test_the_operator_is_told_why_the_file_was_replaced(self):
        pin = guard.Pin("c" * 40, "v0.1.4")
        plan = guard.plan_setup({guard.WORM_GUARD_FILE: DEGRADED_WF}, "main", pin, scanner="0.11.2")
        body = guard.provision._setup_pr_body(plan, "main")
        self.assertIn("Rewrites the configuration of", body)
        self.assertIn("are not preserved", body)
        written = guard.render_setup(guard.SetupResult(plan=plan, wrote=Path("/x")))
        self.assertIn("Replaced because", written)

    def test_a_degraded_gate_elsewhere_is_named_but_its_file_is_not_rewritten(self):
        pin = guard.Pin("c" * 40, "v0.1.4")
        plan = guard.plan_setup({".github/workflows/theirs.yml": DEGRADED_WF}, "main", pin,
                                scanner="0.11.2")
        self.assertNotEqual(plan.action, "repair")
        self.assertIn("token", plan.detail)


class TestSetupSweep(unittest.TestCase):
    """`saw guard setup` sweeps many repos: local discovery (write/PR each) or remote (clone → PR)."""

    def _ok(self):
        return guard.SetupResult(plan=guard.SetupPlan("create", "wf", new_ref=SHA), wrote=Path("/x"))

    def _allow_guard(self):
        from stayawake.core.identity import Decision, Intent
        return mock.patch("stayawake.core.identity.require",
                          return_value=Decision(allowed=True, intent=Intent.OPEN_GUARD_PR))

    def test_local_sweep_sets_up_each_discovered_repo(self):
        with mock.patch.object(guard.sweep, "resolve_pin", return_value=guard.Pin(SHA, "v0.1.4")), \
             mock.patch.object(guard.sweep, "resolve_scanner_version", return_value="0.11.2"), \
             mock.patch.object(guard.resolution, "discover_local_repos",
                               return_value=[Path("/a"), Path("/b")]), \
             mock.patch.object(guard.auth, "resolve_token", return_value=(None, None)), \
             mock.patch.object(guard.sweep, "setup", side_effect=lambda *a, **k: self._ok()) as s:
            rc = guard.setup_targets(paths=["."], no_stream=True)
        self.assertEqual(rc, 0)
        self.assertEqual(s.call_count, 2)

    def test_one_repo_error_isolated_but_exits_one(self):
        with mock.patch.object(guard.sweep, "resolve_pin", return_value=guard.Pin(SHA, "v0.1.4")), \
             mock.patch.object(guard.sweep, "resolve_scanner_version", return_value="0.11.2"), \
             mock.patch.object(guard.resolution, "discover_local_repos",
                               return_value=[Path("/a"), Path("/b")]), \
             mock.patch.object(guard.auth, "resolve_token", return_value=(None, None)), \
             mock.patch.object(guard.sweep, "setup", side_effect=[RuntimeError("boom"), self._ok()]) as s:
            rc = guard.setup_targets(paths=["."], no_stream=True)
        self.assertEqual(s.call_count, 2)                    # second repo still attempted
        self.assertEqual(rc, 1)                              # an errored repo → exit 1

    def test_remote_clones_and_sets_up_with_pr_implied(self):
        with mock.patch.object(guard.sweep, "resolve_pin", return_value=guard.Pin(SHA, "v0.1.4")), \
             mock.patch.object(guard.sweep, "resolve_scanner_version", return_value="0.11.2"), \
             mock.patch.object(guard.resolution, "resolve_remote",
                               return_value=(["o/a", "o/b"], "t", "env")), \
             mock.patch.object(guard.resolution, "cloned_repo",
                               side_effect=lambda *a, **k: _fake_clone(Path("/clone"))), \
             self._allow_guard(), \
             mock.patch.object(guard.sweep, "setup", side_effect=lambda *a, **k: self._ok()) as s:
            rc = guard.setup_targets(remote=True, no_stream=True)
        self.assertEqual(rc, 0)
        self.assertEqual(s.call_count, 2)
        self.assertTrue(s.call_args.kwargs.get("pr"))        # a remote repo has no working tree → always PR

    def test_remote_without_token_exits_two(self):
        with mock.patch.object(guard.resolution, "resolve_remote", return_value=(["o/a"], None, None)):
            self.assertEqual(guard.setup_targets(remote=True, no_stream=True), 2)

    def test_remote_clone_failure_is_an_error(self):
        with mock.patch.object(guard.sweep, "resolve_pin", return_value=guard.Pin(SHA, "v0.1.4")), \
             mock.patch.object(guard.sweep, "resolve_scanner_version", return_value="0.11.2"), \
             mock.patch.object(guard.resolution, "resolve_remote", return_value=(["o/a"], "t", "env")), \
             mock.patch.object(guard.resolution, "cloned_repo",
                               side_effect=lambda *a, **k: _fake_clone(None)), \
             self._allow_guard(), \
             mock.patch.object(guard.sweep, "setup") as s:
            rc = guard.setup_targets(remote=True, no_stream=True)
        self.assertEqual(rc, 1)                              # clone failed → error → exit 1
        s.assert_not_called()                                # never setup on a failed clone

    def test_pushed_but_unopened_pr_is_not_counted_as_success(self):
        # The ladder returns a SubmitResult even when the branch pushed but the PR API call failed
        # (or the fork wasn't ready, or there was no write access). That is NOT an opened PR — it must
        # not be tallied as "opened/updated", and the sweep must exit non-zero, not phantom-succeed.
        from stayawake.core.proposal import SubmitResult
        failed = guard.SetupResult(plan=guard.SetupPlan("create", "wf", new_ref=SHA),
                                   submit=SubmitResult("pr-create-failed"))
        with mock.patch.object(guard.sweep, "resolve_pin", return_value=guard.Pin(SHA, "v0.1.4")), \
             mock.patch.object(guard.sweep, "resolve_scanner_version", return_value="0.11.2"), \
             mock.patch.object(guard.resolution, "resolve_remote", return_value=(["o/a"], "t", "env")), \
             mock.patch.object(guard.resolution, "cloned_repo",
                               side_effect=lambda *a, **k: _fake_clone(Path("/clone"))), \
             self._allow_guard(), \
             mock.patch.object(guard.sweep, "setup", side_effect=lambda *a, **k: failed):
            rc = guard.setup_targets(remote=True, no_stream=True)
        self.assertEqual(rc, 1)                              # pushed-but-unopened → failure, not success

    def test_invalid_slug_exits_two(self):
        self.assertEqual(guard.setup_targets(remote=True, slugs=["not-a-slug"], no_stream=True), 2)

    def test_missing_explicit_config_exits_two(self):
        self.assertEqual(guard.setup_targets(config_path="/no/such.yml", no_stream=True), 2)


if __name__ == "__main__":
    unittest.main()
