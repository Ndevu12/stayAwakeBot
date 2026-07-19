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


if __name__ == "__main__":
    unittest.main()
