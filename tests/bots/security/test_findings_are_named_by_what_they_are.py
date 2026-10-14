#!/usr/bin/env python3
"""`saw scan` and the infected warning of saw's hooks name each finding by what it is and where it
is, and show a short preview of what was found."""
from __future__ import annotations

import contextlib
import io
import unittest
from pathlib import Path
from unittest import mock

import yaml

from stayawake.bots.security import found, hook
from stayawake.bots.security.models import Finding, ScanReport, ScanResult, Severity
from stayawake.bots.security.sinks.render import render_terminal

_SIGNATURES = (Path(found.__file__).parent / "data" / "signatures.yml")
_PAYLOAD = "first line of the file " + "z" * 200


def _loader(**changes):
    fields = dict(signature_id="loader-seed-var", category="code-loader", severity=Severity.CRITICAL,
                  path="postcss.config.mjs", description="d", line=3, evidence=_PAYLOAD)
    fields.update(changes)
    return Finding(**fields)


def _merge():
    return Finding(signature_id="evil-merge", category="evil-merge", severity=Severity.HIGH,
                   path="2a1a8e040e", description="d", commit_sha="2a1a8e040e" + "0" * 30,
                   evidence="adds two files", composed_evidence=True)


def _terminal(*findings) -> str:
    report = ScanReport(generated_at="t", results=[
        ScanResult(target="repo", source="remote", findings=list(findings))])
    return render_terminal(report.to_payload(), detail=True)


class TestEveryFindingHasItsOwnWords(unittest.TestCase):
    def test_every_signature_has_words_of_its_own(self):
        for signature in yaml.safe_load(_SIGNATURES.read_text())["signatures"]:
            self.assertIsInstance(signature.get("shown_as"), str, signature["id"])
            self.assertEqual(found.what_it_is(signature["id"], "not-a-category"),
                             signature["shown_as"])

    def test_a_finding_without_words_of_its_own_still_reads_in_plain_words(self):
        categories = {s["category"] for s in yaml.safe_load(_SIGNATURES.read_text())["signatures"]}
        for category in categories | {"remediation-residue"}:
            self.assertNotEqual(found.what_it_is("not-a-signature", category),
                                found.what_it_is("not-a-signature", "not-a-category"), category)

    def test_no_words_name_a_worm_or_anything_but_the_tools_they_are_about(self):
        tools = {"Claude", "Code", "Dependabot", "CI", "SSH", "AI"}
        every = [s["shown_as"] for s in yaml.safe_load(_SIGNATURES.read_text())["signatures"]]
        every += list(found._WHAT_IT_IS.values()) + [found._ANY_OTHER]
        for words in every:
            names = {w.strip(".,;'") for w in words.replace("-", " ").split() if w[:1].isupper()} - tools
            self.assertEqual(names, set(), words)

    def test_malicious_code_reads_apart_from_the_ordinary_kind(self):
        self.assertNotEqual(found.what_it_is("git-exec-payload", "git-exec"),
                            found.what_it_is("git-exec-runs", "git-exec"))
        self.assertIn("malicious", found.what_it_is("git-exec-payload", "git-exec"))

    def test_a_finding_to_review_reads_as_one_and_a_confirmed_one_does_not(self):
        to_review = ("may", "looks like", "check it", "mention")
        for signature in yaml.safe_load(_SIGNATURES.read_text())["signatures"]:
            words = signature["shown_as"]
            if signature["confidence"] == "heuristic":
                self.assertTrue(any(cue in words for cue in to_review), signature["id"])
            if signature["confidence"] == "confirmed":
                self.assertNotIn("check it", words, signature["id"])

    def test_a_task_that_hides_itself_reads_apart_from_an_ordinary_one(self):
        self.assertIn("hides itself", found.what_it_is("vscode-task-folderopen-exec", "vscode-autorun"))
        self.assertNotIn("hides itself", found.what_it_is("vscode-task-autorun-visible", "vscode-autorun"))

    def test_a_wipe_says_whether_the_files_can_be_recovered(self):
        self.assertIn("can be recovered", found.what_it_is("destructive-home-wipe", "destructive"))
        self.assertIn("cannot be recovered", found.what_it_is("secure-home-wipe", "destructive"))


class TestTheScanNamesWhatItFound(unittest.TestCase):
    def test_a_finding_is_named_by_what_it_is_and_where(self):
        out = _terminal(_loader())
        self.assertIn("hidden code that loads and runs a payload  —  postcss.config.mjs:3", out)
        self.assertNotIn("loader-seed-var", out)

    def test_a_commit_is_named_as_a_commit(self):
        out = _terminal(_merge())
        self.assertIn("a merge commit that adds code of its own; check it  —  commit 2a1a8e040e", out)
        self.assertIn("found: `adds two files`", out)

    def test_what_was_found_is_a_short_preview_never_the_whole_payload(self):
        out = _terminal(_loader())
        self.assertIn("found: `first line of the file zzz", out)
        self.assertIn("…`", out)
        self.assertNotIn(_PAYLOAD, out)
        self.assertNotIn("sha256:", out)
        self.assertNotIn("preview=", out)


class TestTheWordsSayWhatToKnow(unittest.TestCase):
    def test_an_ai_assistant_hook_names_the_assistant_and_when_it_runs(self):
        for signature_id in ("claude-hook-runs-payload", "claude-hook-autorun"):
            words = found.what_it_is(signature_id, "agent-autorun")
            self.assertIn("Claude Code", words, signature_id)
            self.assertIn("in this folder", words, signature_id)

    def test_a_wipe_says_what_happens_if_it_has_run(self):
        for signature_id in ("destructive-home-wipe", "secure-home-wipe"):
            self.assertIn("if it has run", found.what_it_is(signature_id, "destructive"), signature_id)

    def test_words_that_could_not_be_read_are_read_again_next_time(self):
        found._packaged_words.cache_clear()
        self.addCleanup(found._packaged_words.cache_clear)
        with mock.patch.object(found, "load_signatures", side_effect=OSError("unreadable")):
            self.assertEqual(found.what_it_is("git-exec-payload", "git-exec"),
                             found.what_it_is("not-a-signature", "git-exec"))
        self.assertIn("malicious", found.what_it_is("git-exec-payload", "git-exec"))


class TestTheInfectedWarningNamesWhatItFound(unittest.TestCase):
    def _warning(self, *findings) -> str:
        class _Result:
            pass
        result = _Result()
        result.findings = list(findings)
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            hook._warn_infected("repo", "repo", result)
        return err.getvalue()

    def test_a_confirmed_finding_is_listed_before_findings_to_review(self):
        to_review = [_loader(signature_id="loader-decoder-fn", path=f"r{i}.js", confidence="heuristic")
                     for i in range(5)]
        confirmed = _loader(severity=Severity.LOW, path="certain.js")
        text = self._warning(*to_review, confirmed)
        self.assertIn("certain.js", text)
        self.assertIn("…and 1 more", text)

    def test_it_says_not_to_start_an_ai_assistant_in_the_clone(self):
        self.assertIn("start an AI coding assistant in it", self._warning(_loader()))

    def test_each_finding_is_named_by_what_it_is_and_where(self):
        text = self._warning(_loader(), _merge())
        self.assertIn("hidden code that loads and runs a payload  —  postcss.config.mjs:3", text)
        self.assertIn("a merge commit that adds code of its own; check it  —  commit 2a1a8e040e", text)
        self.assertNotIn("loader-seed-var", text)
        self.assertNotIn("evil-merge", text)


if __name__ == "__main__":
    unittest.main()
