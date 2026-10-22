#!/usr/bin/env python3
"""`saw fix` removes a known-malicious package from the project's manifests only when the operator
says yes, and then from the checkout and the prepared branch alike."""
from __future__ import annotations

import io
import json
import shutil
import subprocess
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

from stayawake.bots.security.dependencies.remediation import MALICIOUS, DependencyAction
from stayawake.bots.security.models import Finding, Severity
from stayawake.bots.security.pr import fix as fixmod
from stayawake.bots.security.pr.dependency_questions import Chooser
from stayawake.bots.security.pr.fix_verdict import (BaseFix, BaseState, Checkout, FixVerdict, Grade,
                                                    render_fix_verdict)
from stayawake.bots.security.pr.resolve import (KEEP, TAKE_OUT, DeliveryAnswer, DependencyAnswer,
                                                DependencyQuestion)
from stayawake.bots.security.remediation import manifest
from stayawake.bots.security.signatures import load_signatures
from stayawake.bots.security.targets.base import ScanOptions
from tests.support.gitrepo import GitSandbox

BAD = "html-to-gutenberg"
CLEAN_MANIFEST = '{\n  "name": "app",\n  "version": "1.0.0",\n  "dependencies": {\n    "left-pad": "1.3.0"\n  }\n}\n'
MANIFEST = ('{\n  "name": "app",\n  "version": "1.0.0",\n  "dependencies": {\n    "left-pad": "1.3.0",\n'
            f'    "{BAD}": "4.2.11"\n  }}\n}}\n')


class _Project(GitSandbox):
    def setUp(self):
        super().setUp()
        self.d = self.new_repo("project", user__name="Tester")
        self.write(self.d, "src/index.js", "export const x = 1;\n")
        self.write(self.d, "package.json", CLEAN_MANIFEST)
        self.commit(self.d, "a clean start")
        self.write(self.d, "package.json", MANIFEST)
        self.commit(self.d, "add a dependency")

    def answering(self, answer):
        asked: list[DependencyQuestion] = []

        def resolve(question):
            if not isinstance(question, DependencyQuestion):
                return None
            asked.append(question)
            if isinstance(answer, Exception):
                raise answer
            return answer

        return resolve, asked

    def run_fix(self, resolver=None):
        with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            return fixmod.prepare_fix(self.d, ScanOptions(), load_signatures(), [], resolver=resolver)

    def in_checkout(self) -> dict:
        return json.loads((self.d / "package.json").read_text())["dependencies"]

    def on_prepared_branch(self) -> dict:
        branches = self.git(self.d, "for-each-ref", "--format=%(refname:short)", "refs/heads/security/")
        branch = branches.split()[0]
        shown = subprocess.run(["git", "-C", str(self.d), "show", f"{branch}:package.json"],
                               capture_output=True, text=True, check=True).stdout
        return json.loads(shown)["dependencies"]


class TestWithNobodyToAsk(_Project):
    def test_the_package_stays_declared_in_the_checkout_and_on_the_prepared_branch(self):
        self.run_fix()
        self.assertIn(BAD, self.in_checkout())
        self.assertIn(BAD, self.on_prepared_branch())

    def test_the_run_is_not_called_done(self):
        self.assertIsNot(Grade.DONE, self.run_fix().grade)


class TestOnATerminal(_Project):
    def test_yes_removes_it_from_the_checkout_and_the_prepared_branch_and_keeps_the_rest(self):
        resolver, _ = self.answering(DependencyAnswer(TAKE_OUT))
        self.run_fix(resolver)
        for declared in (self.in_checkout(), self.on_prepared_branch()):
            self.assertNotIn(BAD, declared)
            self.assertIn("left-pad", declared)

    def test_enter_keeps_it_everywhere(self):
        resolver, _ = self.answering(DependencyAnswer(KEEP))
        v = self.run_fix(resolver)
        self.assertIn(BAD, self.in_checkout())
        self.assertIn(BAD, self.on_prepared_branch())
        self.assertIsNot(Grade.DONE, v.grade)

    def test_each_package_is_asked_about_once_with_where_it_is_declared(self):
        resolver, asked = self.answering(DependencyAnswer(KEEP))
        self.run_fix(resolver)
        self.assertEqual([DependencyQuestion(
            BAD, ("4.2.11",), ("package.json",), (("package.json", CLEAN_MANIFEST),))], asked)

    def test_an_answer_of_another_kind_keeps_it(self):
        resolver, _ = self.answering(DeliveryAnswer(TAKE_OUT, ("package.json",)))
        self.run_fix(resolver)
        self.assertIn(BAD, self.in_checkout())

    def test_a_question_that_fails_keeps_it(self):
        resolver, _ = self.answering(RuntimeError("the terminal went away"))
        self.run_fix(resolver)
        self.assertIn(BAD, self.in_checkout())


class TestTwoKnownMaliciousPackages(_Project):
    OTHER = "fetch-page-assets"

    def setUp(self):
        super().setUp()
        both = MANIFEST.replace(f'    "{BAD}": "4.2.11"\n', f'    "{BAD}": "4.2.11",\n    "{self.OTHER}": "1.2.9"\n')
        self.write(self.d, "package.json", both)
        self.commit(self.d, "add another dependency")

    def answering_by_name(self, yes: set[str]):
        def resolve(question):
            if not isinstance(question, DependencyQuestion):
                return None
            return DependencyAnswer(TAKE_OUT if question.name in yes else KEEP)
        return resolve

    def test_yes_to_both_removes_both_from_the_checkout_and_the_prepared_branch(self):
        self.run_fix(self.answering_by_name({BAD, self.OTHER}))
        for declared in (self.in_checkout(), self.on_prepared_branch()):
            self.assertNotIn(BAD, declared)
            self.assertNotIn(self.OTHER, declared)

    def test_a_kept_package_keeps_the_checkout_from_being_called_clean(self):
        v = self.run_fix(self.answering_by_name({self.OTHER}))
        self.assertIn(BAD, self.in_checkout())
        self.assertNotIn(self.OTHER, self.in_checkout())
        self.assertIsNot(Checkout.CLEANED, v.checkout)
        self.assertIs(Grade.NEEDS_REVIEW, v.grade)


class TestStagedChanges(_Project):
    def test_a_committed_declaration_removed_on_yes_leaves_the_checkout_cleaned(self):
        resolver, _ = self.answering(DependencyAnswer(TAKE_OUT))
        self.assertIs(Checkout.CLEANED, self.run_fix(resolver).checkout)

    def test_a_staged_declaration_keeps_the_checkout_from_being_called_clean(self):
        self.git(self.d, "reset", "-q", "--hard", "HEAD~1")
        self.write(self.d, "package.json", MANIFEST)
        self.git(self.d, "add", "package.json")
        resolver, _ = self.answering(DependencyAnswer(TAKE_OUT))
        v = self.run_fix(resolver)
        self.assertIsNot(Checkout.CLEANED, v.checkout)
        self.assertIs(Grade.NEEDS_REVIEW, v.grade)


    def test_a_declaration_in_a_repository_nested_inside_is_never_called_clean(self):
        self.git(self.d, "reset", "-q", "--hard", "HEAD~1")
        self.write(self.d, ".gitignore", "third_party/\n")
        self.commit(self.d, "ignore vendored code")
        nested = self.new_repo("project/third_party/lib", user__name="Tester")
        self.write(nested, "README.md", "vendored\n")
        self.commit(nested, "start")
        self.write(nested, "package.json", MANIFEST)
        self.git(nested, "add", "package.json")
        resolver, _ = self.answering(DependencyAnswer(TAKE_OUT))
        v = self.run_fix(resolver)
        self.assertIsNot(Checkout.CLEANED, v.checkout)
        self.assertIs(Grade.NEEDS_REVIEW, v.grade)


class TestWhatTheRunReports(_Project):
    def test_a_package_left_declared_is_named_with_the_command_that_removes_it(self):
        text = render_fix_verdict(self.run_fix())
        self.assertIn(f"{BAD}@4.2.11", text)
        self.assertIn(f"npm uninstall {BAD}", text)

    def test_a_package_left_declared_needs_review_whatever_else_was_done(self):
        left = (DependencyAction(f"{BAD}@4.2.11", f"npm uninstall {BAD}"),)
        prepared = BaseFix(BaseState.PREPARED, "o/r: prepared", "main")
        self.assertIs(Grade.DONE, FixVerdict("o/r", prepared, Checkout.CLEANED).grade)
        self.assertIs(Grade.NEEDS_REVIEW,
                      FixVerdict("o/r", prepared, Checkout.CLEANED, kept_packages=left).grade)

    def test_a_removed_package_is_not_named_as_left(self):
        resolver, _ = self.answering(DependencyAnswer(TAKE_OUT))
        self.assertNotIn(f"npm uninstall {BAD}", render_fix_verdict(self.run_fix(resolver)))


class TestOnlyWhatWasShownIsRemoved(_Project):
    def test_the_same_name_in_another_manifest_where_it_is_not_malicious_stays(self):
        self.write(self.d, "packages/web/package.json",
                   f'{{\n  "name": "web",\n  "dependencies": {{\n    "{BAD}": "1.0.0"\n  }}\n}}\n')
        self.commit(self.d, "a workspace")
        resolver, _ = self.answering(DependencyAnswer(TAKE_OUT))
        self.run_fix(resolver)
        self.assertNotIn(BAD, self.in_checkout())
        web = json.loads((self.d / "packages/web/package.json").read_text())["dependencies"]
        self.assertEqual("1.0.0", web[BAD])

    def test_line_endings_are_kept(self):
        self.write(self.d, "package.json", MANIFEST)
        (self.d / "package.json").write_bytes(MANIFEST.replace("\n", "\r\n").encode())
        self.commit(self.d, "windows line endings")
        resolver, _ = self.answering(DependencyAnswer(TAKE_OUT))
        self.run_fix(resolver)
        raw = (self.d / "package.json").read_bytes()
        self.assertNotIn(BAD.encode(), raw)
        self.assertEqual(raw.count(b"\n"), raw.count(b"\r\n"))


def _finding(name: str, path: str = "package.json", state: str = MALICIOUS, version: str = "1.0.0"):
    return Finding("sig", "supply-chain-dep", Severity.CRITICAL, path, "d", dependency_state=state,
                   package=f"{name}@{version}", package_name=name, fix_command=f"npm uninstall {name}")


class TestWhatIsPutToTheOperator(unittest.TestCase):
    def setUp(self):
        self.root = Path(tempfile.mkdtemp(prefix="dep-ask-"))
        self.addCleanup(shutil.rmtree, self.root, ignore_errors=True)

    def _manifest(self, *names: str) -> None:
        deps = ",\n".join(f'    "{n}": "1.0.0"' for n in names)
        (self.root / "package.json").write_text(f'{{\n  "dependencies": {{\n{deps}\n  }}\n}}\n')

    def test_only_a_package_a_manifest_declares_is_asked_about(self):
        found = manifest.declared_malicious([_finding("evil"), _finding("deep", "package-lock.json")])
        self.assertEqual({"evil": (("1.0.0",), ("package.json",))}, found)

    def test_a_manifest_still_declaring_a_malicious_package_is_not_cleared(self):
        self._manifest("worse", "left-pad")
        findings = [_finding("evil"), _finding("worse")]
        self.assertEqual([], manifest.manifests_cleared(self.root, findings, ["package.json"]))
        self._manifest("left-pad")
        self.assertEqual(["package.json"], manifest.manifests_cleared(self.root, findings, ["package.json"]))

    def test_a_manifest_that_was_not_rewritten_is_not_cleared(self):
        self._manifest("left-pad")
        self.assertEqual([], manifest.manifests_cleared(self.root, [_finding("evil")], []))

    def test_without_a_resolver_nothing_is_chosen_and_everything_is_kept(self):
        choose = Chooser(None)
        self.assertEqual(set(), choose([_finding("evil")]))
        self.assertEqual(["evil@1.0.0"], [a.package for a in choose.kept()])

    def test_an_answer_is_reused_for_the_rest_of_the_run(self):
        asked = []

        def resolve(question):
            asked.append(question)
            return DependencyAnswer(TAKE_OUT)

        choose = Chooser(resolve)
        self.assertEqual({"evil"}, choose([_finding("evil")]))
        self.assertEqual({"evil"}, choose([_finding("evil")]))
        self.assertEqual(1, len(asked))
        self.assertEqual((), choose.kept())

    def test_the_question_carries_the_manifest_removing_the_package_would_leave(self):
        self._manifest("evil", "left-pad")
        asked = []

        def resolve(question):
            asked.append(question)
            return DependencyAnswer(KEEP)

        Chooser(resolve, self.root)([_finding("evil")])
        proposed = dict(asked[0].proposed)
        self.assertIn("left-pad", proposed["package.json"])
        self.assertNotIn('"evil"', proposed["package.json"])


if __name__ == "__main__":
    unittest.main()
