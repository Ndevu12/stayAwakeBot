#!/usr/bin/env python3
"""`--ask=jsonl` lets a program answer the questions a terminal asks.

Questions are one JSON object per line on stderr. Answers are one JSON object per line on stdin.
A pipe with the flag is asked; a pipe without it is not. A wrong answer is not an answer.
"""
from __future__ import annotations

import hashlib
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from stayawake.bots.security.pr.fix_verdict import remediation_record
from stayawake.bots.security.pr.resolve import (KEEP, REMOVE, SUPPLY, TAKE_OUT, UNANSWERED,
                                                ArrivedFile, DeliveryQuestion, DependencyQuestion,
                                                UncertainItem)
from stayawake.cli.commands import fix as fixcmd
from stayawake.cli.dispatch import _parsed, build_parser
from stayawake.cli.resolve.build import build_resolver
from stayawake.utils.json_documents import FIX_ASK_SCHEMA_VERSION


class _Pipe:
    """A stream that is not a terminal, with a record of what was written."""

    def __init__(self) -> None:
        self.written = ""

    def isatty(self) -> bool:
        return False

    def readline(self) -> str:
        return ""

    def write(self, text: str) -> None:
        self.written += text

    def flush(self) -> None:
        pass


class _Script(_Pipe):
    """Answers from `replies`, each a dict or a function of the question id. One stream for both."""

    def __init__(self, replies) -> None:
        super().__init__()
        self._replies = list(replies)

    def readline(self) -> str:
        if not self._replies:
            return ""
        reply = self._replies.pop(0)
        question_id = json.loads(self.written.strip().splitlines()[-1])["id"]
        if callable(reply):
            return reply(question_id)
        reply = {**reply, "id": question_id}
        return json.dumps(reply) + "\n"


def _asked(pipe: _Pipe) -> list[dict]:
    return [json.loads(line) for line in pipe.written.splitlines() if line.strip()]


def _delivery() -> DeliveryQuestion:
    return DeliveryQuestion(
        "a" * 40, "2020-01-02", "add files", ("evil.js",),
        (ArrivedFile("ok.js", "b" * 40), ArrivedFile("lib/other.js", "c" * 40)),
        changed=("edited.js",), recorded=True, known_as=("d" * 40,),
        named_by=(("ok.js", 2),))


def _package() -> DependencyQuestion:
    return DependencyQuestion(
        "left-pad", ("1.0.0",), ("package.json", "packages/app/package.json"),
        (("package.json", '{\n  "dependencies": {}\n}\n'),))


def _file(**kwargs) -> UncertainItem:
    values = dict(path="util.js", category="code-loader", signature_id="sig",
                  description="why", preview=b"export const n = 1;\n", commit="e" * 40)
    values.update(kwargs)
    return UncertainItem(**values)


def _run(question, replies, *, decisions=None, env=None):
    pipe = _Script(replies)
    with mock.patch.dict(os.environ, {} if env is None else env, clear=True):
        resolver = build_resolver(pipe, pipe, ask="jsonl", decisions=decisions)
    return resolver(question), _asked(pipe), pipe.written


class TestAskJsonl(unittest.TestCase):
    def test_a_pipe_without_the_flag_is_not_asked(self):
        with mock.patch.dict(os.environ, {}, clear=True):
            self.assertIsNone(build_resolver(_Pipe(), _Pipe()))

    def test_a_pipe_in_ci_is_asked_when_the_flag_is_set(self):
        answer, asked, text = _run(_package(), [{"action": "keep"}], env={"CI": "true"})
        self.assertEqual(answer.action, KEEP)
        self.assertNotIn("press Enter", text)
        self.assertEqual(asked[0]["schema_version"], FIX_ASK_SCHEMA_VERSION)
        self.assertEqual(asked[0]["kind"], "package")
        self.assertNotIn("event", asked[0])
        self.assertEqual(asked[0]["manifests"][0]["proposed"], '{\n  "dependencies": {}\n}\n')
        self.assertNotIn("proposed", asked[0]["manifests"][1])

    def test_a_delivery_answer_takes_out_only_offered_paths(self):
        decisions: list = []
        answer, asked, _ = _run(
            _delivery(),
            [{"action": "take-out", "chosen": ["nope.js"]},
             lambda _id: json.dumps({"id": "nope", "action": "take-out",
                                     "chosen": ["ok.js"]}) + "\n",
             {"action": "take-out", "chosen": ["lib/other.js", "ok.js", "ok.js"]}],
            decisions=decisions)
        self.assertEqual(answer.action, TAKE_OUT)
        self.assertEqual(answer.chosen, ("lib/other.js", "ok.js"))
        self.assertEqual(decisions, [{"kind": "delivery", "action": "take-out",
                                      "chosen": ["lib/other.js", "ok.js"]}])
        body = asked[0]
        self.assertEqual(body["commit"], "a" * 40)
        self.assertEqual(body["known_as"], ["d" * 40])
        self.assertNotIn(body["commit"], body["known_as"])
        self.assertEqual(body["files"][0], {"path": "ok.js", "blob": "b" * 40, "named_by": 2})
        self.assertEqual(body["files"][1], {"path": "lib/other.js", "blob": "c" * 40})
        self.assertEqual(body["changed"], ["edited.js"])
        self.assertTrue(body["recorded"])
        self.assertEqual(len({item["id"] for item in asked}), 1)

    def test_an_empty_choice_is_not_an_answer(self):
        answer, _, _ = _run(_delivery(), [{"action": "take-out", "chosen": []}] * 3)
        self.assertEqual(answer.action, UNANSWERED)

    def test_end_of_input_leaves_a_delivery_and_a_package_unanswered(self):
        decisions: list = []
        delivery, _, _ = _run(_delivery(), [], decisions=decisions)
        package, asked, _ = _run(_package(), [], decisions=decisions)
        self.assertEqual(delivery.action, UNANSWERED)
        self.assertEqual(package.action, UNANSWERED)
        self.assertEqual(decisions, [])
        self.assertEqual(len(asked), 1)

    def test_three_rejects_then_give_up(self):
        decisions: list = []
        answer, asked, _ = _run(
            _package(),
            [lambda _id: '{"event":"step"}\n', lambda _id: "not json\n",
             {"action": "yes"}],
            decisions=decisions)
        self.assertEqual(answer.action, UNANSWERED)
        self.assertEqual(decisions, [])
        self.assertEqual(len(asked), 3)
        self.assertEqual(len({item["id"] for item in asked}), 1)

    def test_keeping_a_package_is_recorded(self):
        decisions: list = []
        answer, _, _ = _run(_package(), [{"action": "keep"}], decisions=decisions)
        self.assertEqual(answer.action, KEEP)
        self.assertEqual(decisions, [{"kind": "package", "name": "left-pad", "action": "keep"}])

    def test_a_file_question_keeps_on_end_of_input_and_does_not_carry_the_bytes(self):
        decisions: list = []
        item = _file(category="fake-font")
        answer, asked, text = _run(item, [], decisions=decisions)
        self.assertEqual(answer.action, KEEP)
        self.assertEqual(decisions, [{"kind": "file", "path": "util.js", "action": "keep"}])
        body = asked[0]
        self.assertEqual(body["kind"], "file")
        self.assertEqual(body["introduced_by"], "e" * 40)
        self.assertEqual(body["sha256"], hashlib.sha256(item.preview).hexdigest())
        self.assertIs(body["withheld"], True)
        self.assertNotIn("restore", body)
        self.assertIs(body["supply"], False)
        self.assertNotIn("preview", body)
        self.assertNotIn(item.preview.decode(), text)

    def test_supply_reads_the_path_and_restore_is_offered_with_the_full_ids(self):
        blob = "f" * 40
        item = _file(keep_content=True, restore_candidate=("100644", blob),
                     restore_commit="f" * 40, preview=b"export const n = 1;\n")
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "replacement.js"
            path.write_bytes(b"export const ok = 1;\n")
            answer, asked, _ = _run(item, [{"action": "supply", "path": str(path)}])
        self.assertEqual(answer.action, SUPPLY)
        self.assertEqual(answer.supply, b"export const ok = 1;\n")
        self.assertEqual(asked[0]["restore"], {"commit": "f" * 40, "blob": blob})
        self.assertIs(asked[0]["withheld"], False)
        self.assertIs(asked[0]["supply"], True)

    def test_restore_and_supply_are_refused_when_they_were_not_offered(self):
        answer, _, _ = _run(_file(), [{"action": "restore"},
                                      {"action": "supply", "path": "/no/such/replacement.js"},
                                      {"action": "remove"}])
        self.assertEqual(answer.action, REMOVE)

    def test_an_unreadable_supply_path_is_asked_again(self):
        item = _file(keep_content=True)
        answer, asked, _ = _run(
            item, [{"action": "supply", "path": "/no/such/replacement.js"}, {"action": "remove"}])
        self.assertEqual(answer.action, REMOVE)
        self.assertEqual(len(asked), 2)
        self.assertEqual(asked[0]["id"], asked[1]["id"])

    def test_killing_the_read_records_nothing_for_the_open_question(self):
        decisions = [{"kind": "package", "name": "left-pad", "action": "keep"}]

        class _Die(_Pipe):
            def readline(self):
                raise KeyboardInterrupt

        with self.assertRaises(KeyboardInterrupt):
            build_resolver(_Die(), _Die(), ask="jsonl", decisions=decisions)(_delivery())
        self.assertEqual(decisions, [{"kind": "package", "name": "left-pad", "action": "keep"}])

    def test_the_fix_record_lists_choices_and_still_lists_what_is_left(self):
        record = remediation_record("o/r", None, [{"kind": "package", "name": "left-pad",
                                                   "action": "take-out"}])
        self.assertEqual(record["decisions"], [{"kind": "package", "name": "left-pad",
                                                "action": "take-out"}])
        self.assertEqual(record["needs_review"], [])

    def test_a_remote_run_is_not_asked(self):
        parser = build_parser()
        with mock.patch.object(fixcmd.remediator, "amend", return_value=0) as amend:
            fixcmd.run(_parsed(parser, ["fix", "amend", "--remote", "--ask", "jsonl", "o/r"]))
        self.assertIsNone(amend.call_args.kwargs["resolver"])
        with mock.patch.object(fixcmd.remediator, "fix", return_value=0) as fix:
            fixcmd.run(_parsed(parser, ["fix", "--remote", "--ask", "jsonl", "--json",
                                        "--no-stream", "o/r"]))
        self.assertIsNone(fix.call_args.kwargs["resolver"])
        self.assertEqual(fix.call_args.kwargs["decisions"], [])

    def test_the_flag_is_accepted_on_fix_and_amend(self):
        parser = build_parser()
        fix = _parsed(parser, ["fix", "--ask", "jsonl", "--json", "--progress", "jsonl", "."])
        amend = _parsed(parser, ["fix", "amend", "--ask", "jsonl", "."])
        self.assertEqual(fix.ask, "jsonl")
        self.assertTrue(fix.json)
        self.assertEqual(fix.progress, "jsonl")
        self.assertEqual(amend.ask, "jsonl")


if __name__ == "__main__":
    unittest.main()
