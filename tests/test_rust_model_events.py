"""saw-model reads the progress events and the questions main writes, and writes them back byte for byte."""
import io
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from tests.parity import corpus
from tests.test_rust_model_documents import _Rewriting

REPO_ROOT = Path(__file__).resolve().parents[1]


def _event_lines(text: str) -> list[str]:
    return [line for line in text.splitlines() if line.startswith("{")]


@unittest.skipUnless(shutil.which("cargo"), "cargo is not installed")
class SawModelRewritesEveryEvent(_Rewriting):

    def assert_rewritten(self, lines: list[str], contract: str, style: str) -> None:
        self.assertTrue(lines)
        for line in lines:
            with self.subTest(line=line[:120]):
                self.assertEqual(self.rewritten(line, contract, style), line)

    def test_the_progress_events_real_runs_write(self):
        work = Path(tempfile.mkdtemp(prefix="model-events-"))
        self.addCleanup(shutil.rmtree, work, True)
        targets = corpus.build(work / "corpus")
        accented = work / "café ☃"
        shutil.copytree(targets[0], accented)
        env = {**os.environ, "PYTHONPATH": str(REPO_ROOT / "src")}
        for args in (["scan", str(accented), "--json"], ["scan", *map(str, targets), "--json"],
                     ["audit", "--json"], ["fix", "--path", str(targets[-1]), "--json"]):
            with self.subTest(args=args[:2]):
                done = subprocess.run([sys.executable, "-m", "stayawake", *args, "--no-stream", "--progress=jsonl"],
                                      capture_output=True, text=True, env=env, timeout=600)
                self.assert_rewritten(_event_lines(done.stderr), "progress", "line")

    def test_every_progress_event_main_can_write(self):
        from stayawake.utils.progress_events import ProgressEvents
        out = io.StringIO()
        events = ProgressEvents("scan", enabled=True, out=out)
        events.start(steps=3)
        events.step("read", "reading café…", index=1, of=3)
        events.step("judge", "judging")
        events.target("/tmp/café", index=0, of=2)
        events.target("/tmp/plain")
        events.plan("/tmp/café", files=3, size=10 ** 9, commits=4, workers=2, estimate_seconds=7,
                    budget_seconds=60)
        events.progress("/tmp/café", phase="files", done=1, total=3)
        events.progress("/tmp/café", phase="history", done=None, total=0)
        events.done(2)
        self.assert_rewritten(_event_lines(out.getvalue()), "progress", "line")
        self.assertEqual(len(_event_lines(out.getvalue())), 9)

    def test_every_question_fix_asks(self):
        from stayawake.bots.security.pr.resolve import (ArrivedFile, DeliveryQuestion, DependencyQuestion,
                                                        UncertainItem)
        from stayawake.cli.resolve import jsonl
        questions = [
            jsonl._file_question(UncertainItem("src/café.js", "loader", "sig-1", "a loader ☃",
                                               b"x = 1\n", introduced_by="abc123")),
            jsonl._file_question(UncertainItem("a.js", "loader", "sig-2", "d", b"\x00\x01", confirmed=True,
                                               arrived_with_removed=("b.js",), restore_candidate=("a.js", "f00d"),
                                               restore_commit="c0ffee", keep_content=True, origin_unread=True)),
            jsonl._delivery_question(DeliveryQuestion("c0ffee", "2026-11-01", "add café", ("x.js",),
                                                      (ArrivedFile("x.js", "b1"), ArrivedFile("y.js", "b2")),
                                                      changed=("z.js",), recorded=True, known_as=("v1",),
                                                      named_by=(("x.js", 2),))),
            jsonl._package_question(DependencyQuestion("bad-pkg", ("1.0.0",), ("package.json", "web/package.json"),
                                                       proposed=(("package.json", "remove it"),))),
        ]
        lines = [json.dumps(jsonl._event(f"q{index}", question), ensure_ascii=False)
                 for index, question in enumerate(questions)]
        self.assert_rewritten(lines, "ask", "line-keeping-non-ascii")


if __name__ == "__main__":
    unittest.main()
