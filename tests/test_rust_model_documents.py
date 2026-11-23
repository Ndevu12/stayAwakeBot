"""saw-model reads main's JSON documents and writes them back byte for byte."""
import json
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from tests.parity import corpus, sides

REPO_ROOT = Path(__file__).resolve().parents[1]
_STYLES = {"line": {}, "indented": {"indent": 2}, "compact": {"separators": (",", ":")}}
_SCAN_OPTIONS = ([], ["--deep"], ["--history"], ["-j", "1"])
_AWKWARD_VALUES = [
    {"z": 1, "a": [1, 2.5, -0.0, 1e16, 1e-05, 0.1, 123456.789, 2 ** 64 - 1, -2 ** 63], "m": {}, "e": []},
    {"text": "café ☃ \U0001f600 tab\t nl\n cr\r bs\\ quote\" del\x7f nul\x00 bell\x07 slash/"},
    [[], {}, [[]], {"k": {"k": {}}}, None, True, False, "", 0, -1],
    {"unicode keys é\U0001f600": "v", "": "empty key"},
]


class _Rewriting(unittest.TestCase):
    """Builds saw-model's rewrite tool once and runs it."""

    @classmethod
    def setUpClass(cls):
        subprocess.run(["cargo", "build", "-q", "-p", "saw-model", "--example", "rewrite_document"],
                       cwd=REPO_ROOT, check=True)
        cls.rewrite = REPO_ROOT / "target" / "debug" / "examples" / "rewrite_document"

    def rewritten(self, text: str, contract: str, style: str) -> str:
        done = subprocess.run([str(self.rewrite), contract, style], input=text, capture_output=True, text=True)
        self.assertEqual(done.returncode, 0, done.stderr)
        return done.stdout


@unittest.skipUnless(shutil.which("cargo"), "cargo is not installed")
class SawModelRewritesMainsDocuments(_Rewriting):

    def test_the_writer_writes_what_python_writes(self):
        for value in _AWKWARD_VALUES:
            for style, options in _STYLES.items():
                with self.subTest(style=style, value=value):
                    python = json.dumps(value, **options)
                    self.assertEqual(self.rewritten(python, "any", style), python)

    def test_the_scan_contract_rewrites_every_scan_document(self):
        work = Path(tempfile.mkdtemp(prefix="model-corpus-"))
        self.addCleanup(shutil.rmtree, work, True)
        targets = corpus.build(work / "corpus")
        saw = sides.this_checkout()
        runs = [([str(target)], options) for target in targets for options in _SCAN_OPTIONS]
        runs.append(([str(target) for target in targets], []))
        for paths, options in runs:
            with self.subTest(paths=[Path(p).name for p in paths], options=options):
                printed = saw.run(["scan", *paths, "--json", "--no-stream", *options])
                self.assertTrue(printed.startswith("{"), printed[:200])
                self.assertEqual(self.rewritten(printed, "scan", "indented") + "\n", printed)


if __name__ == "__main__":
    unittest.main()


_CLI_DOCUMENTS = (
    ("capabilities", ["capabilities", "--json"]),
    ("doctor", ["doctor", "--json"]),
    ("auth-status", ["auth", "status", "--json"]),
    ("hook-status", ["hook", "status", "--json"]),
    ("hook-status", ["hook", "install", "--json"]),
    ("hook-status", ["hook", "repair", "--json"]),
    ("watch-status", ["watch", "status", "--json"]),
    ("audit", ["audit", "--json"]),
)


@unittest.skipUnless(shutil.which("cargo"), "cargo is not installed")
class SawModelRewritesEveryDocument(_Rewriting):

    def test_every_document_a_command_prints(self):
        saw = sides.this_checkout()
        for document, args in _CLI_DOCUMENTS:
            with self.subTest(document=document, args=args):
                printed = saw.run([*args, "--no-stream"] if args[0] != "capabilities" else args)
                self.assertTrue(printed.startswith("{"), printed[:300])
                self.assertEqual(self.rewritten(printed, document, "indented") + "\n", printed)

    def test_the_fix_document(self):
        work = Path(tempfile.mkdtemp(prefix="model-fix-"))
        self.addCleanup(shutil.rmtree, work, True)
        saw = sides.this_checkout()
        for target in corpus.build(work / "corpus"):
            with self.subTest(target=target.name):
                printed = saw.run(["fix", "--path", str(target), "--json", "--no-stream"])
                self.assertTrue(printed.startswith("{"), printed[:300])
                self.assertEqual(self.rewritten(printed, "fix", "indented") + "\n", printed)

    def test_the_guard_drift_document(self):
        from stayawake.bots.security.guard.sweep import DriftOutcome, drift_record
        from stayawake.utils.json_documents import versioned
        outcomes = [DriftOutcome("your-org/one", "current"),
                    DriftOutcome("your-org/two", "drifted", "opened", "the gate is behind", 42),
                    DriftOutcome("your-org/three", "error", "failed", "café could not be read")]
        printed = json.dumps(versioned("guard-drift", {"results": [drift_record(o) for o in outcomes]}), indent=2)
        self.assertEqual(self.rewritten(printed, "guard-drift", "indented"), printed)


class _GovernAnswers(unittest.TestCase):
    """Every answer `saw govern` prints, from real updates."""

    def answers(self) -> list[dict]:
        from stayawake.bots.security import govern
        from tests.bots.security.test_govern_replays_a_tracking_checkout import _TrackingCheckout
        from tests.support import samples

        holder = self
        answers: list[dict] = []

        class Updates(_TrackingCheckout):
            def runTest(self):
                open_, into = str(self.open), str(self.into)
                answers.append(govern.prepare(open_, into, "git", ["pull"])[0])
                answers.append(govern.apply(open_, into)[0])
                answers.append(govern.verdict(open_)[0])
                answers.append(govern.restore(open_)[0])
                self.write(self.upstream, ".gitignore", samples._gitignore())
                self.commit(self.upstream, "infected")
                answers.append(govern.prepare(open_, into, "git", ["pull"])[0])
                answers.append(govern.apply(open_, into)[0])
                answers.append(govern.prepare(open_, into, "git", ["pull", "no-such-remote"])[0])

        result = unittest.TestResult()
        Updates().run(result)
        holder.assertEqual(result.errors + result.failures, [])
        return answers


@unittest.skipUnless(shutil.which("cargo"), "cargo is not installed")
class SawModelRewritesEveryGovernAnswer(_Rewriting, _GovernAnswers):

    def test_every_govern_answer(self):
        from stayawake.utils.json_documents import versioned
        answers = self.answers()
        self.assertGreaterEqual(len(answers), 7)
        for answer in answers:
            with self.subTest(keys=list(answer)):
                printed = json.dumps(versioned("govern", answer))
                self.assertEqual(self.rewritten(printed, "govern", "line"), printed)
