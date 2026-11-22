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


@unittest.skipUnless(shutil.which("cargo"), "cargo is not installed")
class SawModelRewritesMainsDocuments(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        subprocess.run(["cargo", "build", "-q", "-p", "saw-model", "--example", "rewrite_document"],
                       cwd=REPO_ROOT, check=True)
        cls.rewrite = REPO_ROOT / "target" / "debug" / "examples" / "rewrite_document"

    def rewritten(self, text: str, contract: str, style: str) -> str:
        done = subprocess.run([str(self.rewrite), contract, style], input=text, capture_output=True, text=True)
        self.assertEqual(done.returncode, 0, done.stderr)
        return done.stdout

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
