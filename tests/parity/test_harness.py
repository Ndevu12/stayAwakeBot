"""The parity harness reports two saws' scans as the same only when they are."""

import json
import subprocess
import tempfile
import unittest
from pathlib import Path

from tests.parity import compare, corpus, sides


def _scan(target: str, findings: list[dict], **fields) -> str:
    return json.dumps({"schema_version": 1, "generated_at": "now", **fields,
                       "results": [{"target": target, "findings": findings}]})


class TheComparison(unittest.TestCase):

    def test_only_the_time_of_the_run_is_ignored(self):
        self.assertEqual(compare.differences(_scan("a", []), _scan("a", []).replace("now", "later")), [])
        self.assertNotEqual(compare.differences(_scan("a", [], any_infected=False), _scan("a", [], any_infected=True)), [])

    def test_a_finding_one_side_lacks_is_named_by_target_and_matcher(self):
        finding = {"signature_id": "loader-x", "path": "a.js"}
        self.assertIn("a: loader-x 1 != 0", compare.differences(_scan("a", [finding]), _scan("a", [])))

    def test_output_that_is_not_json_is_compared_as_text(self):
        self.assertEqual(compare.differences("same", "same"), [])
        self.assertEqual(compare.differences("one", "two"), ["the documents differ"])


class TheCorpus(unittest.TestCase):

    def _commits(self, repo: Path) -> str:
        return subprocess.run(["git", "log", "--all", "--format=%H"], cwd=repo, capture_output=True,
                              text=True, check=True).stdout

    def test_it_is_the_same_every_time_it_is_built(self):
        with tempfile.TemporaryDirectory() as first, tempfile.TemporaryDirectory() as second:
            built = corpus.build(Path(first) / "c"), corpus.build(Path(second) / "c")
            for one, other in zip(*built):
                if (one / ".git").is_dir():
                    self.assertEqual(self._commits(one), self._commits(other), one.name)


class TheHarness(unittest.TestCase):

    def test_a_saw_compared_with_itself_is_the_same(self):
        with tempfile.TemporaryDirectory() as scratch:
            targets = [str(t) for t in corpus.build(Path(scratch) / "corpus")]
            saw = sides.this_checkout()
            args = ["scan", *targets, "--json", "--no-stream"]
            first = saw.run(args)
            self.assertIn('"any_infected": true', first)
            self.assertEqual(compare.differences(first, saw.run(args)), [])


if __name__ == "__main__":
    unittest.main()
