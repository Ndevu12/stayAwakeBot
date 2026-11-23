"""The parity harness reports two saws' scans as the same only when they are."""

import json
import subprocess
import tempfile
import unittest
import unittest.mock
from pathlib import Path

from tests.parity import compare, corpus, real_repositories, sides


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


class TheRealRepositories(unittest.TestCase):

    def setUp(self):
        self.work = Path(tempfile.mkdtemp(prefix="parity-real-"))
        self.source = self.work / "source"
        self.source.mkdir()
        for args in (["init", "-q", "-b", "main"], ["-c", "user.name=t", "-c", "user.email=t@example.invalid",
                                                    "-c", "commit.gpgsign=false", "commit", "-q", "--allow-empty",
                                                    "-m", "one"]):
            subprocess.run(["git", *args], cwd=self.source, check=True, capture_output=True)
        self.commit = subprocess.run(["git", "rev-parse", "HEAD"], cwd=self.source, check=True, capture_output=True,
                                     text=True).stdout.strip()
        self.listing = self.work / "repositories.toml"

    def _list(self, commit: str) -> list[real_repositories.Pinned]:
        self.listing.write_text(f'[[repository]]\nname = "local"\nurl = "{self.source.as_uri()}"\n'
                                f'commit = "{commit}"\n')
        return real_repositories.listed(self.listing)

    def test_a_listed_repository_is_held_at_its_commit(self):
        held = real_repositories.fetched(self._list(self.commit), self.work / "cache")
        self.assertEqual(len(held), 1)
        head = subprocess.run(["git", "rev-parse", "HEAD"], cwd=held[0], capture_output=True, text=True).stdout
        self.assertEqual(head.strip(), self.commit)

    def test_a_checkout_that_moved_off_its_commit_is_refused(self):
        held = real_repositories.fetched(self._list(self.commit), self.work / "cache")
        subprocess.run(["git", "-c", "user.name=t", "-c", "user.email=t@example.invalid", "-c", "commit.gpgsign=false",
                        "commit", "-q", "--allow-empty", "-m", "moved"], cwd=held[0], check=True, capture_output=True)
        with self.assertRaises(ValueError):
            real_repositories.fetched(self._list(self.commit), self.work / "cache")

    def test_without_a_list_the_corpus_stays_offline(self):
        with unittest.mock.patch.dict("os.environ", {real_repositories.LIST_VARIABLE: ""}):
            self.assertIsNone(real_repositories.list_path())
        self.assertEqual(real_repositories.fingerprint(None), b"")

