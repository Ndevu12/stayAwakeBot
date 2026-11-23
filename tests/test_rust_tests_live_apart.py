"""Rust tests live in each crate's tests folder, never inside the code they test."""
import re
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
TEST_MARK = re.compile(r"#\[(?:cfg\([^\]]*\btest\b[^\]]*|test)\]|\bmod tests\b")


class RustTestsLiveApart(unittest.TestCase):

    def test_no_implementation_file_holds_tests(self):
        holding = sorted(str(path.relative_to(REPO_ROOT)) for path in (REPO_ROOT / "crates").glob("*/src/**/*.rs")
                         if TEST_MARK.search(path.read_text(encoding="utf-8")))
        self.assertEqual(holding, [])

    def test_the_mark_finds_each_form(self):
        for text in ("#[cfg(test)]\nmod tests {}", "#[cfg(all(test, unix))]", "#[test]\nfn x() {}", "mod tests;"):
            with self.subTest(text=text):
                self.assertIsNotNone(TEST_MARK.search(text))
        self.assertIsNone(TEST_MARK.search("let latest = tested;"))


if __name__ == "__main__":
    unittest.main()
