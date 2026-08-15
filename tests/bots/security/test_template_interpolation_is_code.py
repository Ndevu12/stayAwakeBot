#!/usr/bin/env python3
"""The interior of `${…}` is the one part of a template literal that RUNS.

The source scrubber blanked it, so every identifier inside an interpolation was invisible to the
detectors that read the scrubbed view. A decoded payload reaching a shell through
`execSync(`sh -c ${d}`)` was therefore missed, while the concatenated `'sh -c ' + d` was caught —
the same flow, differing only in how the value is spliced in.

The literal BODY around it stays kept, as it was: that is string data, and the relative-path
carve-out needs to see it.
"""
from __future__ import annotations

import random
import time
import unittest

from stayawake.bots.security.taint import flow
from stayawake.bots.security.taint.analyzer import detect_dropper
from stayawake.bots.security.obfuscation import analyze_file


def _blob(seed: int, n: int = 200) -> str:
    random.seed(seed)
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    return "".join(random.choice(alphabet) for _ in range(n))


class TestTheScrubberKeepsInterpolatedCode(unittest.TestCase):
    def test_an_identifier_inside_an_interpolation_survives_scrubbing(self):
        for scrub_strings in (True, False):
            with self.subTest(scrub_strings=scrub_strings):
                view = flow._scrub_comments_and_strings("run(`sh -c ${payload}`)",
                                                        scrub_strings=scrub_strings)
                self.assertIn("payload", view)

    def test_the_literal_body_around_it_is_still_kept(self):
        view = flow._scrub_comments_and_strings("import(`./locales/${lang}.json`)", scrub_strings=True)
        self.assertIn("./locales/", view, "the relative-path carve-out reads this")

    def test_offsets_are_preserved(self):
        # Every consumer matches on one view and checks scope on another at the SAME offsets.
        src = "const d = atob('AAAA');\nexecSync(`sh -c ${d}`);\n"
        self.assertEqual(len(flow._scrub_comments_and_strings(src)), len(src))

    def test_a_comment_inside_a_template_is_not_resurrected(self):
        view = flow._scrub_comments_and_strings("x(`a ${ /* eval(1) */ b }`)")
        self.assertNotIn("eval", view)


class TestADecodeReachingAShellThroughInterpolation(unittest.TestCase):
    def test_both_splice_forms_are_detected_alike(self):
        blob = _blob(11)
        interpolated = f"const d = atob('{blob}');\nexecSync(`sh -c ${{d}}`);\n"
        concatenated = f"const d = atob('{blob}');\nexecSync('sh -c ' + d);\n"
        self.assertTrue(detect_dropper(interpolated), "the interpolated form was the blind spot")
        self.assertTrue(detect_dropper(concatenated))

    def test_it_is_not_specific_to_one_decode_call(self):
        blob = _blob(12)
        self.assertTrue(detect_dropper(
            f"const d = Buffer.from('{blob}','base64').toString();\nexecSync(`bash -c ${{d}}`);\n"))

    def test_a_decode_nested_directly_in_the_interpolation_is_detected(self):
        self.assertTrue(detect_dropper(f"execSync(`sh -c ${{atob('{_blob(13)}')}}`);\n"))


class TestOrdinaryTemplatesStayClean(unittest.TestCase):
    """Everything below became newly VISIBLE to the detectors when the interior stopped being
    blanked, so each is a false positive this change could have introduced."""

    CASES = {
        "task runner": "execSync(`npm run ${task}`);",
        "git command": "execSync(`git checkout ${branch}`);",
        "url building": "fetch(`${API_BASE}/users/${id}`);",
        "dynamic import": "await import(`./locales/${lang}.json`);",
        "styled component": "const S = styled.div`color: ${p => p.theme.fg};`;",
        "query template": "db.query(`SELECT * FROM t WHERE id = ${id}`);",
        "log mentioning atob": "console.log(`decoded ${bytes.length} bytes via atob`);",
    }

    def test_none_of_them_is_a_finding(self):
        for name, source in self.CASES.items():
            with self.subTest(case=name):
                self.assertIsNone(detect_dropper(source))
                self.assertFalse(analyze_file(source, ".js"))


class TestItIsBoundedOnHostileInput(unittest.TestCase):
    """The scrubber reads attacker-chosen file content, so its limits are attacker-chosen too.

    A recursive descent into each `${…}` died with RecursionError at ~1000 nested interpolations —
    5 KB of file content — and cost time quadratic in the nesting. Both are reachable by writing a
    file, which makes them a way to stop the analysis rather than a performance note."""

    def _nested(self, depth):
        return "`" + "${`" * depth + "x" + "`}" * depth + "`"

    def test_deep_nesting_neither_raises_nor_truncates(self):
        for depth in (1_000, 20_000):
            with self.subTest(depth=depth):
                source = self._nested(depth)
                scrubbed = flow._scrub_comments_and_strings(source)
                self.assertEqual(len(scrubbed), len(source), "offsets must survive")

    def test_cost_does_not_explode_with_nesting_depth(self):
        # Quadratic would make 4x the depth ~16x the time; linear keeps it near 4x. The bound is
        # generous because a shared runner is noisy — it fails on an order-of-magnitude regression,
        # not on jitter.
        def elapsed(depth):
            source = self._nested(depth)
            start = time.perf_counter()
            flow._scrub_comments_and_strings(source)
            return time.perf_counter() - start

        base = max(elapsed(2_000), 1e-4)
        self.assertLess(elapsed(8_000), base * 40)


if __name__ == "__main__":
    unittest.main()
