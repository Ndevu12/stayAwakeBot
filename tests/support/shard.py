#!/usr/bin/env python3
"""Run one share of the test suite, so CI can split it across parallel jobs, and confirm the shares
together ran every test exactly once.

    python -m tests.support.shard run SHARE SHARES RECORD   # run share SHARE (1-based) of SHARES
    python -m tests.support.shard verify RECORD...          # every test in exactly one share
"""
from __future__ import annotations

import json
import sys
import unittest
from collections import defaultdict
from pathlib import Path

_START = Path(__file__).resolve().parents[1]


def split(sizes: dict[str, int], shares: int) -> list[list[str]]:
    """Split modules into `shares` groups of near-equal test count.

    Takes each module's test count. Returns one sorted list of module names per share; every module
    is in exactly one, and a share can be empty when there are fewer modules than shares."""
    groups: list[list[str]] = [[] for _ in range(shares)]
    totals = [0] * shares
    for module in sorted(sizes, key=lambda name: (-sizes[name], name)):
        smallest = totals.index(min(totals))
        groups[smallest].append(module)
        totals[smallest] += sizes[module]
    return [sorted(group) for group in groups]


def _cases(suite):
    for item in suite:
        if isinstance(item, unittest.TestSuite):
            yield from _cases(item)
        else:
            yield item


def _discovered() -> list[unittest.TestCase]:
    return list(_cases(unittest.defaultTestLoader.discover(str(_START))))


def _module(case: unittest.TestCase) -> str:
    return type(case).__module__


def run(share: int, shares: int, record: Path) -> int:
    """Run share `share` (1-based) of `shares` and write what it ran and what the suite holds to
    `record`. Returns the process status for whether every test in the share passed."""
    if not 1 <= share <= shares:
        raise SystemExit(f"share {share} is not between 1 and {shares}")
    cases = _discovered()
    sizes: dict[str, int] = defaultdict(int)
    for case in cases:
        sizes[_module(case)] += 1
    mine = set(split(dict(sizes), shares)[share - 1])
    chosen = [case for case in cases if _module(case) in mine]
    record.write_text(json.dumps({"share": share, "shares": shares,
                                  "suite": sorted(case.id() for case in cases),
                                  "ran": sorted(case.id() for case in chosen)}), encoding="utf-8")
    print(f"share {share} of {shares}: {len(mine)} modules, {len(chosen)} of {len(cases)} tests",
          flush=True)
    result = unittest.TextTestRunner(verbosity=2).run(unittest.TestSuite(chosen))
    return 0 if result.wasSuccessful() else 1


def verify(records: list[Path]) -> list[str]:
    """Check that the shares in `records` together ran every test of the suite exactly once.

    Takes the record each share wrote. Returns the problems found; an empty list when none."""
    loaded = [json.loads(path.read_text(encoding="utf-8")) for path in records]
    if not loaded:
        return ["no share wrote a record"]
    problems = []
    shares = {entry["shares"] for entry in loaded}
    if len(shares) != 1:
        return [f"the shares disagree on how many there are: {sorted(shares)}"]
    expected = set(range(1, shares.pop() + 1))
    seen = [entry["share"] for entry in loaded]
    if sorted(seen) != sorted(expected):
        problems.append(f"shares recorded {sorted(seen)}, expected {sorted(expected)}")
    suites = {tuple(entry["suite"]) for entry in loaded}
    if len(suites) != 1:
        problems.append("the shares discovered different suites")
    suite = set(next(iter(suites)))
    counted: dict[str, int] = defaultdict(int)
    for entry in loaded:
        for test in entry["ran"]:
            counted[test] += 1
    missing = sorted(suite - set(counted))
    twice = sorted(test for test, times in counted.items() if times > 1)
    unknown = sorted(set(counted) - suite)
    for label, tests in (("never ran", missing), ("ran more than once", twice),
                         ("ran but is not in the suite", unknown)):
        if tests:
            problems.append(f"{len(tests)} test(s) {label}, e.g. {tests[0]}")
    return problems


def main(argv: list[str]) -> int:
    if len(argv) == 4 and argv[0] == "run":
        return run(int(argv[1]), int(argv[2]), Path(argv[3]))
    if len(argv) >= 1 and argv[0] == "verify":
        problems = verify([Path(arg) for arg in argv[1:]])
        for problem in problems:
            print(problem)
        if not problems:
            print(f"{len(argv) - 1} shares ran every test exactly once")
        return 1 if problems else 0
    print(__doc__, file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
