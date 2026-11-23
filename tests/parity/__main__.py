#!/usr/bin/env python3
"""Compare main's saw with another saw on the corpus.

    python -m tests.parity                  # main at the pinned commit against this checkout
    python -m tests.parity --actual main    # main against itself

Set SAW_PARITY_REPOSITORIES to a list of real repositories to add them to the corpus.
"""
from __future__ import annotations

import argparse
import hashlib
import os
import sys
from pathlib import Path

from tests.parity import compare, corpus, real_repositories, sides
from tests.support import isolation

PIN = Path(__file__).with_name("main.pin")
VARIANTS = {
    "default": [],
    "one job": ["-j", "1"],
    "four jobs": ["-j", "4"],
    "deep": ["--deep"],
    "history": ["--history"],
}


def cache_dir() -> Path:
    """Return the folder the harness keeps main's saw and its answers in."""
    return Path(os.environ.get("SAW_PARITY_CACHE") or isolation.REAL_HOME / ".cache" / "saw-parity")


def corpus_version() -> str:
    """Return a fingerprint of what builds the corpus."""
    sources = (Path(corpus.__file__), Path(sys.modules["tests.support.samples"].__file__))
    listed = real_repositories.fingerprint(real_repositories.list_path())
    return hashlib.sha256(b"".join(p.read_bytes() for p in sources) + listed).hexdigest()[:16]


def expected_answer(main: sides.Side, commit: str, variant: str, args: list[str], cache: Path) -> str:
    """Return main's answer for one variant, from the cache when it holds one."""
    stored = cache / "answers" / commit / corpus_version() / f"{variant.replace(' ', '-')}.json"
    if stored.is_file():
        return stored.read_text()
    answer = main.run(args)
    stored.parent.mkdir(parents=True, exist_ok=True)
    stored.write_text(answer)
    return answer


def main(argv: list[str] | None = None) -> int:
    """Run the comparison. Takes the command line. Returns 0 when every variant matches, else 1."""
    parser = argparse.ArgumentParser(prog="python -m tests.parity")
    parser.add_argument("--actual", default="this", help="'this' (this checkout) or 'main'")
    options = parser.parse_args(argv)
    cache = cache_dir()
    commit = PIN.read_text().strip()
    main_saw = sides.main_at(commit, cache)
    actual = main_saw if options.actual == "main" else sides.this_checkout()
    targets = [str(t) for t in corpus.build(cache / "corpus")]
    listing = real_repositories.list_path()
    if listing:
        targets += [str(t) for t in real_repositories.fetched(real_repositories.listed(listing), cache / "real")]
    mismatched = 0
    for variant, extra in VARIANTS.items():
        args = ["scan", *targets, "--json", "--no-stream", *extra]
        found = compare.differences(expected_answer(main_saw, commit, variant, args, cache), actual.run(args))
        print(f"{variant}: {'same' if not found else 'DIFFERENT'}")
        for line in found:
            print(f"  {line}")
        mismatched += bool(found)
    print(f"{main_saw.name} against {actual.name}: {len(VARIANTS) - mismatched} of {len(VARIANTS)} the same")
    return 1 if mismatched else 0


if __name__ == "__main__":
    sys.exit(main())
