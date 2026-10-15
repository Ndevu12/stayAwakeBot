#!/usr/bin/env python3
"""Strings a regular expression matches, built from the expression itself, so a test can check a
property of everything a pattern matches without a corpus that happens to hold it."""
from __future__ import annotations

import random
import re

try:
    import re._constants as _c
    import re._parser as _parser
except ImportError:
    import sre_constants as _c
    import sre_parse as _parser

_CATEGORY = {"CATEGORY_DIGIT": "0123456789", "CATEGORY_SPACE": " \t", "CATEGORY_WORD": "abcXYZ_09",
             "CATEGORY_NOT_DIGIT": "ab_-", "CATEGORY_NOT_SPACE": "ab1-_", "CATEGORY_NOT_WORD": " -.;"}
_REPEATS = {_c.MAX_REPEAT, _c.MIN_REPEAT} | ({_c.POSSESSIVE_REPEAT} if hasattr(_c, "POSSESSIVE_REPEAT") else set())
_ZERO_WIDTH = {_c.AT, _c.ASSERT, _c.ASSERT_NOT}


def _one_of(items, rng: random.Random) -> str:
    pool, negate = [], False
    for op, value in items:
        if op is _c.LITERAL:
            pool.append(chr(value))
        elif op is _c.RANGE:
            pool += [chr(c) for c in range(value[0], min(value[1], value[0] + 30) + 1)]
        elif op is _c.CATEGORY:
            pool += list(_CATEGORY.get(str(value), "a"))
        elif op is _c.NEGATE:
            negate = True
    if negate:
        pool = [c for c in "axQ1_- ;." if c not in pool] or ["a"]
    return rng.choice(pool or ["a"])


def _build(parsed, rng: random.Random, groups: dict) -> str:
    out = []
    for op, value in parsed:
        if op is _c.LITERAL:
            out.append(chr(value))
        elif op is _c.NOT_LITERAL:
            out.append(rng.choice([c for c in "ax1 _-" if ord(c) != value]))
        elif op is _c.ANY:
            out.append(rng.choice("ax1_-"))
        elif op is _c.IN:
            out.append(_one_of(value, rng))
        elif op is _c.BRANCH:
            out.append(_build(rng.choice(value[1]), rng, groups))
        elif op is _c.SUBPATTERN:
            groups[value[0]] = _build(value[-1], rng, groups)
            out.append(groups[value[0]])
        elif op in _REPEATS:
            low, high, inner = value
            out.append("".join(_build(inner, rng, groups) for _ in range(rng.randint(low, min(high, low + 3)))))
        elif hasattr(_c, "ATOMIC_GROUP") and op is _c.ATOMIC_GROUP:
            out.append(_build(value, rng, groups))
        elif op is _c.GROUPREF:
            out.append(groups.get(value, ""))
        elif op is _c.CATEGORY:
            out.append(rng.choice(_CATEGORY.get(str(value), "a")))
        elif op not in _ZERO_WIDTH:
            raise ValueError(f"cannot build a sample for {op}")
    return "".join(out)


def matching_texts(pattern: str, flags: int = re.IGNORECASE, tries: int = 400, seed: int = 0) -> list[str]:
    """Build texts the pattern matches. Takes the pattern, its flags, how many to try and a seed.
    Returns the matched part of each text that the compiled pattern really matches."""
    compiled = re.compile(pattern, flags)
    parsed = _parser.parse(pattern, flags)
    rng = random.Random(seed)
    found = []
    for _ in range(tries):
        match = compiled.search(" " + _build(parsed, rng, {}) + " ")
        if match:
            found.append(match.group(0))
    return found
