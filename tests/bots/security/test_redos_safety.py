#!/usr/bin/env python3
"""Single source of ReDoS-regression truth (#1156, #1158).

`saw scan` walks attacker-controlled repos, so ONE quadratic regex — an unbounded `[^X]*` / `.*`
that scans to end-of-string at every anchor, or a run that re-tries at every offset — lets a crafted
file pin a core for minutes: a cost-free denial of service. Past fixes bounded such patterns one at a
time (the curl→interpreter shape, the hidden-whitespace run, the untrusted-`${{ }}` expression).

Rather than a per-matcher ReDoS test (which drifts, and silently misses the NEXT new pattern), this
enumerates EVERY security-critical compiled regex — the module-level patterns in every matcher plus
every `pattern` in the signature DB, discovered dynamically — and asserts each stays bounded on a
battery of pathological inputs. A new quadratic pattern ANYWHERE fails HERE, with no new test to
write. This is the one place ReDoS safety is enforced; do not re-add per-file ReDoS timing tests.
"""
from __future__ import annotations

import importlib
import pkgutil
import re
import signal
import time
import unittest

import stayawake.bots.security as _security_pkg
from stayawake.bots.security.signatures import load_signatures

# Length chosen so even the MILDEST quadratic shape (the curl→interpreter scan-to-EOF is only ~2 s at
# 100 K chars) blows well past the budget, while any linear pattern still finishes in milliseconds —
# a wide gap that keeps the time assertion robust on slow CI. A runaway search is cut off at the
# budget by SIGALRM, so a larger N costs bounded patterns nothing. Inputs trigger the known
# scan-to-EOF / per-offset-backtrack shapes.
_N = 300_000
_HOSTILE_INPUTS = [
    " " * _N,                                   # whitespace run (hidden-whitespace concealment)
    "\t" * _N,
    " " * _N,                              # no-break-space run
    "${{ " * (_N // 4),                         # untrusted-`${{ }}` expression spam
    "github ${{ " * (_N // 11),                # ...with a `github` token present (defeats a naive prefilter)
    ("${{ github.event.issue" + "x" * 60) * (_N // 80),   # nested-anchor backtrack stress
    "curl " * (_N // 5),                        # curl->interpreter spam (no pipe)
    "curl " * (_N // 10) + "| ",                # ...with a late pipe
    "base64 -d " * (_N // 10),                  # base64-decode MULTI-ANCHOR spam (hygiene arm 4)
    "<dependency>" * (_N // 12),                # `<opener>` with no closer (maven pom.xml class)
    "/* " * (_N // 3),                          # `/*` with no closer (jsonc block-comment class)
    "<version>" + " " * _N, "<groupId>" + "\t" * _N,      # `<tag>` + whitespace body, no closer
    "<tag attr>" * (_N // 10), "</x>" * (_N // 4),        # generic unclosed opener/closer spam
    "a" * _N, "/" * _N, "." * _N, "<" * _N, "=" * _N, ">" * _N,   # generic single-char runs
    "A" * _N + "=",                             # base64-blob shape
]
# Repeated MULTI-CHAR tokens above (`<dependency>`, `/* `) are essential: a `<opener>content<closer>`
# regex whose closer is absent is O(n^2) via findall/sub re-trying at every opener, and NO single-char
# run reproduces that. Budget is generous so a heavy-but-linear pattern (~0.5 s) has ~10x headroom and
# never flakes on a slow runner; a genuine quadratic is cut off here by SIGALRM and fails.
_BUDGET_S = 5.0


class _ReDoSTimeout(Exception):
    pass


def _search_within_budget(rx: re.Pattern, text: str, budget: float) -> tuple[float, bool]:
    """Run rx.search(text) but INTERRUPT it at `budget` seconds (SIGALRM) so a catastrophic pattern
    fails the test in ~budget instead of hanging the suite for minutes. Returns (elapsed, timed_out).
    Requires a Unix main thread (dev + CI); callers skip if setitimer is unavailable."""
    def _fire(signum, frame):
        raise _ReDoSTimeout()
    prev = signal.signal(signal.SIGALRM, _fire)
    signal.setitimer(signal.ITIMER_REAL, budget)
    start = time.time()
    try:
        rx.search(text)
        return time.time() - start, False
    except _ReDoSTimeout:
        return budget, True
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, prev)


def _iter_patterns(val, _depth=0):
    """Yield every compiled regex reachable from `val` — the value itself, or ones stored inside a
    dict / list / tuple / set (a module may hold regexes in a collection, e.g. maven `_TAG_RE`)."""
    if isinstance(val, re.Pattern):
        yield val
    elif _depth < 4 and isinstance(val, dict):
        for v in val.values():
            yield from _iter_patterns(v, _depth + 1)
    elif _depth < 4 and isinstance(val, (list, tuple, set, frozenset)):
        for v in val:
            yield from _iter_patterns(v, _depth + 1)


def _all_security_regexes() -> list[tuple[str, re.Pattern]]:
    """Every compiled security regex in the codebase: module-level patterns (incl. ones nested in a
    dict/list) across EVERY module in the `stayawake.bots.security` package (recursively — matchers/,
    dependencies/resolvers/, jsonc, obfuscation, …), plus each signature `pattern`. Deduped by identity
    so shared constants / aliases (e.g. REMOTE_FETCH_INTO_INTERPRETER) are tested once. Walking the whole
    package — not a hand-listed set — is what keeps a NEW matcher or resolver from silently escaping the
    guard. (Regexes built inline per-call with an f-string are invisible here — the convention is to
    compile security regexes at module level so this guard sees them; see maven `_TAG_RE`.)"""
    seen: set[int] = set()
    out: list[tuple[str, re.Pattern]] = []
    for info in pkgutil.walk_packages(_security_pkg.__path__, _security_pkg.__name__ + "."):
        try:
            mod = importlib.import_module(info.name)
        except Exception:
            continue                            # a module that can't import on its own has no reachable regex
        for name, val in vars(mod).items():
            for rx in _iter_patterns(val):
                if id(rx) not in seen:
                    seen.add(id(rx))
                    out.append((f"{info.name.rsplit('.', 1)[-1]}.{name}", rx))
    for group in load_signatures().values():
        for sig in group:
            if sig.get("pattern"):
                out.append((f"signature:{sig['id']}", re.compile(sig["pattern"], re.IGNORECASE)))
    return out


class TestReDoSSafety(unittest.TestCase):
    @unittest.skipUnless(hasattr(signal, "setitimer"), "needs SIGALRM (Unix) to bound a runaway regex")
    def test_every_security_regex_is_bounded_on_hostile_input(self):
        regexes = _all_security_regexes()
        self.assertGreater(len(regexes), 20, "regex discovery collected too few — did an import fail?")
        slow: list[str] = []
        for name, rx in regexes:
            for evil in _HOSTILE_INPUTS:
                dt, timed_out = _search_within_budget(rx, evil, _BUDGET_S)
                if timed_out or dt > _BUDGET_S:
                    slow.append(f"{name}: >{_BUDGET_S:g}s on a {len(evil):,}-char input")
                    break                       # one confirmed blow-up per regex is enough
        self.assertEqual(slow, [], "catastrophic-backtracking (ReDoS) regex(es):\n  " + "\n  ".join(slow))


if __name__ == "__main__":
    unittest.main()
