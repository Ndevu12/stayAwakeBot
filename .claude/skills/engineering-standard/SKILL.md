---
name: engineering-standard
description: The design bar for this codebase — SRP, DRY-but-not-too-DRY, reusability, self-documenting names, value-before-coverage, reuse-check and measure-first, fix-at-the-right-depth. Apply when designing, adding capability, refactoring, or optimizing; the maintainer asks explicitly whether new work honors these.
---

# Engineering standard

Write for a new/collaborating developer. New work is expected to honor these; be ready to say how it does.

## Design principles

- **SRP** — one reason to change per module. Decompose a god-module-in-waiting *before* adding
  capability (resolver / store / comparators / thin coordinator), don't pile features into one class.
- **DRY, but NOT too DRY.** *Good DRY:* one loader for sources sharing a schema, one canonical
  mapping table, one set of shared domain types rather than per-caller copies. *The boundary:* share an
  **interface, not code**, when the things are genuinely different — no universal super-parser, no
  universal `Version` class (semver ≠ PEP 440 ≠ Gem). Forcing different things together is the wrong
  abstraction.
- **Reusability & dependency inversion** — pieces with an obvious 2nd consumer stand alone; depend on
  an injectable interface so tests inject fakes and backends swap without touching callers.
- **Open/Closed & data/logic separation** — adding a case = add + register, touch nothing else.
  Detection indicators are **data**, not code.
- **Self-documenting names** — name by meaning, not internal jargon (`tier1_only` →
  `constructs_only`). A reader should understand a call site without hunting. Don't propagate
  pre-existing jargon into new identifiers; describe behavior in comments.
- **Comment density — hold what the code can't say.** A comment earns its place with a
  measurement or a rejected alternative — never a trap, which names what the code checks — not by
  narrating the code. Aim two lines, not nine; long rationale belongs in the commit message.
- **Altitude — fix at the right depth, no bandaids.** A special case layered on shared infra is a
  smell; prefer generalizing the underlying mechanism. But don't over-engineer the maximal engine.

## Sequencing: extract-after-2nd-case — with one override

Freeze an abstraction only after a **2nd** implementation proves it (don't build the framework for 8
ecosystems up front). **BUT the maintainer overrides this for INFRASTRUCTURE + CONSISTENCY they call
out** — when it's plumbing every part touches, build the *proper* structure now, not the minimal
patch ("the accurate and quality one, not because it's easy or low-risk"). And when reuse is needed,
**EXTRACT a shared seam and rewire callers** — never duplicate, never treat reuse as a blocker.

## Value & measurement (the strongest, most-repeated rule)

- **Value/viability BEFORE coverage.** Implement only what adds value; a **cheap approach covering the
  real/common case beats an expensive one covering rare/hypothetical cases.** "Continue" ≠ "build the
  next thing" — it means "build the next thing that clears the value bar; if none do, say so and stop."
- **Check what already exists first** — grep the code AND read the open issues before writing new code;
  much may already be implemented or already filed.
- **MEASURE before optimizing, and profile — the bottleneck is rarely where you assume.** Don't ship a
  win that measures ~1×. **Never optimize by creating a blind spot.** When benchmarking, distinguish a
  hung harness from a slow run (`ps -o etime,%cpu`; 0% CPU = hung, not slow) — audit before killing.
- **Explain in plain language, not a jargon multiple-choice.** Lead with the real situation and a
  recommendation.

Related: `working-with-this-codebase`, `shipping-changes`.

## A guard must exercise what it guards

A self-test that re-derives what the check does is a second implementation, and the two drift. The
drift shows up as a **miss** (the guard passes while the check is blind) or a **false alarm** (the
guard is stricter than the check and blocks a host the check reads happily). Both have happened here.

Call the check's own code. Share the function that answers the question — the field selector, the
decoder, the resolver — so a change to one cannot leave the other behind. Where the guard depends on
something the check does not, ask **that** authority rather than trusting a registry to have been
right about a platform nobody tested.

## Never document a variable — fix the name

A comment attached to a constant is a name that failed. `_FIRST_READ_BYTES` needs no sentence;
`_CHUNK_BYTES` with a paragraph above it is the same information, worse placed. Long rationale does
not belong beside the code at all: it goes where the reasoning is kept.

**It breaks most often when the constant is a lookup table**, because the mapping feels like it needs
explaining. It does not — it needs naming. `_TOOLCHAIN` wants a paragraph;
`_TOOLCHAIN_THAT_LEAVES_EACH_KIND` wants nothing.

**A comment over a constant is restating the constant.** If you have written three lines above a
name, move them into the function below it and see how much survives — then hold what survives to
the docstring rule below, which is narrower than it looks.

## A docstring says what the function DOES — never what it cannot do

Three parts, in order, and nothing else: **one short line of WHAT IT DOES**, then **WHAT IT TAKES**
(each parameter that is not obvious), then **WHAT IT RETURNS**, including the falsy or absent case.
No algorithm, no "because", no measurement, no history, no rejected alternative, no threat model —
that reasoning goes to the private tracker, never to any surface that ships.

The failure that keeps recurring is subtler than writing reasoning: **letting the gap become the
definition.**

```python
# WRONG — opens on the result, then spends its words on the limit
"""Every commit on any local branch whose blob at `path` still confirms a payload, or None when
the path's history reaches the enumeration bound and cannot be walked."""

# RIGHT — a verb first, the limit demoted to one returns clause
"""Walk `path`'s history and collect the commits whose version of it carries a payload. Takes the
repo, the path, and the `survives` oracle that judges each version. Returns those commits, or None
when the history is too long to walk."""
```

- **Lead with a verb.** "Walk … and collect …", "Schedule … to be dropped …", "Search … for …".
  Opening with a noun phrase — "Every commit that …", "The nearest …", "`X`s for …" — describes the
  return value, not the behaviour, and step one is then simply missing.
- **The limit is never the subject.** `None`, error tokens, "skipped", "too-large" belong in the
  returns clause, at the end, in one breath. They do not get to define the function.
- **A scope word is not a definition.** "on any local branch" states a known scope *gap* as if it
  were the contract. Say what it walks; if the scope is a defect, it belongs in the tracker.
- **The test:** delete every clause about what it *cannot* do. If what is left does not say what the
  function *does*, the docstring is wrong.

Do not copy the surrounding style — older docstrings in this codebase explain rationale at length.
New and touched docstrings follow this rule.

