---
name: engineering-standard
description: The design bar for the stayawake codebase — SRP, DRY-but-not-too-DRY, reusability, self-documenting names, value-before-coverage, reuse-check and measure-first, fix-at-the-right-depth. Apply when designing, adding capability, refactoring, or optimizing; the maintainer asks explicitly whether new work honors these.
---

# Engineering standard

Write for a new/collaborating developer. New work is expected to honor these; be ready to say how it does.

## Design principles

- **SRP** — one reason to change per module. Decompose a god-module-in-waiting *before* adding
  capability (Resolver / Store / comparators / thin coordinator), don't pile features into one class.
- **DRY, but NOT too DRY.** *Good DRY:* one loader for sources sharing a schema, one canonical
  mapping table, reuse `Target`/`Finding`/allowlist/confidence stamping. *The boundary:* share an
  **interface, not code**, when the things are genuinely different — no universal super-parser, no
  universal `Version` class (semver ≠ PEP 440 ≠ Gem). Forcing different things together is the wrong
  abstraction.
- **Reusability & dependency inversion** — pieces with an obvious 2nd consumer stand alone; depend on
  an injectable interface so tests inject fakes and backends swap without touching callers.
- **Open/Closed & data/logic separation** — adding a case = add + register, touch nothing else. IoCs
  are **data** (`signatures.yml`), not code.
- **Self-documenting names** — name by meaning, not internal jargon (`tier1_only` → `constructs_only`;
  `scan_builds` → `scan_build_outputs`). A reader should understand a call site without hunting. Don't
  propagate pre-existing jargon into new identifiers; describe behavior in comments.
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
  "1×" win (a read-cache once measured ~1.0× because matchers read disjoint subsets). Never optimize by
  creating a blind spot. When benchmarking, distinguish a hung harness from a slow scanner
  (`ps -o etime,%cpu`; 0% CPU = hung, not slow) — audit before killing.
- **Explain in plain language, not a jargon multiple-choice.** Lead with the real situation and a
  recommendation.

Related: `working-with-this-codebase`, `saw-architecture`, `security-change-discipline`.
