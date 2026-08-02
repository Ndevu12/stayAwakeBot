---
name: security-change-discipline
description: How to change detection, trust, defaults, or remediation in stayawake without introducing a downgrade. TIGHTEN don't downgrade (the depth method), byte-identical refactors, adversarial-verification gating the push, confidence-graded verdicts, and never auto-fixing a compromised host. Apply to ANY change under bots/security or affecting a security default.
---

# Security-change discipline

A scanner downgrade is the costly failure — a missed detection is worse than a slow scan. Treat every
change to detection / a trust mechanism / a security default / remediation with this discipline.

## TIGHTEN, don't downgrade — the depth method (run PER change)

Reflex to avoid: hit a false positive → conclude "this construct is FP-prone" → delete it. That
optimizes the visible FP and ignores what the code was built to catch. Instead:

1. **Origin & intent** — `git log -S<symbol>` / the issue: WHY does this exist, what threat, whose
   design?
2. **Full case matrix** — enumerate EVERY case it must CATCH and every benign case it must CLEAR — not
   just the FP in front of you.
3. **Prove coverage EMPIRICALLY** — for each MUST-CATCH, actually test whether the remaining code
   catches it. Don't assume.
4. **Fix the GAP, don't downgrade** — corroborate/tighten to kill the FP while KEEPING the capability.
   Remove only a signal with genuinely NO distinguishable value.
5. **Align before coding** on anything consequential.

Upgrade-never-downgrade is cross-cutting: **refactors must be BYTE-IDENTICAL** (prove per
section/definition vs HEAD; the suite is the ratchet, stays green unedited except mechanical mock
repoints). A perf optimization must be **provably byte-identical in detection** (diff findings vs
`main` on clean AND planted-payload corpora). Clean code is part of accuracy (no unused imports, no
private internals leaked through a facade). **Right-size to the threat, not the maximal engine.**

## Adversarial verification — gate the push

For any change to default network behavior, a trust mechanism, a security default, detection, or
remediation: run **parallel refuter agents**, each trying to REFUTE one specific safety property with
a structured `{verdict, severity, evidence}` verdict, and **hold the push until clean**. Happy-path
tests verify intended paths; adversarial verification finds where an invariant *silently* breaks.

- **Match the lens to the risk:** refute-the-safety-property (trust/remediation/concurrency),
  **FP-hunt** (a new detector — does it fire on realistic legit code?), **FN-hunt / coverage**
  (a REMOVAL or an optimization gate — does a remaining arm still catch every MUST-CATCH? is the
  "necessary anchor" truly necessary for *every* arm?), **under-alarm / proportionality**
  (messaging/severity changes).
- **An FP-hunt tells you a signal is noisy; it does NOT tell you removing it is safe** — add an
  FN/coverage lens to every removal.
- **Re-verify until clean** — fixing a violation can leave the same class one level deeper; run a
  FRESH pass on the amended diff (agents read files live) and push only when all-SAFE. Tell refuters
  the accepted residuals so they don't re-report them.
- These have a long track record of catching real bugs the green suite missed (data-loss in
  remediation, detector FP collisions, a Ctrl-C hang, a read-error message non-determinism, an
  under-parallelized chunker). Prove, don't assert.

## Verdict & remediation stance

- **Confidence-graded verdicts:** clean / suspicious / infected by per-signature confidence — only
  `confirmed` → INFECTED; heuristics → SUSPICIOUS (surfaced, never asserted as malware, never
  CI-fail). Set confidence when adding a signature.
- **Never auto-fix a compromised HOST** — "fixed" would imply "clean" (a lie) and risks a wiper.
  Rotate credentials LAST (isolate → neutralize → rotate). Remediation ships only provably-safe
  partial fixes (git-corroborated excision or human-confirmed), with a fail-closed PARTIAL choke
  point. Match language confidence to evidence confidence; don't accuse on weak signals.

Related: `engineering-standard`, `working-with-this-codebase`, `security-hardening-patterns`,
`scanner-performance`.
