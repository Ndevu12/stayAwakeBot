# CLAUDE.md — stayAwakeBot / `saw`

Guidance for Claude Code (and any AI agent) working in this repository. This file is the always-on
summary; the detail lives in **`.claude/skills/`** (auto-discovered, portable) and `docs/`. Read the
relevant skill before non-trivial work.

## What this is

`saw` (package `stayawake`) is an **offline-first supply-chain worm scanner + sentinel** — detect,
report, remediate (PR-only), prevent, plus dependency-CVE auditing and local hygiene. Start with the
**`saw-overview`** skill and `docs/CLI.md`.

## Always-on rules (the ones that cost the most when missed)

1. **Zero downgrade in the scanner.** A missed detection is worse than a slow scan. Detection changes
   and perf/refactor work must be **byte-identical in findings** — prove it, don't assert it — and
   detectors are **tightened, never downgraded**.
2. **Analyze & ALIGN before consequential/design/security work.** Present the plan first; decide and
   recommend — **no option menus**. Ask before decisive/outward actions. Prove, don't assert. Stay
   focused. → `working-with-this-codebase`.
3. **Feature-branch PRs only — never push `main`.** Rebase on fresh `origin/main`; bare `Closes #NNNN`;
   CHANGELOG `[Unreleased]` in the same PR; signed commits; no `--admin`; merging/releasing are the
   maintainer's. → `shipping-changes`.
4. **Changes under `src/stayawake/bots/security/**` carry additional required checks and review
   obligations.** Agree the approach with the maintainer **before** opening the PR.
5. **Adversarially verify security-critical changes and gate the push** — parallel refuters, with the
   lens matched to the risk, re-verified until clean.
6. **Respect the layers** `utils→lib→core→bots→cli` (import down-only; inject callables up), enforced
   by `test_layering`.
7. **Offline & trust model:** accurate with zero flags; only `-x/--external` leaves the sandbox; the
   allowlist is operator-owned and never taken from a scanned repo; fail closed. → `saw-overview`.
8. **Value before coverage; measure/profile before optimizing; reuse before building; right depth, no
   bandaids; self-documenting names.** → `engineering-standard`.

## Skills index

`saw-overview` · `engineering-standard` · `working-with-this-codebase` · `shipping-changes` — see
`.claude/skills/README.md`, which also states the rule these follow: **skills publish obligations,
never detection mechanisms.**

## Tests

Stdlib `unittest`: `python -m unittest discover -s tests`. The suite is the ratchet — it stays green
(only mechanical mock repoints when code moves). `test_layering` enforces the architecture;
`test_redos_safety` bounds every regex.
