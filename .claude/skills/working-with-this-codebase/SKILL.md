---
name: working-with-this-codebase
description: How to collaborate here — analyze deeply and align BEFORE consequential/design/security work, decide-and-recommend (no option menus), ask before decisive actions, stay focused, warn loudly, and prove don't assert. Apply on every non-trivial task, especially before writing code for a design/security change.
---

# Working with this codebase (collaboration discipline)

These are hard-won working agreements with the maintainer. Following them prevents rework and churn.

## Analyze and ALIGN before implementing (consequential/design/security work)

- Dig deep as a multi-domain expert (engineering / GitOps / DevOps / security). Lay out
  context → problem → impact → trade-offs → **a recommendation**. Don't react fast.
- **Present the PLAN before writing code** for anything structural or consequential — the maintainer
  wants to review the approach first. Report exactly what you intend to change and why.
- **Decide the best solution and recommend it — do NOT offer option menus.** Reserve a discrete
  question only for a genuine, well-understood fork the maintainer must own; never a wall of choices,
  never internal-jargon options. "Do them ALL / the complete proper fix," not "pick one."
- Retract wrong facts plainly the moment you find them.

## Ask before decisive / outward-facing actions

Present options + ask before consequential choices: disabling a feature, changing permissions or repo
settings, merging, closing an issue, cutting a release, force-pushing shared refs. Don't chain quick
fixes to force a green result. (Merging PRs and cutting releases are the maintainer's, not yours.)

## Stay focused

Stay on the current target. When redirected, **fully drop the prior thread** — surface a critical
tangent once, then let it go; don't keep dragging it back. Reproduce a bug with evidence when asked to
"dig into this."

## Warn loudly, never fail silently; prove, don't assert

- Degrade to a safe skip on malformed input (wrap detection/analysis in try/except) — but a genuine
  gap must be surfaced and fail closed, never swallowed.
- **"Tests pass" is not proof for a security/behavior claim.** Show the byte-diff, the empirical case
  matrix, the measured numbers, the adversarial verdict. Match language confidence to evidence
  confidence.

## Launching investigators (open mandate)

When you spawn investigator subagents to find the best approach, give them an **open, upgrade-oriented
mandate** — "find the strongest proper improvement, measure it" — not a biased checklist that primes
them to hunt only downsides. Consider all sides, but the objective is the best upgrade, and let them
honestly reject non-fitting ideas rather than force them. Adversarial *refuters*, used to gate a
security change, are the deliberate opposite — don't conflate the two.

Related: `engineering-standard`, `shipping-changes`.
