---
description: Why saw separates confirmed findings from heuristic ones, what each verdict means, and why advisories never fail a build.
---

# Verdicts

`saw` reports at two levels of certainty, and they lead to different actions.

## Confirmed and heuristic findings

A **confirmed** finding is one `saw` can stand behind: the content is malicious, not merely unusual.
A **heuristic** finding says something here does not look right and a person should decide.

The distinction is not a confidence percentage; it is a decision about what may be acted on
automatically. Confirmed findings can be [fixed](../how-to/fix-findings.md) mechanically. Heuristic
ones are disclosed for review and are **never auto-fixed** — that is the whole reason the two tiers
exist.

## Repository verdicts

| Verdict | What it means |
| --- | --- |
| clean | Nothing found, and the target was fully scanned. |
| suspicious | Heuristic findings only. Read them; nothing was changed. |
| infected | At least one confirmed finding. |
| error | The target could not be fully scanned — unknown, not clean. |

`suspicious` deliberately does not fail a build. A gate that goes red on maybes is a gate people
switch off, and a heuristic finding is not evidence of compromise. `infected` fails
unconditionally — there is no flag that makes it pass, and no flag needed to make it fail.

A repository with heuristic findings only is never reported as "already clean" by any command; it is
reported as what it is, with the findings shown.

## Advisories are a separate axis

Known CVEs in your dependencies are reported alongside findings and **never change the verdict**. A
vulnerable dependency is a thing to plan, not an infection to contain, and folding the two together
would make the gate meaningless in both directions. See [the advisory
database](../reference/advisory-db.md).

## The host verdict is its own thing

`saw audit` does not report clean or infected. It reports whether rotating credentials from this
machine is safe — see [audit a
machine](../how-to/audit-a-machine.md). A repository verdict never says anything about the machine,
and the machine's verdict never says anything about a repository.
