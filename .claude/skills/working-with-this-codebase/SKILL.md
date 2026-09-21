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
honestly reject non-fitting ideas rather than force them.

## Brief from the root — bound the cost, never the thinking

Adversarial *refuters* are narrower than investigators: each is handed one property and told to break
it. That is right for **verifying** a property, and wrong as the whole gate. **A gate built only of
narrow refuters can only find faults inside your design — never that the design is wrong.**

MEASURED on the amend track: an unsound remediation design was caught by a throwaway probe I wrote,
not by the gate that had just passed it; and a ref-scope fix took three rounds because each round I
moved the frame and the refuters dutifully re-verified inside the new one.

- **Always include one reviewer with a free hand**, told in as many words not to take your framing:
  *"I am deliberately not telling you what to check. Decide for yourself whether this is the right
  approach."* Give it the PROBLEM, stated neutrally, and the diff — then let it read the code.
- **Watch what leaks your framing into a brief**: pre-explaining your mechanism, listing the
  properties, naming the prior verdict, and — the quiet one — declaring "accepted residuals", which
  fences off whole avenues before anyone looks.
- **Different agents get different lenses, not the same list.** Usability, safety-seam, mechanics,
  adversarial. Independent lenses that CONVERGE are evidence; agents agreeing with your checklist are
  not — you wrote the checklist.
- **Bound the cost, not the judgement.** A budget and a shape count ("~20 tool calls", "the most
  serious thing you find") keeps a hunt from running away; it is not a licence to pre-decide what
  counts. An open *question* with a bounded *budget* is the shape.
- **Run them before building, not only after.** On this track, launching agents before implementing
  caught that an instinct to refuse was itself a denial-of-remediation bug.

## Before you start: the known-defects register

`Ndevu12/saw` holds `known-defects/` — every defect that is real, reproduced and **not yet fixed**,
grouped by the area of the tool it is about. It is not the issue tracker. **Read the area you are
about to work in before you start**, so the same thing is not rediscovered a fourth time and so a
`clean` result is never read as more than it is. Read `analysis/README.md` first for the evidence
grades every claim there carries.

**React when you hit one — do not re-file it.** A defect you hit again is the same defect: add the
occurrence to its entry with the **verdict and criticality at that stage**. The same behaviour can be
a coverage note at scan tier and critical at a remediation tier, and that difference is the record's
value. Filing it again as new loses "this is the third sighting".

**What never goes in the register:** anything that lets a scan report `clean` over something it did
not read. Being pre-existing is not a reason and neither is being busy — fix it, or fail it closed
with the proper exit code. Nor does anything the change itself broke: that is fixed in the change,
and its history is the record.

An entry answers four questions in order — what happens, how it was reproduced, whether the change
that found it introduced it, what it costs the operator — and **never how to fix it**: a gap and a
proposed repair are different records. Cite by symbol, never `file:line`. Version, never overwrite.
Both are machine-checked.

## Tests are the spec — you may not delete one to go green

A test failing after your edit means **you violated a contract you did not read**. Read it, and the
code it guards, before touching either.

- **Never remove a test to make a change pass.** That removes the evidence, and the next person
  cannot tell a deliberate decision from an accident.
- One may be removed **only when it is proven to test the wrong thing** — and the proof is
  executable, not an argument. Show the case where its assertion is false about behaviour anyone
  actually wants, then remove it in a change that says so.
- **Update a test only when your change affected it directly or through its dependencies.** If your
  change was withdrawn, its tests end at net zero against `main` — verify that, don't assume it.
- When you do update one, **improve it rather than change it.** Editing a fixture so your code passes
  is not an improvement; adding the assertion that pins the risk your change introduces is.
- **A withdrawn fix leaves its tests behind as characterisation** — locking in the behaviour that is
  still wrong, keeping the evidence executable, and forcing the next attempt to change them
  deliberately.

## Read the CI log before you touch anything

Every failure this project has produced was a real defect in the change, not flakiness. Read the
failing job's output and find the assertion. A local run is one machine, one interpreter, one
platform — it cannot tell you what a merge with `main` will do.

## A passing test is not a pin — mutate it

For every property that matters, revert the line that implements it and confirm the suite fails. A
**surviving** mutation means one of two things, and both need action: the test does not cover the
property, or the code is dead. An **anchor that did not match** is a false pass, not a pass — the
harness has to report the miss, or you will read "OK" and believe it.

Expect the first attempt to leave the load-bearing decision unpinned. That has been the norm here,
not the exception, and the fixtures written to kill a surviving mutation are usually the best tests
in the change.

## Adversarial rounds: re-verify until clean

Fixing a violation usually leaves the same class one level deeper — **including inside the fix you
just wrote**. Re-run on the amended tree, fresh, and tell the verifiers which residuals are already
accepted so they hunt new ground. Two rounds have never been enough; three has been.

## Pace: run what you changed, let CI run everything

The full suite is minutes; the affected modules are seconds. Run the modules locally, push, and let
CI be the authority on the whole suite across every supported interpreter — it is faster, and it
tests the platform matrix a single developer machine cannot.

Never run two full suites at once; they contend and each takes twice as long.

## Verify state, do not infer it

Read merged state from the repository (`git show origin/main:<path>`), never from push output or from
what you remember opening. Confirm an issue or PR number by reading it back before linking it. When
you find something already shipped that a plan says is outstanding, say so instead of building it
again.

## Fix it where you found it

Work that a change surfaces belongs in that change, not in a new ticket. File only what genuinely
needs a decision someone else must make, and say in the issue why it could not simply be fixed. A
backlog of things you noticed is not progress.

Related: `engineering-standard`, `shipping-changes`.
