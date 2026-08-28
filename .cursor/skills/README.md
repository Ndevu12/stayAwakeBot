# Agent skills for stayAwakeBot

Portable, repo-committed skills that carry the contribution conventions of this codebase, so any
contributor using Claude Code or Cursor (on any machine) gets the same discipline.

Claude Code auto-discovers `.claude/skills/`; Cursor auto-discovers `.cursor/skills/`. The two trees
are the same skills and **must stay in lockstep** — when a convention changes, update both in the
same PR. You can also invoke a skill by name.

Each skill is `<root>/skills/<name>/SKILL.md` with YAML frontmatter (`name`, `description`) and a
distilled, actionable body.

## The skills

| Skill | Use it when |
| --- | --- |
| **saw-overview** | Starting any work here — what `saw` is, its verbs, and the safety invariants every change must respect. |
| **engineering-standard** | Designing, adding capability, refactoring, or optimizing — SRP, DRY-not-too-DRY, self-documenting names, value-before-coverage, reuse-check + measure-first, right-depth. |
| **working-with-this-codebase** | Every non-trivial task — analyze & align before consequential work, decide-and-recommend (no option menus), ask before decisive actions, stay focused, prove don't assert. |
| **shipping-changes** | Committing or opening a PR — feature-branch PRs, rebase on `origin/main`, bare `Closes #NNNN`, CHANGELOG in-PR, signed commits. |

## What belongs here, and what does not

These skills state **obligations**: what a change must satisfy, and what a contributor must not do
alone. They deliberately do **not** state **mechanisms**: how a detector decides, which inputs gate
which analysis, where coverage ends, or how a control could be satisfied without doing the work it
protects. That material is maintained privately, because published detection mechanics are an
evasion aid.

**A map of where the tool looks — or does not look — is the same disclosure.** Enumerating the paths
examined, or the surfaces skipped, tells a reader where to hide and tells an operator nothing they
can act on. Public documentation states the **bound** — what a clean result covers and what it does
not — never the locations. The same goes for output, help text and commit messages.

Apply that test to every edit. "A detection change must be proven byte-identical before it ships" is
an obligation and belongs here. Naming the specific inputs a detector keys on is a mechanism and does
not — even when it would make the guidance more useful. If a skill feels thin because the useful
specifics are missing, that is the rule working, not a defect to fix.

## Maintaining

Keep skills **durable and distilled** — principles and workflow, not task or status logs. When a
convention changes, update the skill in the same PR that changes the code (like the CHANGELOG). New
durable knowledge → extend an existing skill before adding a new one.
