# Claude Code skills for stayAwakeBot

Portable, repo-committed skills that carry the working knowledge and conventions of this codebase, so
any contributor using Claude Code (on any machine) gets the same discipline — not just whoever
accumulated it locally. Claude Code auto-discovers these; you can also invoke one by name.

Each skill is `.claude/skills/<name>/SKILL.md` with YAML frontmatter (`name`, `description`) and a
distilled, actionable body. They are synthesized from long-running project memory — the durable
principles, workflows, architecture, and implementation patterns — not the ephemeral incident/status
notes.

## The skills

| Skill | Use it when |
| --- | --- |
| **saw-overview** | Starting any work here — what `saw` is, its verbs, and the trust/threat model (allowlist never trusts a scanned repo's config; scan read-only / fix PR-only; offline by default; fail closed). |
| **saw-architecture** | Adding/moving a module, choosing a layer, splitting an over-long file, or wiring a shared seam. The 5-layer `utils→lib→core→bots→cli` (enforced by `test_layering`). |
| **engineering-standard** | Designing, adding capability, refactoring, or optimizing — SRP, DRY-not-too-DRY, self-documenting names, value-before-coverage, reuse-check + measure-first, right-depth. |
| **working-with-this-codebase** | Every non-trivial task — analyze & align before consequential work, decide-and-recommend (no option menus), ask before decisive actions, stay focused, prove don't assert. |
| **shipping-changes** | Committing, opening a PR, or releasing — feature-branch PRs, rebase on `origin/main`, bare `Closes #NNNN`, CHANGELOG in-PR, `pin-bump-deferred` for `bots/security/**`, signed commits, publishing env. |
| **security-change-discipline** | ANY change under `bots/security` or to a security default — TIGHTEN don't downgrade (the depth method), byte-identical refactors, adversarial-verification gating the push, confidence-graded verdicts, never auto-fix a compromised host. |
| **scanner-performance** | Parallelizing or speeding up a scan — the `utils.parallel` seam, across-repo (#1205) + within-target (#1325) parallelism, the progress board, and the measure-first method (the hotspot is obfuscation CPU, not I/O). |
| **security-hardening-patterns** | Writing a regex/matcher, rendering untrusted text, calling the GitHub API, reading arbitrary files, or committing programmatically — ReDoS, log-injection, token preflight, FIFO guards, worktree signing. |

## Maintaining

Keep skills **durable and distilled** — principles, workflows, and stable architecture, not
task/status logs. When a convention changes, update the skill in the same PR that changes the code
(like the CHANGELOG). New durable knowledge → extend an existing skill before adding a new one
(DRY-but-not-too-DRY applies here too).
