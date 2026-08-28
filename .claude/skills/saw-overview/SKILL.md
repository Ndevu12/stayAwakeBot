---
name: saw-overview
description: Read first when working on StayAwakeBot / the `saw` CLI. What the tool is, its command surface, and the safety invariants every change must respect (scan is read-only; fix is PR-only; heuristics are never auto-fixed; offline by default; fail closed).
---

# saw / StayAwakeBot — overview & safety invariants

`saw` (package `stayawake`) is a distributable **supply-chain worm scanner + sentinel**: it detects,
reports, remediates, and *prevents* self-propagating package worms, plus does dependency-CVE auditing
and local hygiene. `docs/reference/cli/index.md` is the authoritative command reference; this skill is the mental model.

## Non-negotiable safety invariants

These are obligations on every change. The reasoning behind each, and the detection mechanisms they
constrain, are maintained privately — if a change appears to require breaking one, raise it with the
maintainer rather than working around it.

- **Offline and fully accurate by ZERO flags.** A default `saw scan` needs no network and no config.
  The *only* thing that leaves the sandbox is `-x/--external` (spawns installed auditors). Never add a
  runtime dependency or a network call to the default path; vendor comparators instead.
- **The allowlist is operator-owned, never target-owned.** Suppressions come from ONE operator-chosen
  config per run — `saw` never takes suppression input from the repository it is scanning. Allowlist
  rules must be signature-scoped.
- **`scan` is read-only; `fix` writes only what this repository owns; `harden` writes only
  the host.** `scan`'s exit code *is* the verdict (0 clean / 1 infected / 2 errored-fail-closed),
  unconditionally — a CI gate just reads it. `saw fix` prepares a local branch and only publishes
  with `--pr`. On a confirmed infection it also removes the installed tree, generated build outputs,
  and lockfile in that repository. Remediation NEVER lives in `scan`. `saw harden` creates host
  denials and never removes a project's tree.
- **Heuristic/SUSPECT findings are never auto-fixed**, and a compromised *host* is never
  "auto-cleaned".
- **Fail closed.** A target that could not be fully scanned (unreadable file, failed clone, malformed
  config) must never read as clean — it exits non-zero. Warn loudly; never fail silently.

## Command surface (see docs/reference/cli/index.md for detail)

`scan` (read-only hunt) · `fix` (PR-only remediation; on confirmed infection also removes the
installed tree in this repository) · `discard` · `audit` (+ `--verify` content-scans a non-repo
suspect dir; + credential/dependency hygiene) · `harden` (host denials; in place only after a
read-back; never a project's tree) · `db` (offline advisory corpus) · `guard`
(install/verify the CI gate) · `search` · `intro` · `doctor` · `completion`.

Scan scope is **local by default** (given paths / configured globs / current repo); `--remote`
(or `--user`/`--org`) switches to GitHub repos. One scope per run. The scan CLI is repo-oriented
(0 repos → fail closed). Large scans show a bounded dashboard plus a written full-report file; the
pager is opt-in (`--pager`), never default.

Related: `engineering-standard`, `working-with-this-codebase`, `shipping-changes`.

## The direction: reporting → acting

`saw` is being standardised from a tool that **reports** into one that **acts**. The complaint it
answers is that it flags things for a human to review and solves nothing. Judge every proposal by
whether it moves off that: **prefer doing the thing over instructing the user to do it, and one line
of output over a runbook.** Good antivirus quarantines and says one sentence.

The direction does not loosen anything below — it is why those rules exist. A tool that only reports
can afford a loose verdict; one that acts turns every false positive into damage.

**What acting may touch:** only what can be PROVEN derivable, and only after what cannot be is
preserved. **`saw` removes; it does not rebuild** — a rebuild re-runs the delivery path. **Capture
comes before anything destructive**, and a control that merely makes something fail is destruction by
another route, bound by the same rule. **Every action is gated on a confirmed finding.**

## Boundaries that settle questions before you reason about them

Each of these was crossed in real work, and each crossing changed what a user was told.

- **Silence is not a clean result — on every axis.** A check that could not run, a platform with no
  implementation, a file that could not be read, a process the kernel would not describe: each
  returns what a clean host returns. Say which one it was. A run that could not establish its answer
  never exits `0`.
- **A verdict that fires on an ordinary host is a defect, not caution.** It teaches operators to
  ignore the one code that matters, which protects the real findings underneath. Narrow it to the
  case that is actually a hole, and measure that it does not fire on a healthy machine.
- **`saw` reports on the host, never on itself.** No internal vocabulary reaches an operator. What
  they read is a condition of their machine and what to do about it — never that the tool may have
  failed its own checks.
- **`saw` may say what its own actions will destroy. It may not say what you can restore.** Advice
  to back up or preserve costs nothing; enumerating or auditing recovery tooling is someone else's
  capability, and out of scope.
- **`audit` audits and reports.** Nothing in that path may signal, stop or end a process. Acting is a
  different command's job, and it is gated on capture existing first.
- **Escalate on corroboration, never on the trigger.** A condition a feature exists to provide is not
  evidence of abuse of it, and two indicators one action creates are one act observed twice.

