# Fix findings

`saw fix` cleans an infected repository **on a branch**, for you to review. It never edits your
working tree, and it pushes nothing unless you ask. Flags: [CLI
reference](../reference/cli/fix.md).

```bash
saw fix .                  # prepare security/auto-clean for this repository — no push, no network
git diff main...security/auto-clean
saw fix --pr               # also push and open (or update) one rolling PR per repository
saw fix --remote           # sweep GitHub targets: clone, fix, PR
```

Re-running updates the same PR rather than opening another.

## What gets fixed, and what does not

A payload is restored from git history — the real previous content, not a reconstruction — or the
file is quarantined whole. `saw` never surgically edits a source file, so a fix cannot corrupt valid
code. Where a clean version cannot be proven safe to restore, the finding is **deferred to review**
with the exact reason and the command to inspect it.

Heuristic (`suspicious`) findings are **never auto-fixed**. A repository with only heuristic findings
is disclosed and deferred, never reported "already clean". See [the safety
envelope](../explanation/safety-envelope.md).

## When you cannot push

`saw fix` degrades rather than giving up:

1. **Fork → cross-fork PR**, if the credential can fork.
2. Otherwise a `git am`-able **patch** under `sab-patches/`, plus a de-duplicated **issue** on the
   target repository if the credential can open one.

So remediation always leaves something actionable, even with read-only access.

## Undo it

```bash
saw discard --branch       # delete the auto-clean branch, locally and on the remote
saw discard --pr           # close the auto-clean PR, keep the branch
```

`saw discard` only ever touches the generated `security/auto-clean` branch.

## Never on the host

A compromised *machine* is never auto-cleaned. If `saw audit` reports the host as unsafe, follow
[audit a machine](audit-a-machine.md) instead.
