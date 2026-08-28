---
description: Clean an infected repository with saw fix, which prepares the change on a branch for review and publishes only through a pull request.
---

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

## The fix cleans the tree, not the history

A fix is a forward commit: it changes what the files contain now. It does **not** rewrite history,
and it never will — a rewrite invalidates every fork, open pull request, existing clone and tag.

So after a merged fix the payload is gone from the working tree and from anything a clone, a build
or CI will run, but an earlier commit still holds it:

```bash
saw scan .                       # clean
git show HEAD~1:postcss.config.mjs   # still returns the old contents
```

That is residue, not execution — nothing runs it on clone or build. `saw scan` says so in its
coverage notes rather than letting `clean` imply the repository has no trace of it.

Removing the residue is a separate decision that is yours to make: it needs a history rewrite
(`git filter-repo`), a force-push of every affected branch, and a request to your hosting provider
to garbage-collect the unreachable objects — a force-push alone does not delete them. Forks keep
their own copies regardless.

## The installed tree

`saw fix` remediates repository files on a branch. The installed dependency tree is a different
object: part of it the lockfile can rebuild, and part of it exists only on this disk. [`saw
condemn`](../reference/cli/condemn.md) removes the first and keeps the second. It refuses unless
the repository is confirmed infected, and it does not reinstall.

## Never on the host

A compromised *machine* is never auto-cleaned. If `saw audit` reports the host as unsafe, follow
[audit a machine](audit-a-machine.md) instead.
