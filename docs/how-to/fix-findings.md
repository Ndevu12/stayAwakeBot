---
description: Clean an infected repository with saw fix, which prepares the change on a branch for review and publishes only through a pull request.
---

# Fix findings

`saw fix` cleans an infected repository **on a branch**, for you to review. Source changes land
there and it pushes nothing unless you ask. On a confirmed infection it also removes the installed
tree, generated build outputs, and the lockfile in this repository (the lockfile is kept on CI).
Flags: [CLI reference](../reference/cli/fix.md).

```bash
saw fix .                  # prepare security/auto-clean for this repository — no push, no network
git diff main...security/auto-clean
saw fix --pr               # also push and open (or update) one rolling PR per repository
saw fix --remote           # sweep GitHub targets: clone, fix, PR
saw fix amend              # replace past commits that still carry the payload — local, not a PR
```

Re-running updates the same PR rather than opening another.

## What gets fixed, and what does not

A payload is restored from git history — the real previous content, not a reconstruction — or the
file is quarantined whole. `saw` never surgically edits a source file, so a fix cannot corrupt valid
code. Where a clean version cannot be proven safe to restore, the finding is **deferred to review**
with the exact reason and the command to inspect it. When a merge finding is still live in the
working tree, those files are restored on the review branch; the merge commit itself is left in
place. `saw fix amend` is for payload that propagated into past commits, not for the working
tree alone. It replaces those commits on the current branch. It does not publish, and it does
not move tags. The previous objects remain until collected.

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

## The tree and the history are different acts

Bare `saw fix` is a forward commit: it changes what the files contain now. After it, the payload
is gone from the working tree and from anything a clone, a build or CI will run, but an earlier
commit can still hold it. A run that finds the payload still in the files now restores those
files on the branch; it does not claim the tree is already clean.

```bash
saw scan .                       # clean
git show HEAD~1:postcss.config.mjs   # still returns the old contents
```

That is residue, not execution — nothing runs it on clone or build. `saw scan` says so in its
coverage notes rather than letting `clean` imply the repository has no trace of it.

`saw fix amend` is the history act. It replaces past commits the payload has already propagated
into. It does not publish, it does not move tags, and it does not clear forks or objects the
hosting platform still serves. A repository-wide rewrite remains a separate decision of yours.

## Never on the host

A compromised *machine* is never auto-cleaned. If `saw audit` reports the host as unsafe, follow
[audit a machine](audit-a-machine.md) instead.
