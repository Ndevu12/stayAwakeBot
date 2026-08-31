---
description: saw fix amend — amend the infected commits and force-update the branches they sat on. Read the caution first.
---

# `saw fix amend`

!!! warning "This amends the infected commits"

    Every branch that reached the payload is force-updated on the remote. Anyone who already has
    those branches must reset to the new tips, and work started from the old ones will not merge
    cleanly. Tell your collaborators before you run it. If you are not sure you want that, use
    [`saw fix`](fix.md), which only prepares a cleanup branch.

Replace a past commit that still carries the payload and force-update each branch it sat on. That
force-update is the fix: an amend that never reaches the remote is not one. The replaced
commit keeps its original message and its original author, and the commits after it are replayed
onto the replacement.

```text
saw fix amend [TARGETS...]
saw fix amend --remote OWNER/REPO [OWNER/REPO...]
```

| Option | Description |
| --- | --- |
| `TARGETS...` | Repositories to amend. A named path that does not exist is an error, not a wider sweep. |
| `--remote` | Clone the named GitHub repositories and amend them. Slugs only. |
| `-c FILE` / `-j N` / `--no-stream` | As for [`saw scan`](scan.md). |

`--pr`, `--branch`, `--user` and `--org` are not accepted. There is no account-wide form: name each
repository.

## What you need first

- A credential that owns the repository or holds admin on it. Permission to push is not enough.
- A clone that is up to date with the remote branches you are amending.
- `user.name` and `user.email` set, so the amend records who made it.
- A signing key, if the repository signs commits or the commits being replaced are signed.

## It stops before moving anything

It tells you and changes nothing when any of the above is missing, when the remote branches cannot
be refreshed or read, when the replacement would drop content the finding does not cover, when the
previous commits cannot be captured first, or when the working tree — or another worktree holding
one of those branches — has uncommitted work.

If it cannot finish, it puts the branches back and says so. If it moved a branch and could not put
it back, it names that branch: look at that repository before doing anything else with it.

## What it leaves for you

- **A protected branch is never force-updated.** The amended history is published beside it under
  its own name, for you to open the pull request. A protection rule it cannot read is treated the
  same way.
- **Tags and forks are reported, not changed.** A tag or a fork that still reaches the replaced
  commit keeps a copy of it, and the run tells you.
- **The previous commits stay on the remote** until GitHub collects them.

See [the safety envelope](../../explanation/safety-envelope.md) for what `fix` will and will not
touch, and [`saw discard`](discard.md) to undo a `saw fix` branch — `amend` is not undone that way.
