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
onto the replacement. Once the remote has moved, your clone's copy of the remote branches is
refreshed to match it; if it cannot be, the run says so.

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
previous commits cannot be captured first, when your checkout is in the middle of a merge, rebase,
cherry-pick or revert, when a folder the amend rewrites has been replaced by a link, or when another
worktree holding one of those branches has any uncommitted work.

## Your checkout and your uncommitted work

The checkout you run it in is treated as [`saw fix`](fix.md) treats it. Your uncommitted work comes
with you onto the amended history: a file the amend does not change keeps your edit, and a file it
does change keeps your version on disk, with what you staged still staged. Then your checkout is
cleaned as `fix` cleans it — the payload taken out of it and out of your staged changes, and your
uncommitted work saved on a local `saw/uncommitted-…` branch. Saved work is cleaned on your
machine and never pushed; a saved branch the remote already holds is force-updated like any other.

Run straight after `fix`, it finishes the job: the files `fix` removed and the settings it stripped
are taken out of every commit that carried them, whatever version each commit held. It reports
completion only when the history it rewrote no longer holds them.

If it cannot finish, it puts the branches back and says so. If it moved a branch and could not put
it back, it names that branch: look at that repository before doing anything else with it.

## Files added in the same commit as the malware

The commit that brought the malware often added other files that carry no finding of their own.
saw never removes those by itself.

- **On a terminal, for one repository,** it shows each such commit — its id, date and subject as the
  commit gives them, and what saw is removing from it — and lists the other files it added, numbered
  by folder, each with how many other files of your project mention it ("named by 2", "named by
  none"). Type `all` or the numbers of the files to take out, then `yes`. Press Enter to keep
  them all. It asks about at most ten such commits in one run; the rest are asked on the next. A
  file you take out is removed from that commit and every later commit that still holds it as it was
  added, even when an earlier run already replaced that commit; a version you changed later, and a
  copy another branch added on its own, stay. The same files added by the same malware on another
  branch go too. A file that commit changed, and did not add, is named, never removed. If that commit
  has left your history, saw takes out no copy of the file and names it for you to review.
- **Your answers are kept.** A file you keep is not asked about again, by `saw fix amend` or
  `saw fix`. A file you take out, here or in `saw fix`, is removed by later runs too, without asking
  again.
- **Anywhere else** — no terminal, CI, several repositories, `--remote` — none of them is removed. The
  run names them, is not called done, and remembers them, so running `saw fix amend` in that
  repository on a terminal later asks about them.
- **When the malware is in the repository's first commit,** saw names that commit for you to review.
- **A merge that brought the malware** may be asked about file by file on a terminal. A file you
  remove there is taken out of that merge and the commits after it, and the merge's other files are
  then asked about too.

## What it leaves for you

- **A protected branch is never force-updated.** The amended history is published beside it under
  its own name, for you to open the pull request. A protection rule it cannot read is treated the
  same way.
- **Tags and forks are reported, not changed.** A tag or a fork that still reaches the replaced
  commit keeps a copy of it, and the run tells you.
- **What it cannot confirm, it does not call done.** When it cannot read a version of a file in
  history, or cannot tell whether a branch, a tag, a stash, another checkout or your copy of the
  remote still holds what it took out, it finishes the rest of the clean-up and names what it could
  not confirm for you to review.
- **A clone missing part of its history is not rewritten.** Fetch it in full first. A branch that
  names a commit the clone does not hold is named for you to repair or delete.
- **The previous commits stay on the remote** until GitHub collects them.

See [the safety envelope](../../explanation/safety-envelope.md) for what `fix` will and will not
touch, and [`saw discard`](discard.md) to undo a `saw fix` branch — `amend` is not undone that way.
