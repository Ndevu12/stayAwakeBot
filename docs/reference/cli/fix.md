---
description: saw fix — clean detected findings on a branch and publish them only as a pull request. Full option reference.
---

# `saw fix`

Clean detected findings **on a branch**. By default `fix` prepares `security/auto-clean` locally and
stops — no push, no PR, no network — for you to review. On a confirmed infection it also clears
the checkout you are standing in: the files it confirms, the installed tree, generated build
outputs, and the lockfile (the lockfile is kept on CI). A merge finding that is still live in the
working tree is restored there; the merge commit is left in history. `--pr` pushes and opens or
updates one rolling PR per repository. Bare `saw fix` publishes nothing.

**Those removals happen in your working tree, as the run happens.** They are not staged on the
branch and they do not wait for a pull request: the files are gone from the checkout you are
standing in whether the pull request is merged, closed, or never opened.

**On a confirmed infection everything a package manager put on disk is removed, whole** — every
installed tree in the repository, the dependency caches and resolver files a project uses instead
of one, the lockfiles, and the generated output directories. Whichever package manager the project
uses, and however many, the same holds. Nothing inside any of them is kept. Reinstall and rebuild
to restore them; whatever installed them can install them again.

A package manager's own directory keeps its patches, plugins and pinned releases, and only what the
resolver writes there is removed. A generated output directory goes whole, including what your
repository commits inside it: nothing reads those directories, so nothing in one can be called
clean. Name it under `keep_dirs` to keep it.

**The directories a scan leaves out are read too**, at any depth, and what they confirm is
removed. An installed tree is read once the others have confirmed an infection, after it is removed. When part of your checkout cannot
be read, the confirmed files are still removed one by one, but the installed trees are left and
the checkout is not called clean.
A link saw confirms is removed; the file it points at goes only when that file carries the payload
itself.

**What is not this repository's, it does not take.** Anything linked to a location outside the
repository loses the link, and what it points at is left alone. Directories you listed under
`keep_dirs` are never removed, and neither is anything inside them. Write each one relative to the
repository root — `data`, or `dist/assets` for one directory of a generated tree. A name alone
keeps that directory at the root, not every directory sharing the name. `exclude_dirs` says what is
not scanned and does not decide this.

**Your uncommitted work is kept.** Once the cleanup is done, what your working tree holds and has
not committed is recorded on a local branch named `saw/uncommitted-…`, as it then stands. It is
never pushed, and your branch is not touched. What the run removed is not
on it, and neither is a file saw confirmed, nor one holding the same bytes as a file it confirmed;
a file it cleaned in place is saved cleaned. A file your
`.gitignore` covers, or one saw could not read, stays on disk only.

**What it confirmed leaves your staged changes too.** Your staged changes are read as well as the
files on disk, so a staged file you have since changed or deleted is still found. A staged file saw
confirmed goes back to what your current commit holds, or leaves your staged changes when that
commit holds nothing clean there.
A file in the middle of a merge keeps its other versions and stays unresolved, so git will not let
you commit it until you choose one. Everything else you staged is left as it was.

**Your history is reported on its own.** When the commit you are on, another local branch or a stash
entry still stores what the run removed, or a payload your commit holds that you have since deleted
or changed, on disk or in your staged changes, the run says so and names the remedy: the fix pull request
for a commit the base branch already has, and [`saw fix amend`](amend.md) for your own commits. A
stash entry is named only, because it also holds your own work.

**Files added in the same commit as the malware are yours to decide.** When that commit added
other files with no finding of their own, the run removes none of them, names them, and is not
called done or clean. Run [`saw fix amend`](amend.md) in that repository on a terminal to decide them.

`fix` cleans your working tree and records that as a new commit. What the repository already
stored stays stored: the payload is still there in the earlier commit, and one `git show` puts it
back on disk. Anyone who cloned or forked the repository still has it too, and nothing you do to
your own copy reaches theirs. Clearing it needs a history rewrite and the hosting provider's
collection — deliberate work, not something `fix` decides for you. Run
[`saw scan --history`](scan.md) to see what is still stored.

[`saw fix amend`](amend.md) is a different act: it amends the infected commits and force-updates
the branches that carried them. Read that page before you run it.

See [the safety envelope](../../explanation/safety-envelope.md) for what `fix` will and will not touch.

```text
saw fix [TARGETS...] [--pr] [-r] [--user U] [--org O] [-p PATH] [-c FILE] [-j N] [--no-stream]
```

| Option | Description |
| --- | --- |
| `TARGETS...` / `-p` / `-c` / `-r` / `--user` / `--org` / `-j` / `--no-stream` | As for [`saw scan`](scan.md). A missing *explicit* `--config` path is a clear error, never a crash. |
| `--pr`, `--open-pr` | Also push the branch and open/update one rolling, de-duplicated PR per repository. Needs a credential with repo + PR write; the API is pre-flighted before any push. Not accepted with `amend`. |
| `amend` | Replace past commits that still carry the payload and force-update each branch they sat on — see [`saw fix amend`](amend.md). Not accepted with `--pr`, `--branch`, `--user` or `--org`. |
