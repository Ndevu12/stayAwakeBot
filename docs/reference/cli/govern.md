---
description: saw govern — check a git or GitHub update in a holding directory before the open folder changes.
---

# `saw govern`

```text
saw govern prepare --repo <open-folder> --into <holding-directory> --tool git|gh -- <arguments>
saw govern apply   --repo <open-folder> --into <holding-directory>
```

For the editor extension. When you pull, fetch, check out, switch, merge, rebase, reset, restore,
stash, cherry-pick, revert, stage files, check out a pull request, sync a repository, or download a
release or an Actions artifact, these commands check what the command would write before your open
folder changes.

`saw govern prepare` works out, in a holding directory saw owns, every file the command would write
into the folder and everything it would stage, whichever repository, index or objects the command
or its environment names. It scans each of them exactly as it would be written and prints the
verdict as the same document `saw scan --json` prints. Your open folder is not changed, and nothing
from the incoming repository runs.

`--deadline SECONDS` stops the check in time; an unfinished check is yours to decide, as below.

`saw govern apply` writes exactly what was checked into your open folder, without fetching again.
The extension calls it only when the verdict was clean or residue. When git would refuse the command
in your folder, for example because it would overwrite uncommitted work, saw says what git says and
the folder is not changed.

saw judges what the update brings against what it let into the folder before. A finding a changed
file already had in a tree saw let in is listed under `pre_existing` and does not hold the update,
unless it is confirmed. Anything else is judged in full, even when your branch already points at
it. An update that
changes a file in the folder git runs your hooks from is held until you let it in, even when
nothing is found in it, and so is an update that changes a file a hook manager runs or reads, such as
a husky, lefthook or pre-commit hook, a file any of those names, a package.json script or Makefile a
hook runs and the files that script names, or a file your configuration has git run or include. What
those files go on to load or run is checked by the scan like the rest of the update.

When the verdict is suspicious or infected, the update is held and your open folder stays as it
was. The answer says what to do in `next_steps`, and its `decision` lets you let the update in after
you review it: `saw govern apply --repo <folder> --into <dir> --accept <commit>` applies exactly the
commit saw checked. For an infected update, saw recommends leaving the folder unchanged; to let it in
anyway, add `--confirm <folder name>`. `saw govern verdict` then answers that you let that tree in.
A command that writes nothing into the folder or its index, such as creating a branch where the
folder already is, is carried out by saw exactly as it was checked, and what git said is shown. A command that stages files your folder
does not hold, such as `git reset` to a fetched commit or staging part of a file, is checked first:
a clean result is staged exactly as checked, and a finding holds the command, with the folder and
its index as they were.

A command that names another repository, index or set of objects, on its command line or in its
environment, is checked the same way. When what it would write is clean, running it is yours to
decide, as below.

When the update cannot be checked, you get the reason and the decision: run the command as
typed, then scan the folder with `saw scan`, or leave the folder as it is. A command that has git
run other programs, such as `git rebase --exec` or an interactive rebase, is one of these. These commands
never push and never open a pull request.

## An update that stops for conflicts

A pull, merge or rebase that stops for conflicts is checked like any other update: every file as it
will reach your folder, conflict markers included, and every file the incoming commit changes, as
that commit has it. The answer from `prepare` lists the files left to resolve under `conflicts`.

`saw govern apply` then brings in exactly what was checked, without fetching again, and leaves the
merge or rebase in progress in your folder, as git would. Its answer says so:

```json
{"applied": true, "conflicts": ["src/app.js"], "next_steps": ["The update is in the folder and stops for conflicts in src/app.js. Resolve them, then run `git commit`."]}
```

Resolve the conflicts, then run `git commit` for a merge or a pull that merges, or
`git rebase --continue` for a rebase. In a terminal, saw prints that next step, and the command
does not report success, so a command chained after it with `&&` does not run. A held update that
stops for conflicts is let in the same way, with `--accept` and, for an infected one, `--confirm`.
For a rebase, every commit it has yet to replay is checked too. Continuing a rebase saw brought in,
with `git rebase --continue` or `--skip`, runs as typed when what is left is what saw checked.
Anything else left is checked first; when the check finds something or cannot finish, the folder is
left as it is and the answer says how to leave the rebase. Continuing a rebase saw did not bring in
gets the answer starting it would get.

When the conflicts cannot be brought into the folder, the update is still checked. A clean one
brings that reason and the same decision as an update that cannot be checked, except for a pull,
where the only choice is to leave the folder as it is and `next_steps` names the command that brings
in exactly the commit saw checked. One saw holds stays out of the folder, and there is no way to let
it in.

## Covering your terminals

```text
saw govern install
saw govern status
saw govern uninstall
```

The editor extension checks updates for the folders you open in the editor. To check them in your
terminals too, and in the shells coding agents run, run `saw govern install`. From then on, when a
terminal pulls, fetches, checks out, switches, merges, rebases, resets, restores, stashes,
cherry-picks, reverts or stages files, saw checks what the command would write before it reaches the
folder you are working in, the same as in the editor. Any other git command that can bring files into the
folder, such as an alias, a mistyped command, `git clone` or `git worktree add`, asks you first, the
same as an update that cannot be checked. So does a command that would also update submodules, one
that writes a file it names, such as `git diff --output`, one that fetches through a remote it adds
or updates, a `git maintenance` that fetches or schedules runs, and a push into a repository with
files on this machine or one that names a program to run. A command that points git at files in a working tree to run, such as setting
`core.hooksPath` on its command line or in a configuration file its environment names, that lets a push change your folder's files, or that copies hooks from a folder in
a working tree into a new repository, asks you first too. A `gh` command that names its repository with `-R` is checked like any other. Open a new terminal, or
source the file the command names, for it to take effect.

In a repository with no working tree, such as a bare repository or a mirror clone, git runs as
typed: a fetch, `git fetch --prune`, `git remote update` or `git gc` there runs as it would without
saw. A command that creates or writes a working tree from such a repository, such as
`git worktree add`, a clone of it, or a command given a working tree with `--work-tree`, is checked
as usual, and so is a command in such a repository when the repository lies among the files of a
working tree.

In a terminal, an update that cannot be checked brings a question: run the command as typed? Answer
yes and the folder is scanned afterwards; after a clone or a new worktree, the folder it created is
the one scanned. Where there is no one to ask, the folder is left as it is;
set `SAW_GOVERN_DECISION=run-as-typed` or `SAW_GOVERN_DECISION=leave-unchanged` to decide ahead.
Whenever git does not run and saw does not write what the command would, saw says so and the command
does not report success, so a command chained after it with `&&` does not run.
A held update prints what to do and asks whether to let it in: a yes for a suspicious update, the
folder name for an infected one. That is never decided ahead; where there is no one to ask, the
folder is left as it is and saw prints the command to let it in.

`saw govern status` says whether your terminals are covered and whether the shell you are in is
covered yet. `saw govern uninstall` takes it back out, and your editor is unaffected. saw always
falls back to your real git and gh.

## Asking whether a tree is one saw let in

```text
saw govern verdict --repo <open-folder>
```

`saw govern verdict` answers whether the folder's current tree is one saw let in — scanned clean by
a hook, or carried in by govern with the tree still matching. It answers `let-in`, `not-let-in` (an
unknown commit, a tree changed on top of one saw let in, or a held tree you let in yourself), or
`could-not-answer`. It reads what saw
already recorded, so it scans nothing and changes nothing. An editor uses it to tell a change saw let
in from one that reached the folder another way.

## Putting the open folder back

```text
saw govern restore --repo <open-folder>
```

`saw govern restore` puts the folder back on the commit saw let in, keeping your uncommitted work.
The branch moves to that commit, so HEAD is not left detached, and nothing is fetched. Call it after
a verdict that the tree is not one saw let in. An editor uses it instead of running git over a tree
with unsaved changes.
