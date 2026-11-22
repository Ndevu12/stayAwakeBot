---
description: saw govern — check a git or GitHub update in a holding directory before the open folder changes.
---

# `saw govern`

```text
saw govern prepare --repo <open-folder> --into <holding-directory> --tool git|gh -- <arguments>
saw govern apply   --repo <open-folder> --into <holding-directory>
```

For the editor extension. When you pull, fetch, check out, switch, merge, rebase, update a
submodule, check out a pull request, sync a repository, or download a release or an Actions
artifact, these commands check what arrives before your open folder changes.

`saw govern prepare` carries the update out into a holding directory saw owns, scans what arrived,
and prints the verdict as the same document `saw scan --json` prints. Your open folder is not
changed, and nothing from the incoming repository runs.

`--deadline SECONDS` stops the check in time; an unfinished check is yours to decide, as below.

`saw govern apply` makes your open folder match the tree that was checked, without fetching again.
The extension calls it only when the verdict was clean or residue, and your uncommitted work is
kept — or the folder is not changed and saw says why.

saw judges what the update brings. A finding a changed file already had before the update is
listed under `pre_existing` and does not hold the update, unless it is confirmed.

When the verdict is suspicious or infected, the update is held and your open folder stays as it
was. The answer says what to do in `next_steps`, and its `decision` lets you let the update in after
you review it: `saw govern apply --repo <folder> --into <dir> --accept <commit>` applies exactly the
commit saw checked. For an infected update, saw recommends leaving the folder unchanged; to let it in
anyway, add `--confirm <folder name>`. `saw govern verdict` then answers that you let that tree in.
When the update cannot be checked, you get the reason and the decision: run the command as
typed, then scan the folder with `saw scan`, or leave the folder as it is. These commands
never push and never open a pull request.

## Covering your terminals

```text
saw govern install
saw govern status
saw govern uninstall
```

The editor extension checks updates for the folders you open in the editor. To check them in your
terminals too, and in the shells coding agents run, run `saw govern install`. From then on, when a
terminal pulls, fetches, checks out, switches, merges, or updates a submodule, saw checks what
arrives before it reaches the folder you are working in, the same as in the editor. Open a new
terminal, or source the file the command names, for it to take effect.

In a terminal, an update that cannot be checked brings a question: run the command as typed? Answer
yes and the folder is scanned afterwards. Where there is no one to ask, the folder is left as it is;
set `SAW_GOVERN_DECISION=run-as-typed` or `SAW_GOVERN_DECISION=leave-unchanged` to decide ahead.
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
