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

`saw govern apply` makes your open folder match the tree that was checked, without fetching again.
The extension calls it only when the verdict was clean or residue, and your uncommitted work is
kept — or the folder is not changed and saw says why.

When the verdict is suspicious or infected, or the check could not finish, the update is held and
your open folder stays as it was. These commands never push and never open a pull request.
