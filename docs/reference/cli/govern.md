---
description: saw govern — check a pull or checkout before it changes an open folder.
---

# `saw govern`

**Check an update before the open folder changes.** A pull, fetch, checkout, merge, rebase, submodule
update, or a GitHub command that lands files is checked outside the folder. The folder changes only
when that check is clean or residue. Suspicious, infected, and a check that did not finish leave the
folder as it was.

```text
saw govern prepare --json --repo <folder> --into <directory> --tool git|gh -- <arguments>
saw govern apply --json --repo <folder> --into <directory>
```

| Option / subcommand | Description |
| --- | --- |
| `prepare` | Check the command outside the open folder. The folder is not changed. |
| `apply` | Make the open folder match the tree that was checked. It does not fetch again. |
| `--repo` | The open folder. |
| `--into` | A directory outside that folder, where the check is kept. |
| `--tool` | `git` or `gh`. |
| `--json` | Print the report for a program to read. |
| `-c`, `--config FILE` | Your config. A repository's own config is never read. |

`apply` does nothing when the check was not clean or residue. Work you had not committed stays. When
it cannot be kept, the folder is left as it was.

A checkout you run yourself is still scanned by [`saw hook`](hook.md). `saw govern` does not replace
that, and it does not put that checkout back.
