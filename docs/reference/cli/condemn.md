---
description: saw condemn — remove an installed dependency tree the lockfile can rebuild.
---

# `saw condemn`

Removes the installed dependency tree of a repository that scans **confirmed infected**.

```text
saw condemn [PATH] [-n | --dry-run]
```

Packages your lockfile accounts for are removed. Everything else is copied aside first and kept —
an installed tree that has drifted from the lockfile is the only record of what actually ran.

It **refuses** on any other verdict. Removing an installed tree on a heuristic match would turn a
false positive into data loss.

It does **not** reinstall. Installing re-runs the lifecycle scripts, so that is your call to make
when you are ready.

## Exit codes

| Code | Meaning |
| --- | --- |
| `0` | The tree was removed, or `--dry-run` reported the split, or there was no tree |
| `2` | Refused — the verdict was not confirmed, or nothing proved the tree reconstructible |

See [exit codes](../exit-codes.md).
