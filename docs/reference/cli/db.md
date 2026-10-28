---
description: saw db — manage the offline advisory database of malicious packages and CVEs that a scan consults.
---

# `saw db`

Manage the [offline advisory database](../advisory-db.md).

```text
saw db update [-e ECO ...] [--cache-dir DIR] [--no-stream]
saw db status [--cache-dir DIR] [--require-snapshot DIGEST] [--max-age-days N] [--no-stream]
```

| Option | Description |
| --- | --- |
| `-e`, `--ecosystem ECO` | Limit the refresh to an ecosystem (repeatable); default: all supported. |
| `--cache-dir DIR` | Cache location (default: `~/.cache/saw/advisories`). |
| `--require-snapshot DIGEST` | `status` fails unless the snapshot equals `DIGEST` — pin it for reproducible CI. |
| `--max-age-days N` | `status` fails if the corpus is older than `N` days. Unknown age counts as stale. |

An advisory its publisher withdrew is not reported from a database saved by an older saw. A package
that database still lists as known-malicious is still reported. `saw db status` says the database
predates this saw. `saw db update` replaces it.

After an update, [`saw hook`](hook.md) and the pre-push check read again what they had already
checked, so a newly listed package is reported the next time it is pushed or checked out.
