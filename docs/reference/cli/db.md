---
description: saw db — manage the offline advisory database of malicious packages and CVEs that a scan consults.
---

# `saw db`

Manage the [offline advisory database](../advisory-db.md).

```text
saw db update [-e ECO ...] [--cache-dir DIR] [--no-stream]
saw db status [--cache-dir DIR] [--require-snapshot DIGEST] [--max-age-days N]
```

| Option | Description |
| --- | --- |
| `-e`, `--ecosystem ECO` | Limit the refresh to an ecosystem (repeatable); default: all supported. |
| `--cache-dir DIR` | Cache location (default: `~/.cache/saw/advisories`). |
| `--require-snapshot DIGEST` | `status` exits non-zero unless the snapshot equals `DIGEST` — pin it for reproducible CI. |
| `--max-age-days N` | `status` exits non-zero if the corpus is older than `N` days. Unknown age counts as stale. |
