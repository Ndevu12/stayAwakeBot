---
description: The offline corpus of malicious-package and CVE advisories a scan consults, how to refresh it and how to gate on its freshness.
---

# The advisory database

An offline corpus of malicious-package and CVE advisories (OpenSSF, GitHub Advisories, OSV.dev) that
a scan consults to flag known-bad dependencies. It is cached at `~/.cache/saw/advisories` and read
entirely offline; downloading it is the only step that needs a network.

```bash
saw db update                     # fetch or refresh it, all ecosystems
saw db update -e npm -e pypi      # just these
saw db status                     # fingerprint, age, per-ecosystem counts, integrity
```

Advisories are reported alongside findings but **never change the verdict or the exit code** — a CVE
in a dependency is not an infection. Quiet them for one run with `saw scan --no-advisories`.

## In CI

Without the corpus a scan continues with less advisory coverage rather than failing. When a job must
not lose that coverage silently, require it:

```bash
saw db status --max-age-days 30                  # fail if the corpus is stale or missing
saw db status --require-snapshot <digest>        # pin an exact snapshot for reproducibility
saw scan --require-db                            # exit 2 rather than scan without it
```

Unknown age counts as stale.

Flags: [CLI reference](cli/db.md).
