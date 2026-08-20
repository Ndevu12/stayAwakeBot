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

## Ecosystems `saw` reads

A scan resolves what a repository declares and locks, in every ecosystem below, and matches it
against the advisory corpus. Nothing here needs configuring — whichever of these files a repository
has, `saw` reads.

| Language | Ecosystem | Read from |
| --- | --- | --- |
| JavaScript / TypeScript | npm | `package.json`, `package-lock.json`, `yarn.lock`, `pnpm-lock.yaml`, `npm-shrinkwrap.json` |
| Python | PyPI | `requirements*.txt`, `poetry.lock`, `Pipfile.lock`, `uv.lock` |
| Go | Go modules | `go.mod`, `go.sum` |
| Java / Kotlin | Maven | `pom.xml`, Gradle lockfiles |
| Rust | Cargo | `Cargo.lock` |
| PHP | Composer | `composer.lock` |
| C# / .NET | NuGet | `packages.lock.json` |
| Ruby | RubyGems | `Gemfile.lock` |

`saw db update -e <ecosystem>` limits a refresh to one of these; the default refreshes all of them.

Two checks go further than the declared list, and both name their scope on their own page: the
installed-tree comparison, which reads npm and PyPI trees as they exist on disk, and
[`saw scan --deep`](cli/scan.md), which reads the contents of installed npm packages.

Everything else `saw` does — the repository scan, the CI gate, `saw audit` on the machine itself —
is language-agnostic and applies whatever a repository is written in.
