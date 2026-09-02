---
description: saw scan — hunt for supply-chain worms across repositories. Read-only. Full option reference.
---

# `saw scan`

Hunt for supply-chain worms across repositories or directories. The full report — with full match
evidence — renders to stdout and **nothing is persisted** unless you ask for a sink; progress goes to
stderr. `scan` never changes a file.

```text
saw scan [TARGETS...] [-r] [--user U] [--org O] [-c FILE] [-p PATH] [-j N]
         [--json] [--sarif FILE] [--alert] [-d DIR] [--no-stream] [--pager]
         [--no-advisories] [-x | --external] [--deep] [--require-db]
```

| Option | Description |
| --- | --- |
| `TARGETS...` | Local repo/dir paths — or `owner/repo` slugs under `--remote`. Omit to scan configured targets, else the current repository. |
| `-p`, `--path PATH` | Another target (repeatable). |
| `-c`, `--config FILE` | Config file (default: `config/security.yml` when present). |
| `-r`, `--remote` | Scan GitHub repositories instead of local paths. See [Remote targeting](remote.md). |
| `--user USER` / `--org ORG` | Scan this GitHub user's / organisation's repositories (repeatable; each implies `--remote`). |
| `--json` | JSON report to stdout, with full evidence. Pipe it; it writes no file. |
| `--sarif FILE` | SARIF 2.1.0 report for GitHub code scanning. Evidence [redacted](sinks.md). |
| `--alert` | In this pass, open/close a GitHub issue per infected repository and post a Slack summary. Bodies are evidence-free. |
| `-d`, `--reports-dir DIR` | Also write `latest.json` + `latest.md` into `DIR`. Evidence redacted. |
| `-j`, `--jobs N` | Scan concurrently; see [shared flags](index.md#flags-shared-by-several-commands). A persisted report is byte-identical to a sequential run, and a worker that dies is an error, not a pass. |
| `--no-stream` | Disable live progress. (Already off when piped, in CI, or with `STAYAWAKE_NO_STREAM=1`.) |
| `--pager` | Page the report through `$PAGER` (default `less -R`). Off by default. |
| `--no-advisories` | Omit the dependency CVE section. Advisories never change the verdict, so this only quiets the output. |
| `-x`, `--external` | **Opt-in; the only flag that leaves the offline sandbox.** Also runs *installed* external auditors (`osv-scanner`, …) and folds their vulnerabilities into the advisory tier — such a tool may send your dependency list to its own servers. Absent tools are skipped; the verdict never changes. |
| `--deep` | **Opt-in, npm only:** also examine the contents of installed npm packages. Reading every dependency file adds roughly 10–60s on a large `node_modules`; the run stays offline and deterministic. |
| `--history` | Also read what the repository still **stores** — other branches, tags, and earlier commits. A file cleaned from your folder is still there and one command away (`git show`, `git clone --branch`). Reported as coverage; it never changes the verdict, because nothing stored there runs on clone or on build. Slow: it reads every stored version, not the current one. |
| `--require-db` | Fail the run when the [advisory database](../advisory-db.md) is absent or fails its integrity check, instead of continuing without it — for CI that must not lose advisory coverage silently. |

```bash
saw scan                                  # the repository you are standing in
saw scan ./service-a ./service-b          # specific paths
saw scan --org UB-TechDEV -j 8            # a whole org, 8 repositories at a time
saw scan --json > report.json             # machine-readable, full evidence
saw scan -d /tmp/saw-reports              # opt-in redacted latest.json + latest.md
```

On a terminal, a long sweep streams each target as it completes. A large sweep keeps the terminal to
a bounded dashboard and moves per-finding evidence into a written report, whose path is printed on
stderr — nothing is lost to scrollback, and you are never dropped into a pager. See
[the report a long scan writes for you](sinks.md#the-report-a-long-scan-writes-for-you) for where
that file lands and how long it survives.
