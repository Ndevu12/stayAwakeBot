# StayAwakeBot — `saw` CLI command guide

`saw` is StayAwakeBot's local **security** command-line tool — a supply-chain worm hunter you
run on your own machine to detect, report, and auto-remediate self-propagating malware
(obfuscated loaders, fake fonts, VS Code auto-run tasks, and stealth "evil merges").

> **Status: implemented; available from source. PyPI release pending.**
> The `saw` CLI is implemented (`stayawake.cli`) and works when you install from source (or
> editable, `pip install -e .`). It is **not in a tagged PyPI release yet**, so
> `pip install stayawakebot` from PyPI does not include it until the next release. The legacy
> `stayawake-security-*` scripts have been **removed** — `saw` is the only local security
> surface; see [Migrating from the legacy scripts](#migrating-from-the-legacy-scripts).

## Contents

- [Overview](#overview)
- [Install](#install)
- [Synopsis](#synopsis)
- [Global options](#global-options)
- [Commands](#commands)
  - [`saw scan`](#saw-scan) · [`saw fix`](#saw-fix) · [`saw discard`](#saw-discard) · [`saw audit`](#saw-audit) ·
    [`saw search`](#saw-search) · [`saw doctor`](#saw-doctor) · [`saw completion`](#saw-completion)
- [Exit codes](#exit-codes)
- [Shell completion](#shell-completion)
- [Migrating from the legacy scripts](#migrating-from-the-legacy-scripts)
- [Compatibility & support](#compatibility--support)
- [Appendix: design rationale](#appendix-design-rationale)

## Overview

- **`saw` is security-only by design.** It exposes the supply-chain worm hunter for local use.
- **The health (uptime) bot is not part of this CLI.** It runs remotely-only (a GitHub Actions
  `*/5` cron) via its own `stayawake-health-*` console scripts; those are unaffected by `saw`.
- **One scanner, two surfaces.** The same engine runs locally as `saw` and in CI as the
  published `strix` GitHub Action. How the names relate:

  ```text
  stayawakebot   the product / PyPI distribution        (pip install stayawakebot)
  strix          the remote CI gate / GitHub Action      (uses: Ndevu12/strix@<sha>)
  saw            the local worm hunter / this CLI         (+ `stayawake` long alias)
  ```

## Install

```bash
pip install stayawakebot          # from PyPI
# or the latest from source:
pip install "stayawakebot @ git+https://github.com/Ndevu12/stayAwakeBot@main"
```

Installing provides two equivalent binaries:

- **`saw`** — the short everyday command used throughout this guide.
- **`stayawake`** — an identical, collision-proof long alias. Prefer it in scripts/CI where a
  3-letter name might clash with another tool on `PATH`.

Verify your install with [`saw doctor`](#saw-doctor).

## Synopsis

```text
saw <command> [options] [PATHS...]
```

`saw` with no command prints help. Every command supports `-h/--help`, which documents that
command's options.

## Global options

Available on `saw` itself:

| Option | Description |
| --- | --- |
| `-h`, `--help` | Show help for `saw` or any command. |
| `--version` | Print the package version and a capability inventory (`security: local + CI; health: CI-only`). |

A few flags recur across commands but are **not** universal — they only exist where they mean
something:

| Option | Where | Description |
| --- | --- | --- |
| `-f`, `--fail` | `audit` | Exit non-zero if the audit found a warning-level issue (the CI gate for `saw audit`). **`saw scan` has no `--fail`** — its exit code is the verdict, unconditionally; see [Exit codes](#exit-codes). |
| `--json` | `scan`, `doctor`, `search` | Emit machine-readable JSON to stdout instead of human-formatted output. On `scan` it carries full evidence (see [`saw scan`](#saw-scan)). |
| `-q`, `--quiet` | `doctor`, `search` | Print only the essentials (problems / command names). |

## Commands

### `saw scan`

Hunt for supply-chain worms across one or more repositories or directories. **`saw scan` is
terminal-first: it renders a full human report — with full match evidence — to `stdout` and
persists nothing by default.** Progress goes to `stderr`, and the **exit code is the verdict,
unconditionally** (`0` clean / `1` infected) — there is no `--fail` flag; a CI gate simply
checks the exit code. Output beyond the terminal is delivered through opt-in "sinks":
`--json`, `--sarif`, `--alert`, and `-d`.

`scan` is **read-only** — it never changes a file. Remediation lives in [`saw fix`](#saw-fix).

```text
saw scan [PATHS...] [-r] [-c FILE] [-p PATH] [--json] [--sarif FILE] [--alert] [-d DIR] [--no-stream]
```

| Option | Description |
| --- | --- |
| `PATHS...` | Repo or directory paths to scan (local). If omitted and nothing is configured, scans the current repository. |
| `-p`, `--path PATH` | Additional path to scan (repeatable); same effect as a positional path. |
| `-c`, `--config FILE` | Config file (default: `config/security.yml` when present). |
| `-r`, `--remote` | Scan the configured GitHub targets instead of local repos. **Scope is local by default**; this switches it to remote. |
| `--json` | Emit a machine-readable JSON report to `stdout`, with **full evidence**. Ephemeral — pipe it; writes no file. |
| `--sarif FILE` | Write a SARIF 2.1.0 report to `FILE` for upload to GitHub code-scanning. Evidence is **redacted** in the file (fingerprint only). |
| `--alert` | Push the durable record **in this pass**: open/close a GitHub issue per infected repo and post a Slack summary. Reads `GITHUB_TOKEN`, `GITHUB_REPOSITORY`, `SLACK_WEBHOOK_URL` from the environment; issue/Slack bodies are **evidence-free**. |
| `-d`, `--reports-dir DIR` | **Opt-in:** also write `latest.json` + `latest.md` into `DIR`. Evidence is **redacted** in these files (fingerprint only). |
| `--no-stream` | Disable the live progress/typewriter output — plain, instant lines. (Auto-off already when piped, in CI, or with `STAYAWAKE_NO_STREAM=1`.) |

```bash
saw scan                                  # scan local targets; full report to terminal; writes nothing
saw scan ./service-a ./service-b          # scan specific paths
saw scan --remote                         # scan the configured GitHub targets instead
saw scan -c config/security.yml           # use a specific config
saw scan; echo $?                         # gate: exit code is the verdict (0 clean / 1 infected)
saw scan --json > report.json             # machine-readable, full evidence, to a pipe
saw scan --sarif scan.sarif               # redacted SARIF for GitHub code-scanning upload
saw scan --alert                          # open/close issues + Slack summary, in-pass
saw scan -d /tmp/sab-reports              # opt-in redacted latest.json + latest.md
```

> **A report is a message, not a file.** The full report — including full match evidence —
> only ever appears on the live terminal (`stdout`) or via `--json`. Any **persisted** artifact
> (`--sarif`, `-d`) stores a redacted fingerprint `{sha256, preview (first 24 chars), len}` in
> place of the raw payload, so a security report on disk can never re-distribute a live malware
> payload. Durable records live **outside the repo tree** — GitHub code-scanning (SARIF,
> uploaded not committed), GitHub issues + Slack (`--alert`), and CI artifacts; security reports
> are **no longer committed** into the repo.

> **Live progress.** On an interactive terminal, `scan` streams each target as it completes
> (`[3/9] [INFECTED] …`) with a spinner over the actual work and a typewriter cadence, so a
> long sweep never looks frozen. It's purely cosmetic pacing of deterministic results — and
> it **auto-disables** when piped, in CI, with `--no-stream`, or `STAYAWAKE_NO_STREAM=1`, so
> `--json` and any persisted artifact stay byte-for-byte unchanged. Progress goes to `stderr`;
> the report goes to `stdout`.
>
### `saw fix`

Clean up detected worm findings on a branch. **By default `fix` PREPARES the fix on a local
`security/auto-clean` branch and stops** — no push, no PR, no network — leaving it for you to
review and push. It never edits your working tree (the fix lives on the branch), so it can't
corrupt code and makes zero surprise remote writes. `--pr` additionally **pushes** the branch
and opens/updates one rolling PR per repo (re-runs update it, never duplicate). `--remote`
sweeps the configured GitHub targets (clone → fix → PR). Scope is **local by default**; each
repo's outcome **streams live**.

```text
saw fix [PATHS...] [--pr] [-r] [-p PATH] [-c FILE] [--no-stream]
```

| Option | Description |
| --- | --- |
| `PATHS...` | Repo/dir paths to fix (local). Omit to fix configured targets or the current repo. |
| `-p`, `--path PATH` | Additional path to fix (repeatable). |
| `--pr`, `--open-pr` | Also **push** the branch and open/update one rolling, de-duplicated PR per repo. Needs a GitHub credential with repo + PR write scope; the API is **pre-flighted** before any push. |
| `-r`, `--remote` | Sweep the configured GitHub targets (clone → fix → PR) instead of local repos. |
| `-c`, `--config FILE` | Config file. **Optional** — defaults to `config/security.yml` when present, else the current repository. A missing explicit path is a clear error (exit `2`), never a crash. |
| `--no-stream` | Disable the live per-repo progress output — plain, instant lines. |

```bash
saw fix                       # prepare a security/auto-clean branch per local infected repo (no push)
saw fix .                     # prepare a branch for the current repo; review the diff, then push
saw fix --pr                  # also push + open/update one rolling PR per repo
saw fix --remote              # sweep the configured GitHub targets, one rolling PR each
```

> **How fixes are built — reliably, never by guessing.** An injected payload is **recovered
> from git** (the file's last clean committed version is restored — the real original, not a
> reconstruction), or, when that can't be proven safe (born-infected, untracked, or legit edits
> sit on the payload), it is **deferred to manual review** with the exact reason and command.
> Fonts/markers/VS-Code-autorun use reliable whole-file-quarantine / exact-line removal. The
> scanner **never surgically edits a source file**, so a fix can never corrupt valid code; and
> heuristic-only (`suspicious`) matches — e.g. an inlined base64 asset — are disclosed in the
> PR for review, never auto-touched. The fix lives on a branch; nothing lands until you merge.

### `saw discard`

The inverse of `saw fix`: remove what it produced. Only ever touches the auto-generated
`security/auto-clean` branch — never a real branch. At least one of `--branch`/`--pr` is
required. Scope is **local by default**; `--remote` sweeps the configured GitHub targets.

```text
saw discard (--branch | --pr) [-r] [PATHS...] [-c FILE] [--no-stream]
```

| Option | Description |
| --- | --- |
| `-br`, `--branch` | Delete the `security/auto-clean` branch **locally and on its remote** (pure git — works even when the GitHub API is unreachable; deleting the remote branch auto-closes its PR). |
| `--pr`, `--close-pr` | **Close** the open `security/auto-clean` PR via the API (leaves the branch). |
| `-r`, `--remote` | Sweep the configured GitHub targets instead of local repos. |
| `PATHS...` / `-p` / `-c` / `--no-stream` | As for `saw fix`. |

```bash
saw discard --branch          # delete the auto-clean branch (local + remote) for each repo
saw discard --pr              # close the auto-clean PRs (keep the branches)
saw discard --branch --remote # delete the branch across the configured GitHub targets
```

### `saw audit`

Run a local security hygiene audit: credential exposure, editor (VS Code) settings, and —
optionally — a repository's default-branch protection.

```text
saw audit [--repo OWNER/NAME] [-b BRANCH] [-f]
```

| Option | Description |
| --- | --- |
| `--repo OWNER/NAME` | Also audit this repository's branch protection (needs a token). |
| `-b`, `--branch NAME` | Branch to check protection for (default: `main`). |
| `-f`, `--fail` | Exit `1` if any warning-level issue is found. |

```bash
saw audit                                       # local credential + editor hygiene
saw audit --repo Ndevu12/strix -f               # also gate on branch-protection issues
```

### `saw search`

Fuzzy "what's the command for…?" lookup over the whole command tree.

```text
saw search <text>
```

```bash
saw search "open a pr"     # → suggests `saw fix`
```

### `saw doctor`

Self-check: confirm that `saw` resolves to this installation, report whether a usable GitHub /
Slack credential is present, and note that the health entry points (`stayawake-health-*`) are
installed even though they are not `saw` subcommands.

```text
saw doctor
```

### `saw completion`

Print a shell-completion script for your shell. See [Shell completion](#shell-completion).

```text
saw completion {bash,zsh,fish}
```

## Exit codes

`saw` is quiet-friendly and scriptable — the exit code is the contract. For **`saw scan` the
exit code is the verdict, unconditionally** — a CI gate just checks it, no flag required:

| Code | Meaning |
| --- | --- |
| `0` | Clean. For `saw scan`, no scanned target is infected. For `saw audit`, no warning-level issue (or issues found without `-f`). |
| `1` | For `saw scan`, at least one target is **infected** — returned unconditionally (there is no `--fail` flag). For `saw audit`, a warning-level issue was found **and** `-f/--fail` was set. |
| `2` | Usage error (unknown command, bad option). |

## Shell completion

Because the short verbs are easiest to use with `<Tab>`, install completion once:

```bash
# bash
saw completion bash > /etc/bash_completion.d/saw       # or source it from your ~/.bashrc

# zsh
saw completion zsh  > "${fpath[1]}/_saw"

# fish
saw completion fish > ~/.config/fish/completions/saw.fish
```

Verbs that share a first letter resolve at two characters: `sc`→scan, `se`→search; the rest are
unambiguous at one — `a`→audit, `co`→completion, `d`→doctor, `f`→fix.

## Migrating from the legacy scripts

The legacy `stayawake-security-*` console scripts **have been removed** — `saw` is the only local
security surface. Each old command maps to a `saw` equivalent:

| Legacy command (removed) | `saw` equivalent |
| --- | --- |
| `stayawake-security-scan` | `saw scan` |
| `stayawake-security-scan --fail-on-findings` | `saw scan` (the exit code **is** the verdict — no flag) |
| `stayawake-security-scan --local-only --config config/security.yml` | `saw scan -c config/security.yml` (local is the default) |
| `stayawake-security-report` | `saw scan` (the report renders to the terminal) |
| `stayawake-security-alert` | `saw scan --alert` |
| `stayawake-security-remediate` | `saw fix` |
| `stayawake-security-remediate --apply --open-pr` | `saw fix` (cleanup is always a PR now) |
| `stayawake-security-remediate --remote` | `saw fix --remote` |
| `stayawake-security-audit --repo OWNER/NAME --fail-on-issues` | `saw audit --repo OWNER/NAME -f` |

The `stayawake-security-{scan,report,alert,remediate,audit}` entry points no longer exist; the
`stayawake-health-*` scripts (the remote-only health bot) are unchanged.

## Compatibility & support

- **Legacy security scripts are removed.** The five `stayawake-security-*` console scripts no
  longer exist; `saw` is the only local security surface. Migrate using the table above.
- **CI and Docker call `saw`.** The remote security workflows
  ([security-sentinel.yml](../.github/workflows/security-sentinel.yml),
  [security-remediate.yml](../.github/workflows/security-remediate.yml),
  [worm-guard.yml](../.github/workflows/worm-guard.yml)) and the Docker image invoke `saw`
  directly; the gate is `saw scan`'s **exit code**, and durable records are pushed via
  `--alert`, `--sarif` (uploaded to code-scanning), and CI artifacts rather than committed files.
- **Health stays remote-only.** The `stayawake-health-*` scripts powering the `*/5` uptime cron
  ([stayawake-sentinel.yml](../.github/workflows/stayawake-sentinel.yml)) are untouched and are
  intentionally not exposed as `saw` subcommands.

## Appendix: design rationale

> Background on why the CLI is shaped this way. Not needed to use `saw`.

### Why `saw`, and why security-only

The CLI replaces eight long hyphenated scripts (`stayawake-security-scan`, …) whose names were
hard to discover and remember, and whose "fail" flag was spelled three different ways. Because
only the security bot runs locally, the CLI is **security-only** and uses **flat top-level verbs**
(no bot-noun) for `git`/`cargo`-style terseness. The name `saw` is three keystrokes, a security
pun ("the sentinel *saw* the worm"), and the acronym of **St‑A‑W**ake; a `stayawake` long alias
ships alongside it as a collision-proof fallback.

### Keystroke comparison

| Operation | Legacy (removed) | `saw` | Reduction |
| --- | --- | --- | --- |
| Scan + CI gate | `stayawake-security-scan --fail-on-findings` | `saw scan` | −86% |
| Scan + alert | `…scan && …alert` | `saw scan --alert` | −68% |
| Remediate + PR | `stayawake-security-remediate --apply --open-pr` | `saw fix` | −74% |
| Audit + gate | `stayawake-security-audit --repo … --fail-on-issues` | `saw audit --repo … -f` | −46% |

### Design decisions

| Decision | Choice |
| --- | --- |
| Scope | Security-only CLI; health stays remote-only, scripts unchanged |
| Binary | `saw` (+ `stayawake` collision-proof long alias) |
| Command shape | Flat top-level verbs; hidden reserved `saw sec <verb>` seam for a future 2nd local bot |
| Output | Terminal-first — `saw scan` renders the report to `stdout` and persists nothing by default; durable records via opt-in sinks (`--json`, `--sarif`, `--alert`, `-d`) |
| Gate | `saw scan`'s exit code **is** the verdict (no `--fail`); `saw audit` keeps `-f`/`--fail` |
| `remediate` → `fix`; `find` → `search` | Terser verbs; `search` avoids the `fix` prefix clash |
| Evidence | Full evidence only on the live terminal / `--json`; persisted artifacts store a redacted fingerprint |
| Back-compat | Legacy `stayawake-security-*` scripts removed; `stayawake-health-*` unchanged |

### Reserved for the future

The visible surface is flat, but `saw sec <verb>` is reserved (hidden) as a namespace seam. If a
second capability ever needs a local CLI, the convention is already set — each bot owns a
`saw <bot> …` group, with the primary bot's verbs promoted to the root as shortcuts — so a future
`saw health …` would be symmetric with the reserved `saw sec …`.
