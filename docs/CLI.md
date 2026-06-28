# StayAwakeBot — `saw` CLI command guide

`saw` is StayAwakeBot's local **security** command-line tool — a supply-chain worm hunter you
run on your own machine to detect, report, and auto-remediate self-propagating malware
(obfuscated loaders, fake fonts, VS Code auto-run tasks, and stealth "evil merges").

> **Status: implemented; available from source. PyPI release pending.**
> The `saw` CLI is implemented (`stayawake.cli`) and works when you install from source (or
> editable, `pip install -e .`). It is **not in a tagged PyPI release yet**, so
> `pip install stayawakebot` from PyPI does not include it until the next release. The legacy
> `stayawake-security-*` scripts keep working everywhere — see [Migrating from the legacy
> scripts](#migrating-from-the-legacy-scripts).

## Contents

- [Overview](#overview)
- [Install](#install)
- [Synopsis](#synopsis)
- [Global options](#global-options)
- [Commands](#commands)
  - [`saw scan`](#saw-scan) · [`saw run`](#saw-run) · [`saw report`](#saw-report) ·
    [`saw alert`](#saw-alert) · [`saw fix`](#saw-fix) · [`saw audit`](#saw-audit) ·
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
| `-f`, `--fail` | `scan`, `run`, `audit` | Exit non-zero if the command found something actionable (findings or issues). The single unified gate flag for CI. Replaces the legacy `--fail-on-findings` / `--fail-on-issues`, which still parse. |
| `--json` | `doctor`, `search` | Emit machine-readable JSON instead of human-formatted output. |
| `-q`, `--quiet` | `doctor`, `search` | Print only the essentials (problems / command names). |

> Broader `--json` / `-q` coverage on the scan/report/fix commands is planned but not yet wired —
> those forward to the existing report writers, which today emit human text and JSON report
> *files* (not stdout JSON).

## Commands

### `saw scan`

Hunt for supply-chain worms across one or more repositories or directories.

```text
saw scan [PATHS...] [-L] [-c FILE] [-p PATH] [-d DIR] [-f] [--fix [--apply [--pr]]]
```

| Option | Description |
| --- | --- |
| `PATHS...` | Repo or directory paths to scan (ad-hoc, local). If omitted and nothing is configured, scans the current repository. |
| `-p`, `--path PATH` | Additional path to scan (repeatable); same effect as a positional path. |
| `-c`, `--config FILE` | Config file (default: `config/security.yml` when present). |
| `-L`, `--local` | Skip remote GitHub targets — scan local paths only. |
| `-d`, `--reports-dir DIR` | Where to write reports (default: `reports/security`). Use a scratch dir to avoid touching committed reports. |
| `-f`, `--fail` | Exit `1` if any scanned target is infected (for CI gating). |
| `--no-stream` | Disable the live progress/typewriter output — plain, instant lines. (Auto-off already when piped, in CI, or with `STAYAWAKE_NO_STREAM=1`.) |
| `--fix` | **Remediate in the same pass** — reuse the scan's findings to fix the scanned local repo(s); no second scan. Dry-run unless `--apply`. |
| `--apply` | With `--fix`: write fixes (originals backed up to quarantine) and commit them to a branch. Implies `--fix`. |
| `--pr`, `--open-pr` | With `--fix --apply`: push a fix branch and open/update one rolling, de-duplicated PR per repo. Implies `--fix`. |

```bash
saw scan                                  # scan the current repo
saw scan ./service-a ./service-b          # scan specific paths
saw scan -L -c config/security.yml        # local-only, configured targets
saw scan -f                               # gate: non-zero exit on any finding
saw scan --fix                            # scan AND preview fixes (dry-run), one pass
saw scan --fix --apply                    # scan and apply fixes, commit to a branch
```

> **Live progress.** On an interactive terminal, `scan` streams each target as it completes
> (`[3/9] [INFECTED] …`) with a spinner over the actual work and a typewriter cadence, so a
> long sweep never looks frozen. It's purely cosmetic pacing of deterministic results — and
> it **auto-disables** when piped, in CI, with `--no-stream`, or `STAYAWAKE_NO_STREAM=1`, so
> `stdout` and the report artifacts stay byte-for-byte unchanged. Progress goes to `stderr`;
> results to `stdout`.
>
> **`scan --fix` is the recommended remediation flow.** It runs detection and remediation
> from a single analysis pass — there is no re-scan and no report file in between — so a fix
> always acts on exactly what the scan just found. The standalone [`saw fix`](#saw-fix) remains
> for the org-wide remote sweep and back-compat.
>
> **How fixes are applied — reliably, never by guessing.** An injected payload is **recovered
> from git** (the file's last clean committed version is restored — the real original, not a
> reconstruction), or, when that can't be proven safe (born-infected, untracked, or legit edits
> sit on the payload), it is **deferred to manual review** with the exact reason and command.
> Fonts/markers/VS-Code-autorun use reliable whole-file-quarantine / exact-line removal. The
> scanner **never surgically edits a source file**, so a fix can never corrupt valid code; and
> heuristic-only (`suspicious`) matches — e.g. an inlined base64 asset — are reviewed, never
> auto-touched. Originals are always backed up to `.malware-quarantine/`.

### `saw run`

Run the full pipeline — **scan → report → alert** — in one process. Report paths are threaded
internally, so you never pass intermediate JSON files by hand.

```text
saw run [PATHS...] [-L] [-c FILE] [-d DIR] [-f]
```

Accepts the same path/config/reports options as [`saw scan`](#saw-scan). Pass `-f` to gate the
whole pipeline on findings.

```bash
saw run            # scan, render the report, send alerts — one command
saw run -f         # same, but exit non-zero if anything was found
```

### `saw report`

Render the latest scan results into a human-readable / markdown report.

```text
saw report [-l FILE]
```

| Option | Description |
| --- | --- |
| `-l`, `--latest FILE` | Latest results JSON to render (default: `reports/security/latest.json`). |

### `saw alert`

Emit alerts (Slack and/or GitHub issues) for the latest scan results.

```text
saw alert [-l FILE]
```

| Option | Description |
| --- | --- |
| `-l`, `--latest FILE` | Latest results JSON to alert on (default: `reports/security/latest.json`). |

Reads credentials from the environment: `SLACK_WEBHOOK_URL`, `GITHUB_TOKEN`, `GITHUB_REPOSITORY`.

### `saw fix`

Remediate detected worm findings. **Dry-run by default** — it shows what would change unless you
pass `--apply`. For the common "scan then fix" flow prefer [`saw scan --fix`](#saw-scan), which
remediates in the same pass without a second scan; `saw fix` is kept for the **org-wide remote
sweep** (`--remote`) and back-compat.

```text
saw fix [--apply] [--pr] [--remote] [-c FILE]
```

| Option | Description |
| --- | --- |
| *(no flags)* | Dry-run: report the fixes that would be applied. |
| `--apply` | Write fixes locally (originals backed up) and commit them to a branch. |
| `--pr` | With `--apply`: push a stable `security/auto-clean` branch and open/update one rolling, de-duplicated PR per repo. |
| `--remote` | Sweep the configured GitHub targets and open/update a dedup'd fix PR per repo. Needs a GitHub credential with repo + PR write scope (an env token or a `gh auth login` session). |
| `-c`, `--config FILE` | Config file. **Optional** — defaults to `config/security.yml` when present, else the current repository. An explicitly-passed path that does not exist is a clear error (exit `2`), never a crash. |

```bash
saw fix                       # dry-run — preview changes
saw fix --apply               # apply fixes locally and commit to a branch
saw fix --apply --pr          # apply + open/update one rolling PR per repo
saw fix --remote              # open fix PRs across configured GitHub targets
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
saw search "open a pr"     # → suggests `saw fix --apply --pr`
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

`saw` is quiet-friendly and scriptable — the exit code is the contract:

| Code | Meaning |
| --- | --- |
| `0` | Success / clean. (Also returned when findings exist but `-f/--fail` was not passed.) |
| `1` | The gate tripped: actionable findings or issues were present **and** `-f/--fail` was set. |
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

Verbs that share a first letter resolve at two characters: `re`→report, `ru`→run, `al`→alert,
`au`→audit, `se`→search; `scan`→`s`, `doctor`→`d`, `fix`→`fix`.

## Migrating from the legacy scripts

Every legacy `stayawake-security-*` command has a shorter `saw` equivalent. **The legacy scripts
keep working** (see [Compatibility & support](#compatibility--support)); migrate at your own pace.

| Legacy command | `saw` equivalent |
| --- | --- |
| `stayawake-security-scan` | `saw scan` |
| `stayawake-security-scan --fail-on-findings` | `saw scan -f` |
| `stayawake-security-scan --local-only --config config/security.yml` | `saw scan -L -c config/security.yml` |
| `stayawake-security-report` | `saw report` |
| `stayawake-security-alert` | `saw alert` |
| `stayawake-security-remediate` | `saw fix` |
| `stayawake-security-remediate --apply --open-pr` | `saw fix --apply --pr` |
| `stayawake-security-remediate --remote` | `saw fix --remote` |
| `stayawake-security-audit --repo OWNER/NAME --fail-on-issues` | `saw audit --repo OWNER/NAME -f` |

The renamed flags — `--local-only`→`--local`/`-L`, `--open-pr`→`--pr`, and the three
`--fail-on-*` flags → `-f/--fail` — are also accepted under their old spellings as hidden
aliases, so copy-pasted commands and existing scripts never break.

## Compatibility & support

- **Legacy scripts are frozen.** All eight `stayawake-*` console scripts (5 security, 3 health)
  remain installed and accept their existing flags byte-for-byte. `saw` is **additive**; it never
  removes or changes a legacy entry point.
- **CI and Docker are unaffected.** The remote workflows
  ([security-sentinel.yml](../.github/workflows/security-sentinel.yml),
  [security-remediate.yml](../.github/workflows/security-remediate.yml),
  [worm-guard.yml](../.github/workflows/worm-guard.yml)) and the Docker image call the legacy
  scripts and continue to work unchanged. The flags `--local-only` and `--fail-on-findings` are a
  **frozen public contract** relied on by the SHA-pinned `worm-guard` scanner.
- **Health stays remote-only.** The `stayawake-health-*` scripts powering the `*/5` uptime cron
  ([stayawake-sentinel.yml](../.github/workflows/stayawake-sentinel.yml)) are untouched and are
  intentionally not exposed as `saw` subcommands.
- **Deprecation.** A future major release may remove the legacy *security* scripts and old flag
  spellings; they will warn (to stderr, suppressible via `STAYAWAKE_NO_DEPRECATION=1`) before
  removal. `pip install stayawakebot` remains stable throughout.

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

| Operation | Legacy | `saw` | Reduction |
| --- | --- | --- | --- |
| Scan + CI gate | `stayawake-security-scan --fail-on-findings` | `saw scan -f` | −74% |
| Full pipeline | `…scan && …report && …alert` | `saw run` | −91% |
| Remediate + PR | `stayawake-security-remediate --apply --open-pr` | `saw fix --apply --pr` | −57% |
| Audit + gate | `stayawake-security-audit --repo … --fail-on-issues` | `saw audit --repo … -f` | −46% |

### Design decisions

| Decision | Choice |
| --- | --- |
| Scope | Security-only CLI; health stays remote-only, scripts unchanged |
| Binary | `saw` (+ `stayawake` collision-proof long alias) |
| Command shape | Flat top-level verbs; hidden reserved `saw sec <verb>` seam for a future 2nd local bot |
| Fail flag | Single `-f`/`--fail`; legacy `--fail-on-*` kept as hidden aliases |
| Pipeline | `run` (no scope arg — one bot) |
| `remediate` → `fix`; `find` → `search` | Terser verbs; `search` avoids the `fix` prefix clash |
| `alias` | Full-word only, so `al` resolves to `alert` |
| Back-compat | All 8 `stayawake-*` scripts frozen byte-for-byte; new flag spellings additive |

### Reserved for the future

The visible surface is flat, but `saw sec <verb>` is reserved (hidden) as a namespace seam. If a
second capability ever needs a local CLI, the convention is already set — each bot owns a
`saw <bot> …` group, with the primary bot's verbs promoted to the root as shortcuts — so a future
`saw health …` would be symmetric with the reserved `saw sec …`.
