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

- [Cheat sheet](#cheat-sheet)
- [Overview](#overview)
- [Install](#install)
- [Synopsis & global options](#synopsis--global-options)
- [Commands](#commands)
  - [`saw scan`](#saw-scan) · [`saw fix`](#saw-fix) · [`saw discard`](#saw-discard) ·
    [`saw audit`](#saw-audit) · [`saw db`](#saw-db) · [`saw search`](#saw-search) ·
    [`saw intro`](#saw-intro) · [`saw doctor`](#saw-doctor) · [`saw completion`](#saw-completion)
- [Remote targeting (`--remote`)](#remote-targeting---remote)
- [How reports are stored (evidence & redaction)](#how-reports-are-stored-evidence--redaction)
- [Exit codes](#exit-codes)
- [Command aliases & shell completion](#command-aliases--shell-completion)
- [Migrating from the legacy scripts](#migrating-from-the-legacy-scripts)
- [Compatibility & support](#compatibility--support)
- [Appendix: design rationale](#appendix-design-rationale)

## Cheat sheet

```text
saw <command> [options] [TARGETS...]      # no command → welcome banner;  -h/--help on any command
```

| Command | What it does | Touches files? |
| --- | --- | --- |
| [`saw scan`](#saw-scan) | Hunt for worms; render a full report to the terminal | **Read-only** |
| [`saw fix`](#saw-fix) | Clean findings onto a `security/auto-clean` branch | Branch only (never your working tree); no push unless `--pr` |
| [`saw discard`](#saw-discard) | Undo `saw fix`: delete the branch and/or close its PR | git / GitHub API |
| [`saw audit`](#saw-audit) | Local hygiene: credentials, editor, host artifacts, branch protection (`--verify` content-scans a suspect dir) | Read-only |
| [`saw db`](#saw-db) | Manage the offline advisory DB (malicious-package + CVE corpus) a scan consults | Cache only (`~/.cache/saw/advisories`) |
| [`saw search`](#saw-search) | Fuzzy "what's the command for…?" lookup | — |
| [`saw intro`](#saw-intro) | Branded tour (also the bare-`saw` welcome) | — |
| [`saw doctor`](#saw-doctor) | Self-check: install resolution + credentials | — |
| [`saw completion`](#saw-completion) | Print a shell-completion script | — |

```bash
# Everyday (local is always the default)
saw scan                          # scan local targets → full report to terminal, persists nothing
saw scan ./svc-a ./svc-b          # scan specific paths
saw scan; echo $?                 # CI gate: the exit code IS the verdict (0 clean / 1 infected)
saw fix .                         # prepare a clean branch for this repo; review the diff, then push
saw fix --pr                      # also push + open/update one rolling PR per repo
saw discard --branch              # delete the auto-clean branch (local + remote)
saw audit                         # local credential + editor hygiene

# Remote (GitHub) sweeps — see "Remote targeting"
saw scan --remote                 # your own GitHub repos (or configured targets)
saw scan --org UB-TechDEV         # a whole org (implies --remote)
saw scan --remote Ndevu12/strix   # one specific repo (owner/repo)
saw fix --remote                  # clone → fix → one rolling PR per repo
```

## Overview

- **`saw` is security-only by design.** It exposes the supply-chain worm hunter for local use.
- **The health (uptime) bot is not part of this CLI.** It runs remotely-only (a GitHub Actions
  `*/5` cron) via its own `stayawake-health-*` console scripts; those are unaffected by `saw`.
- **One scanner, two surfaces.** The same engine runs locally as `saw` and in CI as the
  published `strix` GitHub Action:

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

## Synopsis & global options

```text
saw <command> [options] [TARGETS...]
```

`saw` with no command prints the [welcome banner](#saw-intro) (a branded first-contact screen);
the full command list still lives at `saw -h`. Every command supports `-h/--help`, which documents
that command's options. These options apply to `saw` itself, before any command:

| Option | Description |
| --- | --- |
| `-h`, `--help` | Show help for `saw` or any command. |
| `--version` | Print the package version and a capability inventory (`security: local + CI; health: CI-only`). |

A few flags recur across commands but are **not** universal — they exist only where they mean
something:

| Option | Where | Description |
| --- | --- | --- |
| `--json` | `scan`, `doctor`, `search` | Emit machine-readable JSON to stdout. On `scan` it carries **full evidence**. |
| `-q`, `--quiet` | `doctor`, `search` | Print only the essentials (problems / command names). |
| `-f`, `--fail` | `audit` only | Exit non-zero on a warning-level issue. **`saw scan` has no `--fail`** — its exit code is the verdict unconditionally (see [Exit codes](#exit-codes)). |
| `--verify` | `audit` only | Content-scan a lone **weak** host artifact (e.g. `~/.node_modules`) to corroborate it — opt-in, bounded, CONFIRMED-only; **never touches `saw scan`**. See [`saw audit`](#saw-audit). |
| `--no-stream` | `scan`, `fix`, `discard`, `audit`, `db` | Disable the live progress/typewriter output — plain, instant lines. |

## Commands

### `saw scan`

Hunt for supply-chain worms across one or more repositories or directories. **Terminal-first:**
`scan` renders a full human report — with full match evidence — to `stdout` and **persists
nothing by default**. Progress goes to `stderr`, and the **exit code is the verdict,
unconditionally** (`0` clean / `1` infected) — there is no `--fail` flag; a CI gate just checks
the exit code.

`scan` is **read-only** — it never changes a file. Remediation lives in [`saw fix`](#saw-fix).
Durable output beyond the terminal is opt-in via "sinks": `--json`, `--sarif`, `--alert`, `-d`
(see [How reports are stored](#how-reports-are-stored-evidence--redaction)).

```text
saw scan [TARGETS...] [-r] [--user U] [--org O] [-c FILE] [-p PATH]
         [--json] [--sarif FILE] [--alert] [-d DIR] [--no-stream] [--pager]
         [--no-advisories] [-x | --external] [--require-db]
```

| Option | Description |
| --- | --- |
| `TARGETS...` | Local repo/dir paths — or, with `--remote`, `owner/repo` slugs. If omitted, scans configured targets or the current repository. |
| `-p`, `--path PATH` | Additional target (repeatable); same effect as a positional. |
| `-c`, `--config FILE` | Config file (default: `config/security.yml` when present). |
| `-r`, `--remote` | Scan GitHub repos instead of local. **Scope is local by default.** See [Remote targeting](#remote-targeting---remote). |
| `--user USER` | Scan this GitHub user's repos (repeatable; **implies `--remote`**). |
| `--org ORG` | Scan this GitHub org's repos (repeatable; **implies `--remote`**). |
| `--json` | Machine-readable JSON report to `stdout`, with **full evidence**. Ephemeral — pipe it; writes no file. |
| `--sarif FILE` | Write a SARIF 2.1.0 report to `FILE` for GitHub code-scanning upload. Evidence is **redacted** (fingerprint only). |
| `--alert` | Push the durable record **in this pass**: open/close a GitHub issue per infected repo and post a Slack summary. Reads `GITHUB_TOKEN`, `GITHUB_REPOSITORY`, `SLACK_WEBHOOK_URL` from the environment; bodies are **evidence-free**. |
| `-d`, `--reports-dir DIR` | **Opt-in:** also write `latest.json` + `latest.md` into `DIR`. Evidence is **redacted** (fingerprint only). |
| `--no-stream` | Disable the live progress/typewriter output. (Auto-off already when piped, in CI, or with `STAYAWAKE_NO_STREAM=1`.) |
| `--pager` | Page the report through `$PAGER` (default `less -R`). **Off by default** — the report prints straight through. |
| `--no-advisories` | Suppress the dependency **CVE-advisory** section. A scan reports malware **and** known CVEs (from the offline [advisory DB](#saw-db)) by default; advisories never change the verdict/exit code, so this only quiets the output. |
| `-x`, `--external` | **Opt-in — leaves the offline sandbox.** Also run *installed* external auditors (`osv-scanner`, …) and fold their vulns into the advisory tier. Spawns subprocesses and a tool may send your dependency list to its own servers; absent tools are skipped, and it never changes the verdict/exit code. |
| `--require-db` | Fail (**exit 2**) if the [advisory DB](#saw-db) is absent or fails its integrity check, instead of degrading to the inline malware seed — for CI gates that must not silently lose coverage. Default is **fail-open** (degrade to the seed). |

```bash
saw scan                                  # scan local targets; full report to terminal; writes nothing
saw scan ./service-a ./service-b          # scan specific local paths
saw scan --remote                         # scan your own GitHub repos (or configured targets)
saw scan --org UB-TechDEV                 # an org (implies --remote)
saw scan --remote Ndevu12/strix           # one specific GitHub repo
saw scan; echo $?                         # gate: exit code is the verdict (0 clean / 1 infected)
saw scan --json > report.json             # machine-readable, full evidence, to a pipe
saw scan --sarif scan.sarif               # redacted SARIF for GitHub code-scanning upload
saw scan --alert                          # open/close issues + Slack summary, in-pass
saw scan -d /tmp/sab-reports              # opt-in redacted latest.json + latest.md
```

> **Live progress.** On an interactive terminal, `scan` streams each target as it completes
> (`[3/9] [INFECTED] …`) with a spinner and a typewriter cadence, so a long sweep never looks
> frozen. It's purely cosmetic pacing of deterministic results, and **auto-disables** when piped,
> in CI, with `--no-stream`, or `STAYAWAKE_NO_STREAM=1` — so `--json` and any persisted artifact
> stay byte-for-byte unchanged. Progress → `stderr`; report → `stdout`.
>
> **Large fleets — nothing lost to scrollback.** Scanning many repos produces a report bigger
> than the terminal. Three things keep it readable and complete, **with no pager by default**
> (you're never dropped into `less`): (1) a big sweep keeps the terminal a bounded **dashboard**
> — the table only — and moves **per-finding evidence to the written report** (full Markdown +
> JSON in your `-d` dir or a temp dir, path printed as `Full report: …`), so the complete result
> is always recoverable off-terminal; (2) **clean rows collapse to a count** once the fleet is
> large; (3) `--pager` opts into scrolling the report in place through `$PAGER`.

### `saw fix`

Clean up detected worm findings on a branch. **By default `fix` PREPARES the fix on a local
`security/auto-clean` branch and stops** — no push, no PR, no network — leaving it for you to
review and push. It never edits your working tree (the fix lives on the branch), so it can't
corrupt code and makes zero surprise remote writes. `--pr` additionally **pushes** the branch
and opens/updates one rolling PR per repo (re-runs update it, never duplicate). `--remote`
sweeps GitHub targets (clone → fix → PR). Scope is **local by default**; each repo's outcome
**streams live**.

```text
saw fix [TARGETS...] [--pr] [-r] [--user U] [--org O] [-p PATH] [-c FILE] [--no-stream]
```

| Option | Description |
| --- | --- |
| `TARGETS...` | Local repo/dir paths — or, with `--remote`, `owner/repo` slugs. Omit to fix configured targets or the current repo. |
| `-p`, `--path PATH` | Additional target (repeatable). |
| `--pr`, `--open-pr` | Also **push** the branch and open/update one rolling, de-duplicated PR per repo. Needs a GitHub credential with repo + PR write scope; the API is **pre-flighted** before any push. |
| `-r`, `--remote` | Sweep GitHub repos (clone → fix → PR) instead of local. See [Remote targeting](#remote-targeting---remote). |
| `--user USER` / `--org ORG` | Fix this GitHub user's / org's repos (repeatable; **implies `--remote`**). |
| `-c`, `--config FILE` | Config file. **Optional** — defaults to `config/security.yml` when present, else the current repository. A missing *explicit* path is a clear error (exit `2`), never a crash. |
| `--no-stream` | Disable the live per-repo progress output. |

```bash
saw fix                       # prepare a security/auto-clean branch per local infected repo (no push)
saw fix .                     # prepare a branch for the current repo; review the diff, then push
saw fix --pr                  # also push + open/update one rolling PR per repo
saw fix --remote              # sweep the configured GitHub targets, one rolling PR each
```

> **How fixes are built — reliably, never by guessing.** An injected payload is **recovered from
> git** (the file's last clean committed version is restored — the real original, not a
> reconstruction), or, when that can't be proven safe (born-infected, untracked, or legit edits
> sit on the payload), it is **deferred to manual review** with the exact reason and command.
> Fonts/markers/VS-Code-autorun use reliable whole-file-quarantine / exact-line removal. The
> scanner **never surgically edits a source file**, so a fix can never corrupt valid code; and
> heuristic-only (`suspicious`) matches — e.g. an inlined base64 asset — are disclosed in the PR
> for review, never auto-touched. The fix lives on a branch; nothing lands until you merge.

### `saw discard`

The inverse of `saw fix`: remove what it produced. Only ever touches the auto-generated
`security/auto-clean` branch — never a real branch. **At least one of `--branch` / `--pr` is
required.** Scope is **local by default**; `--remote` sweeps GitHub targets.

```text
saw discard (--branch | --pr) [-r] [--user U] [--org O] [TARGETS...] [-c FILE] [--no-stream]
```

| Option | Description |
| --- | --- |
| `-br`, `--branch` | Delete the `security/auto-clean` branch **locally and on its remote** (pure git — works even when the GitHub API is unreachable; deleting the remote branch auto-closes its PR). |
| `--pr`, `--close-pr` | **Close** the open `security/auto-clean` PR via the API (leaves the branch). |
| `-r`, `--remote` / `--user` / `--org` | Sweep GitHub repos instead of local. See [Remote targeting](#remote-targeting---remote). `--user`/`--org` imply `--remote`. |
| `TARGETS...` / `-p` / `-c` / `--no-stream` | As for [`saw fix`](#saw-fix) (positionals are `owner/repo` slugs under `--remote`). |

```bash
saw discard --branch          # delete the auto-clean branch (local + remote) for each repo
saw discard --pr              # close the auto-clean PRs (keep the branches)
saw discard --branch --remote # delete the branch across the configured GitHub targets
```

### `saw audit`

Run a local security hygiene audit: credential exposure, editor (VS Code) settings, host
persistence / drop-artifacts, and — optionally — a repository's default-branch protection.

```text
saw audit [--repo OWNER/NAME] [-b BRANCH] [-f] [--verify]
```

| Option | Description |
| --- | --- |
| `--repo OWNER/NAME` | Also audit this repository's branch protection (needs a token). |
| `-b`, `--branch NAME` | Branch to check protection for (default: `main`). |
| `-f`, `--fail` | Exit `1` if any warning-level issue is found. (Also accepts `--fail-on-issues`.) |
| `--verify` | When the audit flags a lone **weak** host artifact (e.g. a `~/.node_modules` in `$HOME`), content-scan it to corroborate — it looks *inside* the directory (the everyday `node_modules`/`dist`/`build` excludes are turned off, so the tree is actually examined) and turns the weak indicator into a real verdict: CONFIRMED worm markers → a `warning`; fully scanned clean → a reassuring note; too large / unreadable → the same honest "verify it yourself." **Opt-in** (slower) and **bounded**; graded on CONFIRMED signatures only (a tree of minified libraries is not mistaken for malware). It calls the scan engine directly on that one directory and **never touches `saw scan`** — no repository discovery, no change to how `saw scan` finds or scans repos. |

```bash
saw audit                                       # local credential + editor + host hygiene
saw audit --repo Ndevu12/strix -f               # also gate on branch-protection issues
saw audit --verify                              # also content-scan a weak ~/.node_modules
```

### `saw db`

Manage the **offline advisory database** — the malicious-package + CVE corpus (OpenSSF, GitHub
Advisories, OSV.dev) that a scan's advisory tier consults to flag known-bad dependencies. It is
cached locally (default `~/.cache/saw/advisories`) and used fully offline; a `saw scan` degrades
gracefully when it is absent, unless you pass `saw scan --require-db` to make it mandatory. Two
subcommands:

#### `saw db update`

Download or refresh the corpus so later scans need no network.

```text
saw db update [-e ECO ...] [--cache-dir DIR] [--no-stream]
```

| Option | Description |
| --- | --- |
| `-e`, `--ecosystem ECO` | Limit to an ecosystem (repeatable); default: all supported. |
| `--cache-dir DIR` | Advisory cache location (default: `~/.cache/saw/advisories`). |
| `--no-stream` | Disable the per-ecosystem spinner / typewriter output (for logs & CI). |

#### `saw db status`

Report the cache's snapshot fingerprint, age, per-ecosystem counts, and integrity — and optionally
**gate** on freshness or a pinned snapshot. It exits non-zero on failure, so it drops straight into
CI.

```text
saw db status [--cache-dir DIR] [--require-snapshot DIGEST] [--max-age-days N]
```

| Option | Description |
| --- | --- |
| `--cache-dir DIR` | Advisory cache location. |
| `--require-snapshot DIGEST` | Exit non-zero unless the DB's snapshot equals `DIGEST` (pin for reproducible CI). |
| `--max-age-days N` | Exit non-zero if the DB is older than `N` days. Unknown age **fails closed** (treated as stale). |

```bash
saw db update                         # fetch/refresh the corpus (all ecosystems)
saw db update -e npm -e pypi          # just npm + PyPI
saw db status --max-age-days 30       # CI gate: fail if the corpus is stale (or missing)
saw scan --require-db                 # make a scan hard-require a healthy advisory DB
```

### `saw search`

Fuzzy "what's the command for…?" lookup over the whole command tree.

```text
saw search <text...> [--json] [-q]
```

| Option | Description |
| --- | --- |
| `<text...>` | One or more search terms (required). |
| `--json` | Machine-readable results. |
| `-q`, `--quiet` | Print only the matching command names. |

```bash
saw search "open a pr"     # → suggests `saw fix`
```

### `saw intro`

A branded first-contact screen. Running `saw` with **no command** prints the short **welcome**
(the "SAW" wordmark, tagline, a *Get started* block, and links) instead of the argparse help;
`saw intro` (alias `saw welcome`) prints the **fuller tour** — what saw is, the three verbs, why
it's safe, and how to gate CI. Both run no scan and touch nothing.

Because `saw` is a supply-chain tool, the welcome leans into a real property: **zero code runs at
install** — `pip install` has no post-install hook (the very vector saw hunts), so first contact is
your first *invocation*, not install time.

```text
saw intro          # or: saw welcome  ·  or just: saw
```

Colour degrades to the terminal's capability (truecolor → 256 → 16) and is **dropped entirely**
when output is piped/redirected, when `NO_COLOR` is set, under `CI`, or on a `TERM=dumb` terminal —
so scripted and CI output stays clean plain text. `CLICOLOR_FORCE=1` forces colour on (handy for
recording). The full command list is always at `saw -h`.

### `saw doctor`

Self-check: confirm that `saw` resolves to this installation, report whether a usable GitHub /
Slack credential is present, and note that the health entry points (`stayawake-health-*`) are
installed even though they are not `saw` subcommands.

```text
saw doctor [--json] [-q]
```

| Option | Description |
| --- | --- |
| `--json` | Machine-readable output. |
| `-q`, `--quiet` | Print only problems. |

### `saw completion`

Print a shell-completion script for your shell. See
[Command aliases & shell completion](#command-aliases--shell-completion).

```text
saw completion {bash,zsh,fish}
```

## Remote targeting (`--remote`)

`--remote` switches `scan`, `fix`, and `discard` from your local disk to GitHub repositories.
**Scope is local by default** — you always opt in. `--user`/`--org` imply `--remote`, and under
`--remote` a positional is an `owner/repo` slug (a non-`owner/repo` positional is a **hard
error**, never silently treated as a path).

Targets resolve by this ladder — **first match wins**:

1. **ad-hoc selectors** — `--user` / `--org` and `owner/repo` positionals (these **override**
   config);
2. **configured** `targets.github.users` / `orgs`;
3. **your own repos** — the authenticated user's *owned* repos (private-inclusive, via
   `/user/repos`), or a GitHub App installation's repos.

```bash
saw scan --remote                 # ladder rung 2/3: configured targets, else your own repos
saw scan --org UB-TechDEV         # rung 1: an org (implies --remote)
saw fix --remote Ndevu12/strix    # rung 1: one specific repo
```

## How reports are stored (evidence & redaction)

**A report is a message, not a file.** The full report — including full match evidence — only
ever appears on the live terminal (`stdout`) or via `--json`. Any **persisted** artifact
(`--sarif`, `-d`) stores a redacted fingerprint `{sha256, preview (first 24 chars), len}` in
place of the raw payload, so a security report on disk can never re-distribute a live malware
payload.

Durable records live **outside the repo tree** — GitHub code-scanning (SARIF, uploaded not
committed), GitHub issues + Slack (`--alert`), and CI artifacts. Security reports are **no longer
committed** into the repo.

| Sink | Flag | Evidence | Destination |
| --- | --- | --- | --- |
| Terminal | (default) | **Full** | `stdout` (ephemeral) |
| JSON | `--json` | **Full** | `stdout` (pipe it; no file) |
| SARIF | `--sarif FILE` | Redacted | `FILE`, for GitHub code-scanning |
| Alert | `--alert` | Evidence-free | GitHub issue + Slack |
| Reports dir | `-d DIR` | Redacted | `DIR/latest.{json,md}` |

## Exit codes

`saw` is quiet-friendly and scriptable — the exit code is the contract. For **`saw scan` the exit
code is the verdict, unconditionally** — a CI gate just checks it, no flag required:

| Code | Meaning |
| --- | --- |
| `0` | Clean. For `saw scan`, no scanned target is infected. For `saw audit`, no warning-level issue (or issues found without `-f`). |
| `1` | For `saw scan`, at least one target is **infected** — returned unconditionally (there is no `--fail`). For `saw audit`, a warning-level issue was found **and** `-f/--fail` was set. |
| `2` | Usage error (unknown command, bad option, or a missing explicit `--config` path), **or** a scan that could not complete — a malformed config (e.g. an `allowlist` that isn't a list of mappings) or a target that errored during scanning. `saw scan` fails **closed** here: a target it could not scan is never reported as clean. |

## Command aliases & shell completion

Two independent shortcuts help you type less.

**Built-in command aliases** (accepted anywhere the full verb is):

| Command | Aliases |
| --- | --- |
| `scan` | `s`, `sc` |
| `audit` | `au` |
| `search` | `se` |
| `doctor` | `d`, `doc` |
| `completion` | `comp` |
| `fix`, `discard` | *(none — always spelled out)* |

**Shell completion.** Because the short verbs are easiest to use with `<Tab>`, install completion
once:

```bash
# bash
saw completion bash > /etc/bash_completion.d/saw       # or source it from your ~/.bashrc

# zsh
saw completion zsh  > "${fpath[1]}/_saw"

# fish
saw completion fish > ~/.config/fish/completions/saw.fish
```

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
| `stayawake-security-remediate --apply --open-pr` | `saw fix --pr` |
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
  directly; the gate is `saw scan`'s **exit code**, and durable records are pushed via `--alert`,
  `--sarif` (uploaded to code-scanning), and CI artifacts rather than committed files.
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
| Remediate + PR | `stayawake-security-remediate --apply --open-pr` | `saw fix --pr` | −74% |
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
