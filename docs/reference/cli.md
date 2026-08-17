# `saw` command reference

Every `saw` flag is documented here, and only here — the guides link to this page rather than
repeating it. `saw -h` and `saw <command> -h` print the same surface.

```text
saw <command> [options] [TARGETS...]
```

Bare `saw` prints the welcome screen; `saw -h` lists the commands. `stayawake` is an identical long
alias, for scripts where a three-letter name might clash on `PATH`.

| Command | What it does | Writes? |
| --- | --- | --- |
| [`scan`](#saw-scan) | Hunt for supply-chain worms and report | read-only |
| [`fix`](#saw-fix) | Prepare the cleanup on a `security/auto-clean` branch | that branch only; pushes with `--pr` |
| [`discard`](#saw-discard) | Undo `saw fix` | git / GitHub API |
| [`audit`](#saw-audit) | Machine hygiene, start-up surface, branch protection | read-only |
| [`guard`](#saw-guard) | Install and verify the Strix CI gate | `check`/`drift` read-only; `setup` writes a workflow or a PR |
| [`hook`](#saw-hook) | Scan what a clone or pull just brought in | your global git config |
| [`auth`](#saw-auth) | Credential and capability status; register a GitHub App | local config |
| [`db`](#saw-db) | Manage the offline advisory database | its cache only |
| [`search`](#saw-search) | Find the command you want | — |
| [`intro`](#saw-intro) | Tour (also the bare-`saw` welcome) | — |
| [`doctor`](#saw-doctor) | Self-check: install, credential, capabilities | — |
| [`completion`](#saw-completion) | Print a shell-completion script | — |

## Global options

| Option | Description |
| --- | --- |
| `-h`, `--help` | Help for `saw` or for any command. |
| `--version` | Package version and capability inventory. |

## Flags shared by several commands

| Option | Where | Description |
| --- | --- | --- |
| `--json` | `scan`, `auth status`, `doctor`, `search` | Machine-readable output on stdout. |
| `-q`, `--quiet` | `doctor`, `search` | Only the essentials. |
| `-f`, `--fail` | `audit`, `guard check` | Exit non-zero on a warning-level issue. **`saw scan` has no `--fail`** — its exit code is the verdict unconditionally. |
| `--no-stream` | `scan`, `fix`, `discard`, `audit`, `guard`, `auth`, `db` | Plain instant lines instead of live progress. |
| `-j`, `--jobs N` | `scan`, `fix`, `guard check`/`setup`/`drift` | Work on up to N repositories at once. Default `auto` (one repo sequential, several use one worker per core); `-j 1` forces sequential. On `scan` it also splits one large repository across workers. |

## `saw scan`

Hunt for supply-chain worms across repositories or directories. The full report — with full match
evidence — renders to stdout and **nothing is persisted** unless you ask for a sink; progress goes to
stderr; the [exit code is the verdict](exit-codes.md). `scan` never changes a file.

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
| `-r`, `--remote` | Scan GitHub repositories instead of local paths. See [Remote targeting](#remote-targeting). |
| `--user USER` / `--org ORG` | Scan this GitHub user's / organisation's repositories (repeatable; each implies `--remote`). |
| `--json` | JSON report to stdout, with full evidence. Pipe it; it writes no file. |
| `--sarif FILE` | SARIF 2.1.0 report for GitHub code scanning. Evidence [redacted](#report-sinks). |
| `--alert` | In this pass, open/close a GitHub issue per infected repository and post a Slack summary. Bodies are evidence-free. |
| `-d`, `--reports-dir DIR` | Also write `latest.json` + `latest.md` into `DIR`. Evidence redacted. |
| `-j`, `--jobs N` | Scan concurrently; see [shared flags](#flags-shared-by-several-commands). A persisted report is byte-identical to a sequential run, and a worker that dies is an error, not a pass. |
| `--no-stream` | Disable live progress. (Already off when piped, in CI, or with `STAYAWAKE_NO_STREAM=1`.) |
| `--pager` | Page the report through `$PAGER` (default `less -R`). Off by default. |
| `--no-advisories` | Omit the dependency CVE section. Advisories never change the verdict or exit code, so this only quiets the output. |
| `-x`, `--external` | **Opt-in; the only flag that leaves the offline sandbox.** Also runs *installed* external auditors (`osv-scanner`, …) and folds their vulnerabilities into the advisory tier — such a tool may send your dependency list to its own servers. Absent tools are skipped; the verdict never changes. |
| `--deep` | **Opt-in:** also examine the installed npm dependency tree itself. Reading every dependency file adds roughly 10–60s on a large `node_modules`; the run stays offline and deterministic. |
| `--require-db` | Exit `2` when the [advisory database](advisory-db.md) is absent or fails its integrity check, instead of continuing without it — for CI that must not lose advisory coverage silently. |

```bash
saw scan                                  # the repository you are standing in
saw scan ./service-a ./service-b          # specific paths
saw scan --org UB-TechDEV -j 8            # a whole org, 8 repositories at a time
saw scan --json > report.json             # machine-readable, full evidence
saw scan -d /tmp/saw-reports              # opt-in redacted latest.json + latest.md
```

On a terminal, a long sweep streams each target as it completes. A large sweep keeps the terminal to
a bounded dashboard and moves per-finding evidence into the written report, whose path is printed on
stderr — nothing is lost to scrollback, and you are never dropped into a pager.

## `saw fix`

Clean detected findings **on a branch**. By default `fix` prepares `security/auto-clean` locally and
stops — no push, no PR, no network — for you to review. It never edits your working tree. `--pr`
pushes and opens or updates one rolling PR per repository. See [the safety
envelope](../explanation/safety-envelope.md) for what `fix` will and will not touch.

```text
saw fix [TARGETS...] [--pr] [-r] [--user U] [--org O] [-p PATH] [-c FILE] [-j N] [--no-stream]
```

| Option | Description |
| --- | --- |
| `TARGETS...` / `-p` / `-c` / `-r` / `--user` / `--org` / `-j` / `--no-stream` | As for [`saw scan`](#saw-scan). A missing *explicit* `--config` path is a clear error (exit `2`), never a crash. |
| `--pr`, `--open-pr` | Also push the branch and open/update one rolling, de-duplicated PR per repository. Needs a credential with repo + PR write; the API is pre-flighted before any push. |

## `saw discard`

The inverse of `saw fix`: remove what it produced. It only ever touches the generated
`security/auto-clean` branch. **At least one of `--branch` / `--pr` is required.**

```text
saw discard (--branch | --pr) [-r] [--user U] [--org O] [TARGETS...] [-c FILE] [--no-stream]
```

| Option | Description |
| --- | --- |
| `-br`, `--branch` | Delete the branch locally and on its remote (pure git; deleting the remote branch closes its PR). |
| `--pr`, `--close-pr` | Close the open `security/auto-clean` PR, leaving the branch. |
| `TARGETS...` / `-p` / `-c` / `-r` / `--user` / `--org` / `--no-stream` | As for [`saw fix`](#saw-fix). |

## `saw audit`

Audit the machine: credential exposure, editor settings, the start-up surface, and optionally a
repository's branch protection. Every run ends with a **rotation-safety verdict**, and `saw audit`
exits `3` when rotating from this host would be unsafe — see [audit a
machine](../how-to/audit-a-machine.md) for what to do with each outcome, and [exit
codes](exit-codes.md) for the contract. Scope: [what `saw audit` does not
scan](../CLI.md#what-saw-audit-does-not-scan).

```text
saw audit [--repo OWNER/NAME] [-b BRANCH] [-f] [--verify] [--no-stream]
```

| Option | Description |
| --- | --- |
| `--repo OWNER/NAME` | Also audit that repository's branch protection (needs a token). |
| `-b`, `--branch NAME` | Branch whose protection is checked (default: `main`). |
| `-f`, `--fail` | Exit `1` on a weaker warning-level hygiene issue. The rotation-safety axis gates unconditionally, independent of this flag. |
| `--verify` | **Opt-in:** content-scan a suspicious directory the audit flagged outside a repository (for example a `~/.node_modules`) and report what it found — worm markers, scanned clean, or an honest "too large / unreadable, verify it yourself". It examines that one directory and never changes how `saw scan` behaves. |

## `saw guard`

Install and verify the **Strix worm-guard CI gate**: `scan` finds worms, `fix` cleans them, `guard`
stops an infected change from merging in the first place. A gate is recognised by its action
reference, not by the workflow's filename or job name, so renaming the file is safe. All three
subcommands sweep repositories exactly like [`saw scan`](#saw-scan) — local by default,
`--remote`/`--user`/`--org` for GitHub.

### `saw guard check`

Read-only. For each repository: is a worm gate present, is the Strix pin a SHA rather than a tag, is
it behind the latest release, and — for a remote repository — does branch protection actually
**require** its check. A gate that is not required is decoration.

```text
saw guard check [TARGETS...] [-p PATH] [-c FILE] [-r] [--user U] [--org O]
                [--repo OWNER/NAME] [-b BRANCH] [-f] [-j N] [--no-stream]
```

| Option | Description |
| --- | --- |
| `TARGETS...` / `-p` / `-c` / `-r` / `--user` / `--org` / `-j` / `--no-stream` | As for [`saw scan`](#saw-scan). |
| `--repo OWNER/NAME` | Shorthand for a single remote repository. |
| `-b`, `--branch` | Branch whose protection must require the gate (default: `main`). |
| `-f`, `--fail` | Exit `1` when any repository's gate is absent, unpinned, stale, or not required. |

### `saw guard setup`

Install the gate, or surgically bump an existing pin, across the resolved repositories. It resolves
the latest Strix release to a commit SHA and writes a workflow with two least-privilege jobs — the
gate itself, and a weekly `pin-drift` job that runs [`saw guard drift`](#saw-guard-drift). When a
gate already exists it rewrites only that `uses:` reference and leaves the rest of the file
untouched. It is idempotent, fails closed if the SHA cannot be resolved, and **never pushes to a
default branch**. See [gate CI](../how-to/gate-ci.md).

```text
saw guard setup [TARGETS...] [-p PATH] [-c FILE] [--pr] [-r] [--user U] [--org O]
                [--ref SHA|TAG] [-b BRANCH] [--dry-run] [-j N] [--no-stream]
```

| Option | Description |
| --- | --- |
| `TARGETS...` / `-p` / `-c` / `-r` / `--user` / `--org` / `-j` / `--no-stream` | As for [`saw scan`](#saw-scan). |
| `--pr`, `--open-pr` | Open/update a rolling `security/guard-setup` PR per repository instead of writing into the working tree. `--remote` always opens a PR. Needs a token with the `workflow` permission. |
| `--ref SHA\|TAG` | Pin this Strix ref explicitly instead of resolving the latest release — offline and deterministic. A tag is resolved to its immutable SHA. |
| `-b`, `--branch` | Default branch to target (default: auto-detect). |
| `--dry-run` | Print what would be written; write nothing. |

### `saw guard drift`

Keeps each repository gated and current by maintaining one de-duplicated, self-closing tracking
issue: it opens the issue when a repository has no gate or its pin has fallen behind, and closes it
once the repository is protected and current. It reports as an issue and never fails a build (exit
`0`), so it is safe on a schedule.

```text
saw guard drift [TARGETS...] [-p PATH] [-c FILE] [-r] [--user U] [--org O] [--repo OWNER/NAME]
                [-j N] [--no-stream]
```

Target selection is identical to [`saw guard check`](#saw-guard-check).

## `saw hook`

**Scan on clone.** Installs global git hooks so a fresh clone, a pull, a branch switch or a rebase
scans what just landed and warns you *before* you run `npm install`, a build, or an editor auto-run
task. It uses git's `init.templateDir` rather than a global `core.hooksPath`, so existing
repositories are untouched, a repository's own hooks still run, and nothing is hijacked. The hook
warns and points at [`saw fix`](#saw-fix); it never modifies anything and can never break a git
command. See [scan on clone](../how-to/scan-on-clone.md).

```text
saw hook install [-c FILE]
saw hook uninstall
saw hook status
```

| Option / subcommand | Description |
| --- | --- |
| `install` | Point git's global `init.templateDir` at saw's template, so repositories cloned or created from now on get the hooks. |
| `uninstall` | Reverse it, restoring any hook it had to preserve. |
| `status` | Whether it is active, the template directory, and the scan cache. |
| `-c`, `--config FILE` | Operator config whose allowlist clones are scanned against, baked into the hook. The hook never reads a cloned repository's own config. |

A pull or switch scans only what changed, so it is near-instant, and each scan runs under a
wall-clock budget (`SAW_HOOK_TIMEOUT`, default 60s) so a huge clone can never hang git; a scan that
times out reports the tree as unverified, never clean. `git reset --hard` fires no git hook, so scan
that case yourself with [`saw scan`](#saw-scan).

## `saw auth`

Credential and capability status, and registration of an operator-managed StayAwakeBot GitHub App.
Most of `saw` is offline; `auth` is only about the credential used for the network paths — remote
scanning, `saw fix --pr`, and `saw guard setup --pr`. Bare `saw auth` is `saw auth status`.

```text
saw auth status [--json] [--no-stream]
saw auth app register [--name NAME] [--no-browser] [--replace] [--no-stream]
saw auth app show [--no-stream]
```

| Option / subcommand | Description |
| --- | --- |
| `status` | The active credential (source, actor, whether it is live), its scopes, whether an App is configured, and per-intent gating: for each key action, whether this credential is allowed and, if not, the command that fixes it. Exits non-zero when a live credential could not open a guard PR, so it drops straight into CI. |
| `app register` | Register and install an App through GitHub's browser manifest flow, storing the credentials locally (mode `0600`). Idempotent: with an App already configured it points you at installing that same App elsewhere. |
| `app show` | Whether a local App config is present, with its install and settings URLs. |
| `--name NAME` | App display name (default: `StayAwakeBot`). |
| `--no-browser` | Print the manifest URL instead of opening a browser. |
| `--replace` | Register a brand-new App even if one is configured. |

## `saw db`

Manage the [offline advisory database](advisory-db.md).

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

## `saw search`

```text
saw search <text...> [--json] [-q]
```

Fuzzy lookup over the whole command tree — `saw search "open a pr"` suggests `saw fix`. `-q` prints
only the matching command names.

## `saw intro`

```text
saw intro          # or: saw welcome  ·  or just: saw
```

Bare `saw` prints the short welcome; `saw intro` prints the fuller tour. Both run no scan and touch
nothing. Colour degrades to the terminal's capability and is dropped entirely when output is piped or
redirected, when `NO_COLOR` is set, under CI, or on a `TERM=dumb` terminal; `CLICOLOR_FORCE=1` forces
it on.

## `saw doctor`

```text
saw doctor [--json] [-q]
```

Confirms `saw` resolves to this installation, reports the active credential and whether it can open
fix and guard PRs, and confirms the health entry points are installed. `saw auth status` carries the
full capability matrix. `-q` prints only problems.

## `saw completion`

```text
saw completion {bash,zsh,fish}
```

```bash
saw completion bash > /etc/bash_completion.d/saw     # or source it from ~/.bashrc
saw completion zsh  > "${fpath[1]}/_saw"
saw completion fish > ~/.config/fish/completions/saw.fish
```

Command aliases, accepted anywhere the full verb is: `scan` → `s`, `sc`; `audit` → `au`;
`guard` → `gd`; `search` → `se`; `intro` → `welcome`; `doctor` → `d`, `doc`; `completion` → `comp`.
`fix` and `discard` are always spelled out.

## Remote targeting

`--remote` switches `scan`, `fix`, `discard` and `guard` from local disk to GitHub repositories.
**Scope is local by default and one scope per run** — you always opt in. `--user`/`--org` imply
`--remote`, and under `--remote` a positional must be an `owner/repo` slug; anything else is a hard
error rather than a silently-treated path.

Targets resolve by this ladder, first match wins:

1. **ad-hoc selectors** — `--user` / `--org` and `owner/repo` positionals (these override config);
2. **configured** `targets.github.users` / `orgs`;
3. **your own repositories** — the authenticated user's owned repositories (private included), or a
   GitHub App installation's repositories.

## Report sinks

A report is a message, not a file. Full evidence exists only on the live terminal or via `--json`;
any artifact written to disk stores a `{sha256, preview, len}` fingerprint in place of the raw match,
so a report on disk can never re-distribute a live payload.

| Sink | Flag | Evidence | Destination |
| --- | --- | --- | --- |
| Terminal | (default) | full | stdout, ephemeral |
| JSON | `--json` | full | stdout — pipe it; no file |
| SARIF | `--sarif FILE` | redacted | `FILE`, for GitHub code scanning |
| Alert | `--alert` | evidence-free | GitHub issue + Slack |
| Reports dir | `-d DIR` | redacted | `DIR/latest.{json,md}` |

## Credentials

Local scanning needs **no credential**. A GitHub token is only used to clone private repositories and
to write — open PRs or issues, read branch protection. However it is supplied, the token reaches git
through `GIT_ASKPASS`, never through a URL or process arguments, so it cannot leak via `ps`, git's
error output, or CI logs.

You configure only `GH_SECURITY_TOKEN`. When a token is needed, `saw` resolves one in this order:

1. **`GH_SECURITY_TOKEN`** — the one you set up. The only credential that can reach *other*
   repositories, so the one an org-wide sweep needs.
2. **`GITHUB_TOKEN`** — minted automatically for every GitHub Actions run; the zero-config fallback
   for same-repo work in CI. It cannot reach other repositories.
3. A **GitHub App** installation token — minted on demand, scoped to what the App was granted, and
   rotated hourly. Preferred for continuous or org-wide use; signing is built in, so App auth needs
   no extra install. Apps install on a personal account as well as an organisation, and the
   installation itself defines which repositories are in scope.
4. Your **GitHub CLI** session (`gh auth token`) — short-lived and never stored by `saw`.

Point `saw` at an existing App with `GH_APP_ID` and `GH_APP_PRIVATE_KEY` (or
`GH_APP_PRIVATE_KEY_PATH`), plus `GH_APP_INSTALLATION_ID` when the App has more than one
installation. An explicit `GH_SECURITY_TOKEN` still wins, for a one-off human override.

### Least privilege per command

Fine-grained permission first; the classic scope in parentheses.

| Command | Needs a token? | Permission (classic) |
| --- | --- | --- |
| `saw scan <path>`, public remotes | no | — |
| `saw scan --remote` (private) | read | Contents + Metadata: Read (`repo`) |
| `saw fix`, `saw fix --remote` | write | Contents + Pull requests: R/W (`repo`) |
| ↳ fork fallback | fork + PR | Pull requests: R/W on your fork (`public_repo` / `repo`) |
| ↳ patch / issue fallback | none / issues | Issues: R/W (`repo` / `public_repo`); a patch needs nothing |
| `saw guard setup --pr` / `--user` / `--org` | write + **workflows** | Contents + Pull requests + **Workflows**: R/W (`repo` + **`workflow`**) |
| `saw scan --alert` | write | Issues: R/W (`repo` / `public_repo`) |
| `saw audit --repo` | read | Administration: Read (`repo`) |

Missing the `workflow` permission is **not** "no write access" — GitHub rejects pushes that touch
`.github/workflows/*` without it. Fix it with `gh auth refresh -h github.com -s repo,workflow`, or
use `saw auth app register`.

## Environment variables

| Variable | Effect |
| --- | --- |
| `GH_SECURITY_TOKEN`, `GITHUB_TOKEN`, `GH_APP_*` | Credentials — see [above](#credentials). |
| `SLACK_WEBHOOK_URL`, `GITHUB_REPOSITORY` | Where `--alert` posts. |
| `STAYAWAKE_REPORTS_DIR` | Default reports directory; `-d` overrides it. |
| `STAYAWAKE_NO_STREAM=1` | As `--no-stream`. |
| `SAW_HOOK_DISABLED=1` | Skip the clone/pull hook for one command. |
| `SAW_HOOK_TIMEOUT` | Wall-clock budget for a hook scan (default 60s). |
| `NO_COLOR`, `CLICOLOR_FORCE` | Force colour off / on. |

## Migrating from the legacy scripts

The `stayawake-security-*` console scripts have been removed; `saw` is the only local security
surface. The `stayawake-health-*` scripts are unchanged.

| Legacy command (removed) | `saw` equivalent |
| --- | --- |
| `stayawake-security-scan` | `saw scan` (the exit code **is** the verdict — no flag) |
| `stayawake-security-report` | `saw scan` (the report renders to the terminal) |
| `stayawake-security-alert` | `saw scan --alert` |
| `stayawake-security-remediate [--apply --open-pr\|--remote]` | `saw fix [--pr\|--remote]` |
| `stayawake-security-audit --repo OWNER/NAME --fail-on-issues` | `saw audit --repo OWNER/NAME -f` |
