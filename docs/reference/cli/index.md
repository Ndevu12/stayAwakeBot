---
description: Every saw command and flag, documented once: scan, fix, discard, audit, guard, hook, auth, db, search, intro, doctor and completion.
---

# `saw` command reference

Every `saw` flag is documented here, and only here — the guides link to these pages rather than
repeating them. `saw <command> -h` states what that command is for, lists its flags, and ends
with a short `examples:` block — the same invocations used here, so the terminal and this page
agree.

```text
saw <command> [options] [TARGETS...]
```

Bare `saw` prints the welcome screen; `saw -h` lists the commands. `stayawake` is an identical long
alias, for scripts where a three-letter name might clash on `PATH`.

| Command | What it does | Writes? |
| --- | --- | --- |
| [`scan`](scan.md) | Hunt for supply-chain worms and report | read-only |
| [`fix`](fix.md) | Prepare the cleanup on a `security/auto-clean` branch | that branch only; pushes with `--pr` |
| [`discard`](discard.md) | Undo `saw fix` | git / GitHub API |
| [`audit`](audit.md) | Machine hygiene, start-up surface, branch protection | read-only |
| [`guard`](guard.md) | Install and verify the Strix CI gate | `check`/`drift` read-only; `setup` writes a workflow or a PR |
| [`hook`](hook.md) | Scan what a clone or pull just brought in | your global git config |
| [`auth`](auth.md) | Credential and capability status; register a GitHub App | local config |
| [`db`](db.md) | Manage the offline advisory database | its cache only |
| [`search`](search.md) | Find the command you want | — |
| [`intro`](intro.md) | Tour (also the bare-`saw` welcome) | — |
| [`doctor`](doctor.md) | Self-check: install, credential, capabilities | — |
| [`completion`](completion.md) | Print a shell-completion script | — |

Three sections apply across commands: [remote targeting](remote.md), [report sinks](sinks.md) and
[credentials](credentials.md). Coming from the removed console scripts? See
[migrating](migrating.md).

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

## Command aliases

Accepted anywhere the full verb is: `scan` → `s`, `sc`; `audit` → `au`;
`guard` → `gd`; `search` → `se`; `intro` → `welcome`; `doctor` → `d`, `doc`; `completion` → `comp`.
`fix` and `discard` are always spelled out.

## Environment variables

| Variable | Effect |
| --- | --- |
| `GH_SECURITY_TOKEN`, `GITHUB_TOKEN`, `GH_APP_*` | Credentials — see [credentials](credentials.md). |
| `SLACK_WEBHOOK_URL`, `GITHUB_REPOSITORY` | Where `--alert` posts. |
| `STAYAWAKE_REPORTS_DIR` | Default reports directory; `-d` overrides it. |
| `STAYAWAKE_NO_STREAM=1` | As `--no-stream`. |
| `SAW_HOOK_DISABLED=1` | Skip the clone/pull hook for one command. |
| `SAW_HOOK_TIMEOUT` | Wall-clock budget for a hook scan (default 60s). |
| `NO_COLOR`, `CLICOLOR_FORCE` | Force colour off / on. |
