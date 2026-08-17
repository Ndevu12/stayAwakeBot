# `saw guard`

Install and verify the **Strix worm-guard CI gate**: `scan` finds worms, `fix` cleans them, `guard`
stops an infected change from merging in the first place. A gate is recognised by its action
reference, not by the workflow's filename or job name, so renaming the file is safe. All three
subcommands sweep repositories exactly like [`saw scan`](scan.md) — local by default,
`--remote`/`--user`/`--org` for GitHub.

## `saw guard check`

Read-only. For each repository: is a worm gate present, is the Strix pin a SHA rather than a tag, is
it behind the latest release, and — for a remote repository — does branch protection actually
**require** its check. A gate that is not required is decoration.

```text
saw guard check [TARGETS...] [-p PATH] [-c FILE] [-r] [--user U] [--org O]
                [--repo OWNER/NAME] [-b BRANCH] [-f] [-j N] [--no-stream]
```

| Option | Description |
| --- | --- |
| `TARGETS...` / `-p` / `-c` / `-r` / `--user` / `--org` / `-j` / `--no-stream` | As for [`saw scan`](scan.md). |
| `--repo OWNER/NAME` | Shorthand for a single remote repository. |
| `-b`, `--branch` | Branch whose protection must require the gate (default: `main`). |
| `-f`, `--fail` | Exit `1` when any repository's gate is absent, unpinned, stale, or not required. |

## `saw guard setup`

Install the gate, or surgically bump an existing pin, across the resolved repositories. It resolves
the latest Strix release to a commit SHA and writes a workflow with two least-privilege jobs — the
gate itself, and a weekly `pin-drift` job that runs [`saw guard drift`](#saw-guard-drift). When a
gate already exists it rewrites only that `uses:` reference and leaves the rest of the file
untouched. It is idempotent, fails closed if the SHA cannot be resolved, and **never pushes to a
default branch**. See [gate CI](../../how-to/gate-ci.md).

```text
saw guard setup [TARGETS...] [-p PATH] [-c FILE] [--pr] [-r] [--user U] [--org O]
                [--ref SHA|TAG] [-b BRANCH] [--dry-run] [-j N] [--no-stream]
```

| Option | Description |
| --- | --- |
| `TARGETS...` / `-p` / `-c` / `-r` / `--user` / `--org` / `-j` / `--no-stream` | As for [`saw scan`](scan.md). |
| `--pr`, `--open-pr` | Open/update a rolling `security/guard-setup` PR per repository instead of writing into the working tree. `--remote` always opens a PR. Needs a token with the `workflow` permission. |
| `--ref SHA\|TAG` | Pin this Strix ref explicitly instead of resolving the latest release — offline and deterministic. A tag is resolved to its immutable SHA. |
| `-b`, `--branch` | Default branch to target (default: auto-detect). |
| `--dry-run` | Print what would be written; write nothing. |

## `saw guard drift`

Keeps each repository gated and current by maintaining one de-duplicated, self-closing tracking
issue: it opens the issue when a repository has no gate or its pin has fallen behind, and closes it
once the repository is protected and current. It reports as an issue and never fails a build (exit
`0`), so it is safe on a schedule.

```text
saw guard drift [TARGETS...] [-p PATH] [-c FILE] [-r] [--user U] [--org O] [--repo OWNER/NAME]
                [-j N] [--no-stream]
```

Target selection is identical to [`saw guard check`](#saw-guard-check).
