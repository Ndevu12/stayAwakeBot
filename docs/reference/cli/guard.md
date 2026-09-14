---
description: saw guard — install, verify and keep current the worm-guard CI gate across one repository or a fleet. Full option reference.
---

# `saw guard`

Install and verify the **Strix worm-guard CI gate**: `scan` finds worms, `fix` cleans them, `guard`
stops an infected change from merging in the first place. A gate is recognised by its action
reference, not by the workflow's filename or job name, so renaming the file is safe. All three
subcommands sweep repositories exactly like [`saw scan`](scan.md) — local by default,
`--remote`/`--user`/`--org` for GitHub.

## `saw guard check`

Read-only. For each repository: is a worm gate present, is the Strix pin a SHA rather than a tag, is
it behind the latest release, is it configured so a finding reaches someone and so the scanning job
holds no write access it does not need, and — for a remote repository — does branch protection
actually **require** its check. A gate that is not required is decoration.

A gate reports when it comments, raises an alert, or keeps the evidence. One that does none of those
still reports through a red **required** check — so `check` condemns it only once it knows the check
is not required, or that the gate fails no merge at all, and otherwise says plainly that it could not
establish the answer. It does the same for a setting the workflow resolves at run time, and for a job
that grants itself no permissions and so takes whatever the repository hands every workflow: those are
reported as unknown, never as clean.

Where a repository references the action more than once, `check` answers for an occurrence that can
actually run on a change — its workflow triggers on a pull request or a push, its job waits on no
other job, and its job is not switched off — and among those it reports the **worst**-configured one,
so a decorative gate cannot answer for a live one.

```text
saw guard check [TARGETS...] [-p PATH] [-c FILE] [-r] [--user U] [--org O]
                [--repo OWNER/NAME] [-b BRANCH] [-f] [-j N] [--no-stream]
```

| Option | Description |
| --- | --- |
| `TARGETS...` / `-p` / `-c` / `-r` / `--user` / `--org` / `-j` / `--no-stream` | As for [`saw scan`](scan.md). |
| `--repo OWNER/NAME` | Shorthand for a single remote repository. |
| `-b`, `--branch` | Branch whose protection must require the gate (default: `main`). |
| `-f`, `--fail` | Fail the run when any repository's gate is absent, unpinned, stale, or not required. |

## `saw guard setup`

Install the gate, or surgically bump an existing pin, across the resolved repositories. It resolves
the latest Strix release to a commit SHA and the latest scanner release to a version, then writes the
workflow described below. When a gate already exists it rewrites only that `uses:` reference and
leaves the rest of the file untouched — unless the gate is configured so it cannot report what it
finds, which is repaired. It is idempotent, fails closed if either release cannot be resolved, and
**never pushes to a default branch**. See [gate CI](../../how-to/gate-ci.md).

### What the installed workflow contains

The generated file carries no commentary of its own — this is where it is described. Three jobs,
each holding only what it needs:

| Job | Runs on | Permissions | What it does |
| --- | --- | --- | --- |
| `worm-guard` | every pull request and push to the default branch | `contents: read`, `pull-requests: write`, `security-events: write` | Scans, and reports what it finds: a comment on the pull request, an alert in the Security tab, and the evidence as a run artifact. It **cannot push code to your repository** — it comments and raises alerts, nothing more. |
| `remediate` | only once `worm-guard` has reported an infected verdict | `contents: write`, `pull-requests: write` | Opens one rolling `security/auto-clean` pull request with the payload removed. This is the only job that can push, and on a clean run it never starts. |
| `pin-drift` | weekly, and on demand | `contents: read`, `issues: write` | Files one self-closing issue when the pinned Strix release falls behind. |

The gate stays **red until the fix pull request is merged**: remediation opens the fix, it does not
make the check pass.

Every `uses:` is pinned to a commit SHA, and the scanner itself is pinned to a released version — a
pinned action whose first act is an unpinned install would fetch whatever is newest at run time.

**Two settings a workflow file cannot set for you.** Enable *Settings → Actions → General → "Allow
GitHub Actions to create and approve pull requests"*, or the fix pull request cannot be opened. And
add a `GH_SECURITY_TOKEN` repository secret — a token with repository and pull-request scope — so the
fix pull request is itself scanned; one opened with the built-in token does not re-trigger the gate.
Without the secret the gate still detects, reports and remediates; only the re-scan of its own fix is
lost.

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
once the repository is protected and current. It reports as an issue and never fails a build, so it
is safe on a schedule.

```text
saw guard drift [TARGETS...] [-p PATH] [-c FILE] [-r] [--user U] [--org O] [--repo OWNER/NAME]
                [-j N] [--no-stream]
```

Target selection is identical to [`saw guard check`](#saw-guard-check).
