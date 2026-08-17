# Gate a repository

A repository that scans clean today can still merge an infected change tomorrow. This walks one
repository from unguarded to *provably* guarded. You need a GitHub token with the `workflow`
permission (see [credentials](../reference/cli/credentials.md)).

## 1. See what is missing

```bash
saw guard check
```

It reports whether a gate exists, whether it is pinned to a SHA, whether the pin is current, and — for
a remote repository — whether branch protection actually requires the check.

## 2. Preview, then install

```bash
saw guard setup --dry-run     # print the workflow that would be written
saw guard setup               # write it into the working tree to review and commit
```

Prefer a pull request, and never a push to `main`:

```bash
saw guard setup --pr
```

The PR body lists the two things a file cannot do for itself: allow GitHub Actions to create pull
requests, and (optionally) add the `GH_SECURITY_TOKEN` secret so the fix PR gets scanned too.

## 3. Make the check required

Merge the PR, then in **Settings → Branches** require the gate's check on your default branch. A gate
that is not required is decoration — anyone can merge past it.

## 4. Prove it

```bash
saw guard check -f
```

`-f` makes it exit non-zero if the gate is absent, unpinned, stale, or not required, so this same
line works as a CI step. Repeat for every repository at once with `--user` or `--org`:

```bash
saw guard check --org your-org -f
```

## 5. Keep it current

The installed workflow carries a weekly `pin-drift` job that files one self-closing issue when the
pinned release falls behind, and closes it once you bump. Run it across a fleet yourself with
`saw guard drift --org your-org`.

## What the gate does on an infected verdict

It goes **red**, and it opens one rolling `security/auto-clean` pull request with the fix. The check
stays red until that PR is merged — remediation opens the fix, it never makes the check pass. For
detection without remediation, see [gate CI](../how-to/gate-ci.md).
