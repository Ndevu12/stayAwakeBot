---
description: A layered baseline that keeps a worm from re-entering a repository, applied per repository or across a fleet.
---

# Harden a repository

A layered baseline that keeps a worm from re-entering a repository. Apply it per repository, or
org-wide. Each layer catches what the one before it cannot.

## 1. The CI gate — the key control

It blocks an infected change from merging. One command, per repository or per organisation:

```bash
saw guard setup --pr          # or --org your-org for the whole fleet
```

See [gate CI](gate-ci.md), and [gate a repository](../tutorial/gate-a-repo.md) for the walkthrough.
If you write the workflow by hand instead, **pin the action by commit SHA**, not by tag: a tag can be
moved to different code after you reviewed it, a SHA cannot.

## 2. Branch protection

- Require pull-request review before merging to the default branch, and disable auto-merge.
- Require the gate's status check.
- Restrict who may push to the default branch; require linear history.
- Verify it is really enforced — `saw guard check -f`, or `saw audit --repo owner/name -f`.

## 3. On the developer machine

Scan what arrives before you run it:

```bash
saw hook install        # see docs/how-to/scan-on-clone.md
saw audit               # the machine's own posture
```

For a repository that would rather commit its hooks alongside its code than have each developer
install them, `prevent/install-hooks.sh` is a dependency-free alternative that installs a `pre-commit`
hook (blocking worm artifacts on the way out) plus `post-merge` / `post-checkout` hooks (warning about
code that arrives via a pull, merge or clone — which a pre-commit hook cannot see):

```bash
prevent/install-hooks.sh                 # this repository
prevent/install-hooks.sh --template      # every FUTURE clone
prevent/install-hooks.sh --all ~/dev     # every existing repository under a root
prevent/install-hooks.sh --force         # overwrite a foreign hook instead of backing it up
```

An existing non-StayAwakeBot hook is backed up to `<hook>.pre-stayawake.bak`, never destroyed.

## 4. Keep dependencies audited

```bash
saw db update                 # refresh the offline advisory corpus
saw db status --max-age-days 30
```

See [the advisory database](../reference/advisory-db.md).
