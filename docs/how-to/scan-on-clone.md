---
description: Scan code the moment it lands — a clone, pull, branch switch or rebase — so you are warned before you install, build or open it.
---

# Scan on clone

A worm fires when you install dependencies, run a build, or open the folder in an editor — not when
you clone. And a worm spreads when you push it on to a shared remote, where it reaches your
collaborators and your CI.
`saw hook` puts a scan in between on both sides: a fresh clone, a pull, a branch switch or a rebase
is scanned and you are warned *before* you run anything, and a `git push` is checked for every file
version it would publish, and reported, *before* the code leaves your machine. Flags:
[CLI reference](../reference/cli/hook.md).

```bash
saw hook install                       # new clones and this repository are scanned automatically
saw hook install ~/dev                 # give the hooks to every repository under ~/dev
saw hook install -c ~/security.yml     # scan them against YOUR allowlist
saw hook status                        # active? where is its state?
saw hook uninstall                     # stop
SAW_HOOK_DISABLED=1 git clone <url>    # one-off bypass, no uninstall needed
```

The hook warns and points at [`saw fix`](fix-findings.md). It modifies nothing and can never break a
git command. It is scanned against *your* allowlist, never the cloned repository's own config — see
[trust model](../explanation/trust-model.md).

**What you are installing.** Hooks that git runs, unprompted, in your repositories. Each repository
keeps them current on its own, and [`saw audit`](audit-a-machine.md) reports a hook saw did not
install or one that has been changed.

**Limits worth knowing.** `git reset --hard` runs no hook, so scan that yourself. If git is set to
run every repository's hooks from one folder, saw's hooks do not run there, and `install` and
`status` say so. saw never stops a push: a push it could not check in full reads as not verified,
never clean.

CI has no clone hook; the equivalent there is [gate CI](gate-ci.md).
