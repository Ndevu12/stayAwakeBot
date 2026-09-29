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
saw hook install                       # future clones and pulls are scanned automatically
saw hook install -c ~/security.yml     # scan them against YOUR allowlist
saw hook status                        # active? where is its state?
saw hook uninstall                     # stop
SAW_HOOK_DISABLED=1 git clone <url>    # one-off bypass, no uninstall needed
```

The hook warns and points at [`saw fix`](fix-findings.md). It modifies nothing and can never break a
git command. It is scanned against *your* allowlist, never the cloned repository's own config — see
[trust model](../explanation/trust-model.md).

**What you are installing.** A directory whose contents git runs, unprompted, in every repository
you clone or create from then on. That is what makes scan-on-clone work, and it is also a place a
foothold could be planted, so [`saw audit`](audit-a-machine.md) enumerates it along with the
repositories it has seeded and reports a hook saw did not install or one that has been changed.

**Limits worth knowing.** It applies to repositories cloned or created *after* you install it, which
is how git's template mechanism works — scan the ones you already have with `saw scan ~/dev`. A
global `core.hooksPath` overrides it, and `install`/`status` warn when one is set. `git reset --hard`
fires no git hook at all, so scan that yourself. saw never stops a push: it reports what the push
carries, and a push it could not check in full reads as not verified, never clean.

CI has no clone hook; the equivalent there is [gate CI](gate-ci.md).
