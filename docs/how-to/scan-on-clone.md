# Scan on clone

A worm fires when you `npm install`, build, or open the folder in an editor — not when you clone.
`saw hook` puts a scan in between: a fresh clone, a pull, a branch switch or a rebase is scanned and
you are warned *before* you run anything. Flags: [CLI reference](../reference/cli/hook.md).

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

**Limits worth knowing.** It applies to repositories cloned or created *after* you install it, which
is how git's template mechanism works — scan the ones you already have with `saw scan ~/dev`. A
global `core.hooksPath` overrides it, and `install`/`status` warn when one is set. `git reset --hard`
fires no git hook at all, so scan that yourself.

CI has no clone hook; the equivalent there is [gate CI](gate-ci.md).
