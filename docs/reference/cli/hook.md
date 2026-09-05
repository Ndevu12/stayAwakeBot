---
description: saw hook — install global git hooks that scan a clone, pull or rebase before you run the code. Full option reference.
---

# `saw hook`

**Scan on clone.** Installs global git hooks so a fresh clone, a pull, a branch switch or a rebase
scans what just landed and warns you *before* a dependency install, a build, or an editor auto-run
task. It uses git's `init.templateDir` rather than a global `core.hooksPath`, so existing
repositories are untouched, a repository's own hooks still run, and nothing is hijacked. The hook
warns and points at [`saw fix`](fix.md); it never modifies anything and can never break a git
command. See [scan on clone](../../how-to/scan-on-clone.md).

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

`install` creates a directory whose contents git runs, unprompted, in every repository cloned or
created afterwards. [`saw audit`](audit.md) enumerates that directory, any template directory you
configured yourself, and the hooks of the repositories it has seeded, and reports a hook that was
not installed by saw, or one that was installed by saw and has since been changed.

A pull or switch scans only what changed, so it is near-instant, and each scan runs under a
wall-clock budget (`SAW_HOOK_TIMEOUT`, default 60s) so a huge clone can never hang git; a scan that
times out reports the tree as unverified, never clean. `git reset --hard` fires no git hook, so scan
that case yourself with [`saw scan`](scan.md).
