---
description: saw hook — install global git hooks that scan code as it lands and as you are about to publish it, before you run or push it. Full option reference.
---

# `saw hook`

**Scan on clone, and before you push.** Installs global git hooks so a fresh clone, a pull, a branch
switch or a rebase scans what just landed and warns you *before* a dependency install, a build, or
an editor auto-run task — and a `git push` is checked for every file version it would publish, and
reported, *before* the code leaves your machine. It uses git's `init.templateDir` rather than a
global `core.hooksPath`, so existing repositories are untouched, a repository's own hooks still run,
and nothing is hijacked. The hook warns and points at [`saw fix`](fix.md); it never modifies
anything, never breaks a git command, and never stops a push. See
[scan on clone](../../how-to/scan-on-clone.md).

```text
saw hook install [-c FILE] [--no-stream]
saw hook repair [--no-stream]
saw hook uninstall [--no-stream]
saw hook status [--no-stream]
```

| Option / subcommand | Description |
| --- | --- |
| `install` | Point git's global `init.templateDir` at saw's template, so repositories cloned or created from now on get the hooks. |
| `repair` | Put back every hook saw installs, wherever git runs it, and move aside what stood in its place. |
| `uninstall` | Reverse it, restoring any hook it had to preserve. |
| `status` | Whether it is active, the template directory, and the scan cache. |
| `-c`, `--config FILE` | Operator config whose allowlist clones are scanned against, baked into the hook. The hook never reads a cloned repository's own config. |
| `--no-stream` | Plain instant lines instead of live progress on the clone/pull scan. Same as `STAYAWAKE_NO_STREAM=1`. |

`install` creates a directory whose contents git runs, unprompted, in every repository cloned or
created afterwards. [`saw audit`](audit.md) enumerates that directory, any template directory you
configured yourself, and the hooks of the repositories it has seeded, and reports a hook that was
not installed by saw, or one that was installed by saw and has since been changed.

`repair` answers that report. It rewrites every hook saw installs, in the template directories and in
every repository saw has seeded, and moves aside whatever was found in a hook's place. The
directory saw manages is saw's alone: anything in it that is not a hook saw installs is moved aside
too, on `install`, `repair` and `uninstall` alike. Nothing is deleted. What is moved aside is kept
under saw's state directory beside a record of where it came from, for you to examine. A hook counts
as back only after it is read back as written; one that could not be is named, and left as it was.
A repository's own hooks are never touched; a hook of yours that saw chained to in a template
directory you configured stays, and is restored by `uninstall`. `install` records which saw, which
config and which directory it installed into; `repair` puts back exactly that, there and in the
repositories saw has seeded, and asks you to run `install` once when no record exists. A seeded
repository that runs its hooks from elsewhere is named and left alone. A hook of saw's that names another saw or config is put back as well. `uninstall`
also forgets the repositories saw had seeded.

`status` says when something where saw's hooks run is not what saw installed.

A pull or switch scans only what changed, so it is near-instant, and each scan runs under a
wall-clock budget (`SAW_HOOK_TIMEOUT`, default 60s) so a huge clone can never hang git; a scan that
times out reports the tree as unverified, never clean. `git reset --hard` fires no git hook, so scan
that case yourself with [`saw scan`](scan.md).

A push is checked for what it would publish: every branch and tag it sends, every commit in it, and
what each branch and tag will serve once it lands, including one pushed back to an older state, as
committed rather than as your working folder holds it. A worm it finds is named with the commit
that carries it and pointed at [`saw fix amend`](amend.md), which removes it from what you published;
the push itself goes through. A push is checked under a shorter budget, 20s by default
(`SAW_HOOK_TIMEOUT` sets both), and what it could not check in time reads as not verified and is
checked the next time that repository pushes. A hook of yours that saw runs after its own, and
Git LFS, keep their say over the push.
