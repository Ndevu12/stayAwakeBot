---
description: saw hook — install global git hooks that scan code as it lands and as you are about to publish it, before you run or push it. Full option reference.
---

# `saw hook`

**Scan on clone, and before you push.** saw's git hooks scan what lands in a repository (a clone,
a pull, a branch switch, a rebase) and warn you *before* a dependency install, a build or an editor
task runs it. A `git push` is checked for everything it would publish *before* the code leaves your
machine. The hooks warn and point at [`saw fix`](fix.md); they never change your code, never break a
git command, and never stop a push. See [scan on clone](../../how-to/scan-on-clone.md).

```text
saw hook install [PATH...] [-c FILE] [--no-stream]
saw hook repair [--no-stream]
saw hook uninstall [--no-stream]
saw hook status [--no-stream]
```

| Option / subcommand | Description |
| --- | --- |
| `install` | Give the hooks to every repository you clone or create from now on, and to the repositories you already have. |
| `PATH...` | Repositories, folders or globs to give the hooks to. Without them: your configured local targets, else the repository you are in. |
| `repair` | Put back every hook saw installed, and set aside whatever stood in its place. |
| `uninstall` | Remove saw's hooks and restore any hook of yours they ran before. |
| `status` | Whether the hooks are in place and will run. |
| `-c`, `--config FILE` | Your config, whose allowlist the hooks scan with. A repository's own config is never read. |
| `--no-stream` | Plain instant lines instead of live progress. Same as `STAYAWAKE_NO_STREAM=1`. |

## What to expect

- **Your repositories stay current.** Whenever one of saw's hooks runs, a saw hook that is missing or
  out of date there is put back. Your own hooks keep running and are left as they are.
- **Nothing is deleted.** Whatever saw sets aside is kept, with a record of where it came from, for
  you to examine. A hook that could not be put back is named.
- **[`saw audit`](audit.md) reports** a hook saw did not install, or one of saw's that was changed;
  `saw hook repair` puts it back.
- **Scans are quick and bounded.** A pull or switch scans only what changed. Each scan has a time
  budget (`SAW_HOOK_TIMEOUT`: 60s, 20s for a push). What could not be checked in time reads as not
  verified, never clean.
- **A push goes through.** A worm it would publish is named with the commit that carries it and
  pointed at [`saw fix amend`](amend.md). Your own pre-push hook and Git LFS keep their say.
- `git reset --hard` runs no hook; check that case with [`saw scan`](scan.md).
