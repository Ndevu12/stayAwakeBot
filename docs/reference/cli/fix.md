---
description: saw fix — clean detected findings on a branch and publish them only as a pull request. Full option reference.
---

# `saw fix`

Clean detected findings **on a branch**. By default `fix` prepares `security/auto-clean` locally and
stops — no push, no PR, no network — for you to review. Source changes land on that branch. On a
confirmed infection it also removes the installed tree, generated build outputs, and the lockfile
in this repository (the lockfile is kept on CI). A merge finding that is still live in the working
tree is restored there; the merge commit is left in history unless you run `saw fix amend`.
`--pr` pushes and opens or updates one rolling PR per repository. `saw fix amend` is local and
does not publish. See [the safety envelope](../../explanation/safety-envelope.md) for what `fix`
will and will not touch.

```text
saw fix [TARGETS...] [--pr] [-r] [--user U] [--org O] [-p PATH] [-c FILE] [-j N] [--no-stream]
saw fix amend [TARGETS...]
```

| Option | Description |
| --- | --- |
| `TARGETS...` / `-p` / `-c` / `-r` / `--user` / `--org` / `-j` / `--no-stream` | As for [`saw scan`](scan.md). A missing *explicit* `--config` path is a clear error, never a crash. |
| `--pr`, `--open-pr` | Also push the branch and open/update one rolling, de-duplicated PR per repository. Needs a credential with repo + PR write; the API is pre-flighted before any push. Not accepted with `amend`. |
| `amend` | Replace a confirmed merge on the current branch. Local only. Tags are not moved. The previous objects remain until collected. |
