---
description: saw fix — clean detected findings on a branch and publish them only as a pull request. Full option reference.
---

# `saw fix`

Clean detected findings **on a branch**. By default `fix` prepares `security/auto-clean` locally and
stops — no push, no PR, no network — for you to review. Source changes land on that branch. On a
confirmed infection it also removes the installed tree, generated build outputs, and the lockfile
in this repository (the lockfile is kept on CI). A merge finding that is still live in the working
tree is restored there; the merge commit is left in history. `--pr` pushes and opens or updates one
rolling PR per repository. `saw fix amend` replaces past commits that still carry the payload and
force-updates each branch they sat on. That force-update is the fix. It does not open a pull request
and it does not take `--branch`. Bare `saw fix` still only prepares a cleanup branch.
See [the safety envelope](../../explanation/safety-envelope.md) for what `fix` will and will not touch.

```text
saw fix [TARGETS...] [--pr] [-r] [--user U] [--org O] [-p PATH] [-c FILE] [-j N] [--no-stream]
saw fix amend [TARGETS...]
saw fix amend --remote [--user U] [--org O]
```

| Option | Description |
| --- | --- |
| `TARGETS...` / `-p` / `-c` / `-r` / `--user` / `--org` / `-j` / `--no-stream` | As for [`saw scan`](scan.md). A missing *explicit* `--config` path is a clear error, never a crash. |
| `--pr`, `--open-pr` | Also push the branch and open/update one rolling, de-duplicated PR per repository. Needs a credential with repo + PR write; the API is pre-flighted before any push. Not accepted with `amend`. |
| `amend` | Replace past commits that still carry the payload and force-update each branch they sat on. That force-update is the fix. The replaced commit keeps its original message. Tags and notes are not moved. `--branch` is not accepted. If the remote does not move, local branches are left as they stood. The previous objects remain until collected. |
