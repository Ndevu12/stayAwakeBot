---
description: saw fix — clean detected findings on a branch and publish them only as a pull request. Full option reference.
---

# `saw fix`

Clean detected findings **on a branch**. By default `fix` prepares `security/auto-clean` locally and
stops — no push, no PR, no network — for you to review. It never edits your working tree. `--pr`
pushes and opens or updates one rolling PR per repository. See [the safety
envelope](../../explanation/safety-envelope.md) for what `fix` will and will not touch.

```text
saw fix [TARGETS...] [--pr] [-r] [--user U] [--org O] [-p PATH] [-c FILE] [-j N] [--no-stream]
```

| Option | Description |
| --- | --- |
| `TARGETS...` / `-p` / `-c` / `-r` / `--user` / `--org` / `-j` / `--no-stream` | As for [`saw scan`](scan.md). A missing *explicit* `--config` path is a clear error (exit `2`), never a crash. |
| `--pr`, `--open-pr` | Also push the branch and open/update one rolling, de-duplicated PR per repository. Needs a credential with repo + PR write; the API is pre-flighted before any push. |
