# `saw discard`

The inverse of `saw fix`: remove what it produced. It only ever touches the generated
`security/auto-clean` branch. **At least one of `--branch` / `--pr` is required.**

```text
saw discard (--branch | --pr) [-r] [--user U] [--org O] [TARGETS...] [-c FILE] [--no-stream]
```

| Option | Description |
| --- | --- |
| `-br`, `--branch` | Delete the branch locally and on its remote (pure git; deleting the remote branch closes its PR). |
| `--pr`, `--close-pr` | Close the open `security/auto-clean` PR, leaving the branch. |
| `TARGETS...` / `-p` / `-c` / `-r` / `--user` / `--org` / `--no-stream` | As for [`saw fix`](fix.md). |
