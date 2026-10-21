---
description: saw capabilities — what the installed saw supports, for an editor extension or script that runs it.
---

# `saw capabilities`

```text
saw capabilities [--json] [--no-stream]
```

Prints the installed saw's version, the schema version of each JSON document it prints, and the
features it has. A program that runs saw, such as an editor extension or a CI script, reads this
instead of comparing version numbers. It is offline and read-only.

```console
$ saw capabilities --json
{
  "schema_version": 1,
  "version": "X.Y.Z",
  "schema_versions": {
    "scan": 1,
    "fix": 1,
    "doctor": 1,
    "auth-status": 1,
    "guard-drift": 1,
    "audit": 1,
    "hook-status": 1,
    "capabilities": 1
  },
  "features": [
    "scan.json",
    "fix.json",
    "doctor.json",
    "auth.status.json",
    "guard.drift.json",
    "audit.json",
    "hook.status.json",
    "capabilities.json",
    "progress.jsonl"
  ],
  "platform": {
    "os": "linux",
    "supported": true
  }
}
```

| Field | Meaning |
| --- | --- |
| `version` | The installed saw, as `saw --version` prints it. |
| `schema_versions` | Each JSON document this saw prints, and the schema version it writes. A document is named after the command that prints it: `auth-status` is `saw auth status --json`. |
| `features` | What this saw can do. `<command>.json` means that command takes `--json`. `progress.jsonl` means `saw scan`, `saw audit` and `saw fix` take `--progress=jsonl`. |
| `platform` | The operating system, and whether saw supports it. |

## Schema versions

Every JSON document saw prints starts with `"schema_version"`. A version changes only when a
change would break a program reading the document: a field removed or renamed, or a value that
changes meaning. Adding a field does not change it, so a reader should ignore fields it does not
know.

A program that meets a `schema_version` newer than the one it was written for should stop and say
which side to update, rather than guess.

`saw search --json` prints a list of matching commands, not a document, and has no
`schema_version`.
