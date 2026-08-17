# Report sinks

A report is a message, not a file. Full evidence exists only on the live terminal or via `--json`;
any artifact written to disk stores a `{sha256, preview, len}` fingerprint in place of the raw match,
so a report on disk can never re-distribute a live payload.

| Sink | Flag | Evidence | Destination |
| --- | --- | --- | --- |
| Terminal | (default) | full | stdout, ephemeral |
| JSON | `--json` | full | stdout — pipe it; no file |
| SARIF | `--sarif FILE` | redacted | `FILE`, for GitHub code scanning |
| Alert | `--alert` | evidence-free | GitHub issue + Slack |
| Reports dir | `-d DIR` | redacted | `DIR/latest.{json,md}` |
