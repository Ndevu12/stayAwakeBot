---
description: saw serve — stay running and answer scan and audit questions.
---

# `saw serve`

```text
saw serve --stdio
```

Stays running and answers a scan, a scan of named files, a verdict, and an audit. Each answer is
the same JSON document as [`saw scan --json`](scan.md) or [`saw audit --json`](audit.md). A later
question about a folder that has not changed reuses that result. A question that does not finish
is not verified.

This does not change files. An editor keeps one `saw serve --stdio` open for the window.

| Option | Description |
| --- | --- |
| `--stdio` | Answer on standard input and output. One JSON-RPC message per line in, one per line out. A scan answer carries the same document as `saw scan --json`. |
