---
description: saw mcp — answer an editor's agent.
---

# `saw mcp`

```text
saw mcp
```

Speaks the Model Context Protocol on standard input and output. An editor launches it and keeps
it open, so an agent can ask for a verdict before it installs or runs anything.

The tools are `saw_scan_folder`, `saw_scan_files`, `saw_verdict` and `saw_audit_summary`. A scan
answer is the same document as [`saw scan --json`](scan.md). An audit answer is the same document
as [`saw audit --json`](audit.md). The first line of each answer is the verdict: clean, infected,
suspicious, residue, or not verified. An audit says safe, safe once you confirm the items it
names, unsafe, or that it did not finish.

A later question about a folder that has not changed reuses that result. The first audit in a
session stands until the agent asks for it again.

This does not change files. If the session cannot start, nothing is verified. Ask before you
install, build, or run anything. When the verdict is infected, suspicious, residue, or not
verified, stop and ask the person. When an audit says unsafe or incomplete, stop and ask the
person.

An editor points its agent configuration at `saw mcp`.
