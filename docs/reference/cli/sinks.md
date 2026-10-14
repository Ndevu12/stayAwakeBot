---
description: Where a saw report can go — terminal, JSON, SARIF, alerts, a reports directory — and what evidence each one carries.
---

# Report sinks

A report is a message, not a file. Only `--json` carries the full evidence. The terminal shows a
short preview of each finding it lists, and any artifact written to disk stores a
`{sha256, preview, len}` fingerprint in place of the raw match, so a report on disk can never
re-distribute a live payload.

| Sink | Flag | Evidence | Destination |
| --- | --- | --- | --- |
| Terminal | (default) | a short preview | stdout, ephemeral |
| JSON | `--json` | full | stdout — pipe it; no file |
| SARIF | `--sarif FILE` | redacted | `FILE`, for GitHub code scanning |
| Alert | `--alert` | evidence-free | GitHub issue + Slack |
| Reports dir | `-d DIR` | redacted | `DIR/latest.{json,md}` |

## The report a long scan writes for you

A large scan — many targets, or many findings and advisories between them — stops printing
per-finding detail and shows the summary table only. The full report is written to a file
instead, so nothing is lost to scrollback, and the path is printed on stderr in a ruled block
(clickable when your terminal supports it). A smaller scan prints every finding on the terminal.

Where it lands:

| You passed | Written to |
| --- | --- |
| `-d DIR` | `DIR/latest.md` and `DIR/latest.json` |
| nothing | a folder `saw` keeps for you in the system's temporary directory, named by when it was written |

Two things worth knowing about the copy `saw` keeps. Its evidence is **redacted**, like any artifact
on disk; `saw scan --json` carries it in full. And `saw` never deletes it; your operating system
clears its temporary directory on its own schedule, which may be at reboot or not at all. If you
want the report kept somewhere you chose, pass `-d DIR` and it goes there instead.

`--json` turns the spill off: that payload already carries every finding in full, so there is
nothing to rescue from scrollback. A `-d DIR` you asked for is still written.

## The dependencies to remove

When a scan flags a dependency, the commands that remove each known-malicious package, and the
versions an advisory affects, are given once per run: last on the terminal, below the report's path
when a large scan writes one; at the top of the written report; and in the body of a fix pull
request. `saw` names the compromised versions and never a version to install.
