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

## The report a long scan writes for you

A scan whose result is too large for a terminal — many repositories, or a lot of findings and
advisories between them — stops printing per-finding detail and shows the summary table only. The
full report is written to a file instead, so nothing is lost to scrollback, and the path is printed
on stderr in a ruled block (clickable when your terminal supports it).

Where it lands:

| You passed | Written to |
| --- | --- |
| `-d DIR` | `DIR/latest.md` and `DIR/latest.json` |
| nothing | a fresh temporary directory named `sab-report-…`, printed with the report |

Two things worth knowing about the temporary copy. Its evidence is **redacted**, like any artifact
on disk — the full evidence stayed on your terminal. And `saw` never deletes it; your operating
system clears its temporary directory on its own schedule, which may be at reboot or not at all. If
you want the report kept somewhere you chose, pass `-d DIR` and it goes there instead.

`--json` turns the spill off: that payload already carries every finding in full, so there is
nothing to rescue from scrollback. A `-d DIR` you asked for is still written.
