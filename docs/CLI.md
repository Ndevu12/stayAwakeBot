# `saw audit` — scope note

The `saw` command guide has moved to **[reference/cli.md](reference/cli.md)**; start at the
[documentation index](index.md). This page keeps its path because `saw audit` prints a link to the
section below.

### What `saw audit` does not scan

`saw audit` reads the host persistence surface and a targeted set of known drop-paths: your home
directory, `/tmp`, the system temp dir, and the working directory.

**It does not scan** — so a clean audit is not a clean bill of health for any of these:

| not scanned | why it matters |
| --- | --- |
| other survivor temp dirs | a payload staged where `$TMPDIR` does not point survives a reboot |
| the global npm prefix, beyond Node's own resolution paths | a globally installed package is not read |
| Docker images and volumes | a compromised image is untouched by a host scan |
| other mounted filesystems | only the paths above are walked |
| account and organization state | a self-hosted runner registered against the org survives a host rebuild |
| Windows autorun | registry Run keys, the Startup folder and Scheduled Tasks are enumerated nowhere — persistence enumeration is macOS and Linux user-scope only |

### Where to go next

- [`saw audit` reference](reference/cli.md#saw-audit)
- [Audit a machine](how-to/audit-a-machine.md) — what each outcome means and what to do
