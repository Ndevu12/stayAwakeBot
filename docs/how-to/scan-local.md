# Scan local code

No token, no config, nothing leaves your machine. Every flag is in the
[CLI reference](../reference/cli.md#saw-scan).

```bash
saw scan                      # the repository you are standing in
saw scan ~/dev/some-project   # one repository, or a folder full of them
saw scan ./a ./b --path ./c   # several at once
```

A path may be a single repository or a directory containing many — `saw` walks it for git
repositories. With no paths and nothing configured, it scans the repository you are in.

**Go faster.** Concurrency is automatic: a small scan stays sequential, a big one uses one worker per
core, and one large repository is split across workers too. Override it when you want to:

```bash
saw scan ~ -j auto            # sweep $HOME, one worker per core
saw scan -j 1                 # force sequential, e.g. on a low-memory box
```

A persisted report is byte-identical either way.

**Keep a copy.** A scan writes nothing by default. Pick a sink — see [report
sinks](../reference/cli.md#report-sinks):

```bash
saw scan --json > report.json     # full evidence, to a pipe
saw scan --sarif scan.sarif       # for GitHub code scanning
saw scan -d /tmp/saw-reports      # latest.json + latest.md
```

**Also examine installed dependency code** with `saw scan --deep` — opt-in because it adds roughly
10–60s on a large `node_modules`. For a suspicious directory that is *not* part of a repository, use
`saw audit --verify` instead ([audit a machine](audit-a-machine.md)).

Next: [fix findings](fix-findings.md) · [what a verdict means](../explanation/verdicts.md)
