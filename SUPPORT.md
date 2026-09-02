# Getting help

## Answer it yourself, first

Most questions are one command away, and both work offline:

```bash
saw search "open a pr"    # "what's the command for…?"
saw doctor                # self-check: install resolution, credentials, capabilities
saw intro                 # a 60-second tour
```

Then the docs:

- [CLI command guide](docs/reference/cli/index.md) — every `saw` command and its flags
- [Usage](docs/index.md) — install, secrets, GitHub Actions, deploying your own
- [Configuration & Reports](docs/reference/configuration.md) — config fields and report formats
- [Credential hygiene](docs/explanation/credential-hygiene.md) — what a cached-credential finding means
- [Prerequisites](docs/tutorial/first-scan.md) — supported Python versions and install troubleshooting

## Where to take it

| | |
| --- | --- |
| **A question** | Open an issue with the `question` label, or start a [discussion](https://github.com/Ndevu12/stayAwakeBot/discussions). Say what you ran and what you expected. |
| **saw did something other than what it documents** | [Bug report](https://github.com/Ndevu12/stayAwakeBot/issues/new?template=bug_report.yml). |
| **A finding you believe is benign** | [False positive](https://github.com/Ndevu12/stayAwakeBot/issues/new?template=false_positive.yml). These are the most useful reports we get. |
| **Something saw should do and cannot** | [Feature request](https://github.com/Ndevu12/stayAwakeBot/issues/new?template=feature_request.yml). |
| **A security issue** | **Not a public issue** — see [SECURITY.md](SECURITY.md). This includes any way to make the tool report clean when it should not. |
| **Contributing a change** | [CONTRIBUTING.md](CONTRIBUTING.md). |

Everyone taking part is covered by the [Code of Conduct](CODE_OF_CONDUCT.md).

## What we do not handle here

A finding in a repository that `saw` scanned is a report for the owner of **that** repository, not
for this one — unless you believe the finding itself is wrong, which is a false positive.

This is a small project. Issues get read; there is no support SLA, and no commercial-support
channel beyond the [commercial licence](COMMERCIAL-LICENSE.md) contact, **saw@ndevuspace.com**.
