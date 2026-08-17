---
description: saw auth — GitHub credential and capability status, and registration of an operator-managed StayAwakeBot App.
---

# `saw auth`

Credential and capability status, and registration of an operator-managed StayAwakeBot GitHub App.
Most of `saw` is offline; `auth` is only about the credential used for the network paths — remote
scanning, `saw fix --pr`, and `saw guard setup --pr`. Bare `saw auth` is `saw auth status`.

```text
saw auth status [--json] [--no-stream]
saw auth app register [--name NAME] [--no-browser] [--replace] [--no-stream]
saw auth app show [--no-stream]
```

| Option / subcommand | Description |
| --- | --- |
| `status` | The active credential (source, actor, whether it is live), its scopes, whether an App is configured, and per-intent gating: for each key action, whether this credential is allowed and, if not, the command that fixes it. Exits non-zero when a live credential could not open a guard PR, so it drops straight into CI. |
| `app register` | Register and install an App through GitHub's browser manifest flow, storing the credentials locally (mode `0600`). Idempotent: with an App already configured it points you at installing that same App elsewhere. |
| `app show` | Whether a local App config is present, with its install and settings URLs. |
| `--name NAME` | App display name (default: `StayAwakeBot`). |
| `--no-browser` | Print the manifest URL instead of opening a browser. |
| `--replace` | Register a brand-new App even if one is configured. |

Which credential `saw` picks, and the least privilege each command needs, are in
[credentials](credentials.md).
