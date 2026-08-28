---
description: Install saw, scan a repository, read the verdict and act on it. A guided first run in about five minutes, with no token and no configuration.
---

# Your first scan

Install `saw`, scan a repository, read the verdict, act on it. About five minutes.

## 1. Install

You need **Python 3.11 or newer** (3.11–3.14 are tested, and newer releases keep working).

```bash
pip install stayawakebot          # or: pipx install stayawakebot
```

The distribution is `stayawakebot`; the command it installs is `saw` (with `stayawake` as an
identical long alias). If pip answers `No matching distribution found for stayawakebot`, your Python
is older than 3.11 — that is how pip reports a version mismatch. Install a 3.11+ interpreter and try
again.

No Python at all? The same code ships as a non-root image:

```bash
docker run --rm -v "$PWD:/repo:ro" ghcr.io/ndevu12/stayawakebot saw scan /repo
```

Confirm the install with `saw doctor`.

## 2. Scan

Stand in a repository and run:

```bash
saw scan
```

Nothing is sent anywhere, no token is needed, and no file is written. The full report renders to your
terminal.

## 3. Read the verdict

The last line names the verdict:

| Verdict | What it means |
| --- | --- |
| clean | Nothing was found, and every target was fully scanned. |
| suspicious | Something wants a human look; it is not a confirmed infection. |
| infected | Confirmed malicious content is present. |
| error | A target could not be scanned — treat it as unknown, not clean. |

That is the whole CI contract: [verdicts](../explanation/verdicts.md).

## 4. Act

- **infected** → [fix the findings](../how-to/fix-findings.md). `saw fix` prepares the cleanup on a
  branch for you to review. On a confirmed infection it also removes the installed tree in this
  repository.
- **suspicious** → read the report and decide. Nothing here is auto-fixed.
- **error** → resolve what could not be read, then scan again.
- **clean** → keep it that way: [gate the repository's CI](gate-a-repo.md), and install
  [scan-on-clone](../how-to/scan-on-clone.md) so the next clone or pull is checked before you build
  it.

Then check the machine itself, which no repository scan covers:

```bash
saw audit
sudo saw harden
```

See [audit a machine](../how-to/audit-a-machine.md) and
[harden this machine](../how-to/harden-this-machine.md).
