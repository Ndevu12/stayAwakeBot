# Contributing to StayAwakeBot

Thanks for helping! StayAwakeBot is a distributable toolkit of **bots** (uptime +
security sentinels) over a shared `core`, packaged with `pyproject.toml`.

## Setup
```bash
python -m venv .venv && source .venv/bin/activate
pip install -e .
python -m unittest discover -s tests      # all tests must pass
```

**Python versions** — we support every maintained (non-EOL) CPython minor with real-world
deployment: currently **3.11–3.14**, tested in CI on each (the `ci.yml` matrix). The policy:
drop a version the release *after* it reaches upstream end-of-life, and add a new minor once it
ships — so the matrix evolves on its own. The packaged **floor** is `requires-python` in
`pyproject.toml`; keep the classifiers and the CI matrix in sync with it. The CI/dev toolchain
default lives in one place, [`.python-version`](.python-version) (read by `actions/setup-python`) —
bump it there, not in workflow files. (The `worm-scan` action stays pinned explicitly so it
remains self-contained for repos that adopt the gate.) The user-facing version requirement
lives in [`docs/tutorial/first-scan.md`](docs/tutorial/first-scan.md).

## Updating the container's dependencies

The container installs from `requirements.lock`, with hashes, rather than resolving dependencies at
build time. That keeps the image reproducible and means a poisoned release of a dependency cannot
enter it — pip refuses anything whose SHA-256 does not match.

`pyproject.toml` stays the source of truth and its dependencies stay unpinned: they are a contract
with people who `pip install stayawakebot`, and pinning there would force versions on them. The lock
applies to the image only.

After changing a dependency in `pyproject.toml`, regenerate the lock in the same PR:

```bash
pip install pip-tools
pip-compile pyproject.toml --generate-hashes --strip-extras -o requirements.lock
```

Commit the result. The diff shows exactly which versions moved, which is the point.

## Pull requests
- Keep commits focused; describe **what** changed (not internal roadmap phases).
- Run the suite locally; the **Worm Guard** CI gate must pass (it blocks any infected/evil-merge change).
- For security-sensitive changes, see [`docs/how-to/harden-a-repo.md`](docs/how-to/harden-a-repo.md).
- Add a `CHANGELOG.md` `[Unreleased]` entry in the same PR for any user-visible change — see below.

## Changelog entries

`CHANGELOG.md` follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). An entry describes
what someone **using** the release observes: new or changed behaviour, flags, compatibility, and
fixes they would notice.

An entry does **not** describe internal implementation — module layout, refactors, detector or rule
internals, thresholds, the inputs an analysis keys on, coverage gaps, or release-pipeline mechanics.
**A change with no user-visible effect gets no entry**, which is the normal outcome for a refactor.

For a **security** entry, say that the fix shipped and what it means for the reader — not the
mechanism, and not the weakness it closed. This file is public, permanent, and ships inside the
source distribution, so it is read by everyone including someone looking for a way past the scanner.

If an entry cannot be written without internal detail, that is the signal the change is not
user-visible and needs no entry.
