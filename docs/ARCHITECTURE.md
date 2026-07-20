# StayAwakeBot — Architecture

A distributable (`pip install`-able) toolkit: two bots as packages under one
`stayawake` namespace, over a **layered shared foundation**. One responsibility per folder.

## Layered architecture

Five packages under `stayawake/`, low → high. **A module may import only from layers to its LEFT**
— an upward import is a dependency inversion. This is enforced by
[`tests/core/test_layering.py`](../tests/core/test_layering.py), which walks the full AST (so lazy
imports inside functions count too) and fails on any violation.

```
utils/  →  lib/  →  core/  →  bots/  →  cli/
```

- **`utils/`** — pure, generic helpers: `render` · `textsafe` · `config` · `env` · `io` ·
  `streaming` · `terminal` · `pager` · `timeutil`. No external I/O, no domain, no integration;
  liftable into any project. **Depends on nothing internal.**
- **`lib/`** — integration libraries / adapters — the *ports* to external systems:
  `adapters/` (`github_api` · `http_client` · `slack`) · `git/` (the git-CLI package) · `auth` ·
  `github_app`. **Depends on `utils/`.**
- **`core/`** — the application's **domain layer**: cross-bot abstractions & shared patterns, e.g.
  `issue_state` (a GitHub issue used as a durable, file-less state store). **Depends on `lib/` + `utils/`.**
- **`bots/`** — the features/policies. **Depends on `core/` + `lib/` + `utils/`.**
- **`cli/`** — the unified `saw` command; one module per verb. **Depends on `bots/`.**

When a lower layer needs behavior that lives higher up (e.g. the merge corroborator in
`lib/git/merge/` needs the security obfuscation check), the higher layer **injects** it as a
callable — the lower layer never imports up. (See `corroborate.py`'s `obfuscation_reason` / `content_sig`.)

## Package layout

```
src/stayawake/                     ← single import root (installable; no name clashes)
  utils/       render · textsafe · config · env · io · streaming · terminal · pager · timeutil
  lib/         auth · github_app
    adapters/  http_client · github_api · slack     # external I/O, one per file (SRP)
    git/       run · auth · query · merge/ · write/  # the git CLI, split per concern
  core/        issue_state                          # domain layer (cross-bot patterns)
  bots/
    health/    models · config · checker · alerter · cli/            # uptime sentinel
    security/  models · signatures · scanner · service · remediator · resolution · pr · proposal · guard
      matchers/  base · content · filename · structural · heuristic · git_history  # one technique/file
      targets/   base · local · remote
      sinks/     terminal · json · sarif · alert · file_sink   # terminal-first output (Strategy); evidence redacted when persisted
      hygiene/   host-persistence audit (saw audit)
      data/      signatures.yml      # default IoC DB shipped INSIDE the package
  cli/         dispatch · _meta · commands/{scan,fix,audit,guard,search,db,…}   # unified `saw` CLI
pyproject.toml   packaging: metadata · console scripts · package-data
config/   urls.yml · security.yml        # deployment config (targets/allowlist; signatures are packaged)
tests/    core/test_layering.py · bots/health · bots/security    # mirrors src; the layering guard lives in tests/core
docs/  CONTRIBUTING.md
```

## Principles
- **Layering / no upward imports** — `utils → lib → core → bots → cli`; enforced by the guard test.
  Keeps the foundation reusable and the dependency graph acyclic.
- **SRP** — one responsibility per folder/file (a matcher per technique, an adapter per external system, a CLI module per verb).
- **Unified CLI** — the top-level `stayawake.cli` package is the terse `saw` (and `stayawake`) command; one module per verb under `cli/commands/`, each routing to the **same** `bots/security` service. `saw scan` is **terminal-first**, delivering durable output through the opt-in `bots/security/sinks/` (`--json`, `--sarif`, `--alert`, `-d`). See [CLI command guide](CLI.md).
- **DRY** — `utils/` + `lib/` are reused by both bots; console scripts reuse the thin `main()`s; one packaged signature source.
- **Reusability / distributability** — `pip install stayawakebot` gives a self-contained scanner with console commands; the worm-scan Action installs it instead of cloning.
- **Maintainability / collaboration** — standard modern `src/` layout, `pyproject.toml` single source of truth, `CONTRIBUTING.md`, tests mirror `src`, importable without path tricks.
- **Scalability** — a new bot is `src/stayawake/bots/<bot>/`; new detections are data (`…/security/data/signatures.yml`) or a file in `security/matchers/`. New shared code lands in the layer that fits: a pure helper → `utils/`, an external-system adapter → `lib/`, a cross-bot domain abstraction → `core/`.

## Install & run
```bash
pip install -e .            # or: pip install .
stayawake-health-check   --config config/urls.yml    # check URLs → refresh the ONE status issue
saw scan  --config config/security.yml               # local security CLI (see docs/CLI.md)
saw fix [--pr] [--remote]                            # prepare a security/auto-clean branch (--pr to PR)
saw guard check | setup                              # verify / install the Strix CI gate
python -m unittest discover -s tests      # tests (package must be installed)
```
(The health bot's actions also run as `python -m stayawake.bots.health.cli.<action>`.)

## Adding shared code or a bot
- **A pure helper** (no I/O, no domain) → `src/stayawake/utils/`.
- **An external-system adapter** (a new API/tool wrapper) → `src/stayawake/lib/` (or `lib/adapters/`).
- **A cross-bot domain abstraction** → `src/stayawake/core/`.
- **A new bot** → `src/stayawake/bots/<bot>/` with its `models`/`service` + a thin `cli/`; register
  console scripts in `pyproject.toml`; mirror tests under `tests/bots/<bot>/`.

Whatever you add, keep the imports pointing **down** — the layering guard will fail the build otherwise.
