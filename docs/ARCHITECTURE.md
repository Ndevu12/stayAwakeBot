# StayAwakeBot — Architecture

A distributable (`pip install`-able) toolkit: two bots as packages under one
`stayawake` namespace, over a shared `core`. Layering runs
`cli → service → (domain + adapters) → core`. One responsibility per folder.

```
src/stayawake/                     ← single import root (installable; no name clashes)
  core/        io · timeutil · config · git          # shared utilities (DRY)
    adapters/  http_client · github_api · slack   # external I/O, one per file (SRP)
  bots/
    health/    models · config · checker · reporter · alerter · service · cli/   # uptime sentinel
    security/  models · signatures · scanner · service · remediator · pr
      matchers/  base · content · filename · structural · heuristic · git_history  # one technique/file
      targets/   base · local · remote
      sinks/     terminal · json · sarif · alert · reports_dir   # terminal-first output (Strategy); evidence redacted when persisted
      data/      signatures.yml      # default IoC DB shipped INSIDE the package
  cli/         dispatch · _meta · commands/{scan,fix,audit,search,doctor,completion}   # unified `saw` CLI
pyproject.toml   packaging: metadata · console scripts · package-data
config/   urls.yml · security.yml        # deployment config (targets/allowlist; signatures are packaged)
tests/    bots/health · bots/security    # mirrors src
docs/  prevent/  reports/  .github/  CONTRIBUTING.md
```

## Principles
- **SRP** — `core` (utilities) · `bots/*` (each bot) · `cli/` (entrypoints) · `data/` (signatures) are separate.
- **Unified CLI** — the top-level `stayawake.cli` package is the terse, security-only `saw` (and `stayawake`) command; one module per verb under `cli/commands/` (`scan`, `fix`, `audit`, `search`, `doctor`, `completion`), each routing to the **same** `bots/security` service. `saw scan` is **terminal-first** — it renders the report to the terminal and delivers durable output through the opt-in `bots/security/sinks/` (`--json`, `--sarif`, `--alert`, `-d`). The legacy `stayawake-security-*` scripts have been **removed**; health remains remote-only. See [CLI command guide](CLI.md).
- **DRY** — `core` (+ `core/adapters`) is reused by both bots; console scripts reuse the thin `main()`s; one packaged signature source.
- **Reusability / distributability** — `pip install stayawakebot` gives a self-contained scanner with console commands; the worm-scan Action installs it instead of cloning.
- **Maintainability / collaboration** — standard modern `src/` layout, `pyproject.toml` single source of truth, `CONTRIBUTING.md`, tests mirror `src`, importable without path tricks.
- **Scalability** — a new bot is `src/stayawake/bots/<bot>/`; new shared code is `src/stayawake/core/<x>`; new detections are data (`…/security/data/signatures.yml`) or a file in `security/matchers/`.

## Install & run
```bash
pip install -e .            # or: pip install .
stayawake-health-check   --config config/urls.yml    # health bot is remote-only; scripts kept for CI
stayawake-health-report
stayawake-health-alert
saw scan  --config config/security.yml               # local security CLI (see docs/CLI.md)
saw fix [--remote]                                   # cleanup → PR per infected repo
python -m unittest discover -s tests      # tests (package must be installed)
```
(The health bot's actions also run as `python -m stayawake.bots.health.cli.<action>`.)

## Adding a bot
Create `src/stayawake/bots/<bot>/` with its `models`/`service` + a thin `cli/`,
reuse `stayawake.core` (+ `core.adapters`), register console scripts in `pyproject.toml`,
and mirror tests under `tests/bots/<bot>/`. Existing bots are untouched.
