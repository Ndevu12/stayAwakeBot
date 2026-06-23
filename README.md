<!-- STAYAWAKEBOT_BADGE -->
![Health](https://img.shields.io/badge/health-0%2F2%20up-red)
<!-- STAYAWAKEBOT_BADGE_END -->
<!-- STAYAWAKEBOT_SECURITY_BADGE -->
![Security](https://img.shields.io/badge/security-clean-brightgreen)
<!-- STAYAWAKEBOT_SECURITY_BADGE_END -->

# StayAwakeBot

StayAwakeBot is a distributable (`pip install`-able) Python monitoring **and** security
toolkit. Under one `stayawake` namespace it ships two bots over a shared `core`:

- **Health sentinel** — a URL/uptime availability monitor (HTTP status, latency, TLS,
  keyword checks) that writes JSON/markdown reports and a status badge.
- **Security sentinel** — a supply-chain worm hunter that detects, alerts on, and
  auto-fixes self-propagating malware (obfuscated loaders, fake fonts, VS Code auto-run
  tasks, and stealth "evil merges"), opening remediation PRs and gating CI.

Run either bot as a **console script** locally, or as **GitHub Actions** workflows that
commit reports back to the repository — the same packaged code in both places.

## Architecture

![StayAwakeBot architecture](public/stayawakebot_architecture.svg)

## Usage

StayAwakeBot installs as a Python package and exposes both bots as **console scripts**.
The same commands run locally or inside the bundled GitHub Actions workflows.

### Install

```bash
pip install "stayawake @ git+https://github.com/Ndevu12/stayAwakeBot@main"   # or: pipx install "stayawake @ git+…"
# from a clone, for development:
pip install -e .
```

### Health bot — uptime monitoring

Run the pipeline against `config/urls.yml`:

```bash
stayawake-health-check  --config config/urls.yml   # probe URLs → reports/latest.json
stayawake-health-report                            # build status.json, history, dated .md, badge
stayawake-health-alert                             # Slack alert on failures / recoveries
```

Add `--fail-on-unhealthy` to `check` to exit non-zero when any URL is down (handy locally;
CI keeps it non-fatal so reports always generate).

### Security bot — worm hunting

```bash
stayawake-security-scan --config config/security.yml --local-only   # scan local repos → reports/security/latest.json
stayawake-security-report                                           # status + security badge
stayawake-security-alert                                            # Slack + GitHub issue on findings
```

Remediation is **safe by default (dry-run)**:

```bash
stayawake-security-remediate                    # dry-run: show what would be fixed
stayawake-security-remediate --apply            # strip/quarantine worm artifacts on a security/auto-clean branch
stayawake-security-remediate --apply --open-pr  # also open one rolling PR per repo
stayawake-security-remediate --remote           # operate on remote GitHub targets from config
```

Drop `--local-only` to also scan the GitHub users/orgs listed in `config/security.yml`.
Use `--fail-on-findings` to make `scan` exit non-zero (the CI gate uses this).

### Local defense-in-depth (hooks + audit)

Harden a developer machine with layered, dependency-free git hooks:

```bash
prevent/install-hooks.sh                 # this repo: pre-commit + post-merge + post-checkout
prevent/install-hooks.sh --template      # auto-protect all FUTURE clones (init.templateDir)
prevent/install-hooks.sh --all ~/dev     # install into every existing repo under a root
```

- **pre-commit** blocks committing worm artifacts (outgoing).
- **post-merge / post-checkout** scan code that *arrives* via pull/merge or clone — the
  layer that catches **evil merges**, the worm's real spread vector.

Audit the machine's security posture (cached GitHub credential, VS Code auto-run / Workspace Trust):

```bash
stayawake-security-audit                 # advisory; add --fail-on-issues for scripts/CI
```

### Environment / secrets

- `SLACK_WEBHOOK_URL` — enables Slack alerts (both bots).
- `GH_SECURITY_TOKEN` (or `GITHUB_TOKEN`) — required for remote scans and opening issues / PRs.

### In GitHub Actions

The bundled workflows run these for you:

- `stayawake-sentinel.yml` — health checks on a `*/5` cron.
- `security-sentinel.yml` — security scan on push to `main` + manual dispatch + weekly backstop.
- `security-remediate.yml` — remediation (dispatch + weekly).
- `worm-guard.yml` — blocks infected / evil-merge changes on every PR and push.

## Quick Setup

1. Fork the repo.
2. Edit `config/urls.yml` with your URLs and settings.
3. (Optional) Add `SLACK_WEBHOOK_URL` and `GITHUB_TOKEN` to repository secrets.
4. Push — the workflow will run on schedule and on push to `config/urls.yml`.

## Configuration reference

`config/urls.yml` fields:

- `settings` (global defaults)
  - `timeout_seconds`: int — request timeout in seconds
  - `retries`: int — number of retries on failure
  - `user_agent`: string — User-Agent header
  - `alert_on_failure`: bool — enable failure alerts
  - `alert_on_recovery`: bool — enable recovery alerts
  - `consecutive_failures_before_alert`: int — require this many consecutive failures before alerting

- `urls` (list of URLs to check)
  - `name` (required): friendly name
  - `url` (required): full URL to check
  - `expected_status`: int — expected HTTP status (e.g., 200)
  - `max_response_ms`: int | null — threshold in milliseconds
  - `check_ssl`: bool — inspect TLS certificate (only for https)
  - `keyword`: string — fail if this substring not found in response body (case-insensitive)
  - `tags`: list[string] — grouping tags
  - `timeout_seconds`: int — per-URL override of timeout

## Reports

All reports are stored under the `reports/` directory committed back to the repo.

- `reports/latest.json` — latest raw results
- `reports/history.json` — append-only history of runs
- `reports/status.json` — machine-readable summary of current status
- `reports/YYYY-MM-DD/HH-MM-UTC.md` — human-readable markdown report for each run

Note: The checker now writes a richer `latest.json` that includes a `summary` block
and an `any_unhealthy` boolean. The reporter appends run summaries to `reports/history.json`,
so per-run JSON files are not created by the checker.

## Local development

The project is a standard `pyproject.toml` package — install it (editable) and run
the console scripts:

```bash
python -m venv .venv && source .venv/bin/activate
pip install -e .
stayawake-health-check --config config/urls.yml
stayawake-health-report
stayawake-health-alert
stayawake-security-scan --config config/security.yml
python -m unittest discover -s tests       # run the test suite
```

`pyproject.toml` is the single source of truth for dependencies and packaging.

Notes on checker behaviour

- By default the checker is non-fatal (it will exit successfully) so that reporting
  and alerting steps can always run in CI. The checker writes full results to
  `reports/latest.json` and appends a run summary to `reports/history.json`; the
  reporter produces the dated markdown report (`reports/YYYY-MM-DD/HH-MM-UTC.md`).
- To make the checker exit with a non-zero code (useful for local debugging), pass
  `--fail-on-unhealthy` to the checker CLI:

```bash
stayawake-health-check --config config/urls.yml --fail-on-unhealthy
```

This will cause the checker to return a non-zero exit code if any URL was flagged
unhealthy. In CI the default non-failing behavior is recommended so that reports
are always generated and committed.
