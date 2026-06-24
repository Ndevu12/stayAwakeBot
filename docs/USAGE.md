# StayAwakeBot — Usage

StayAwakeBot installs as a Python package and exposes both bots as **console scripts**.
The same commands run locally or inside the bundled GitHub Actions workflows.

## Install

```bash
pip install "stayawake @ git+https://github.com/Ndevu12/stayAwakeBot@main"   # or: pipx install "stayawake @ git+…"
# from a clone, for development:
pip install -e .
```

## Health bot — uptime monitoring

Run the pipeline against `config/urls.yml`:

```bash
stayawake-health-check  --config config/urls.yml   # probe URLs → reports/latest.json
stayawake-health-report                            # build status.json, history, dated .md, badge
stayawake-health-alert                             # Slack alert on failures / recoveries
```

By default `check` is **non-fatal** (exits 0) so reporting/alerting always run in CI.
Add `--fail-on-unhealthy` to exit non-zero when any URL is down (handy locally):

```bash
stayawake-health-check --config config/urls.yml --fail-on-unhealthy
```

## Security bot — worm hunting

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
See [SECURITY_ARCHITECTURE.md](SECURITY_ARCHITECTURE.md) for how detection / remediation work.

Reports go to `reports/security/` by default. To run a scan **without touching the
committed reports** (local experiments, CI, scanning someone else's repo), redirect the
output — via `--reports-dir` or `settings.reports_dir` in config:

```bash
stayawake-security-scan --local-only --reports-dir /tmp/sab-reports   # writes only there
stayawake-health-check  --reports-dir /tmp/sab-reports                # same for the health bot
```

## Local defense-in-depth (hooks + audit)

Harden a developer machine with layered, dependency-free git hooks:

```bash
prevent/install-hooks.sh                 # this repo: pre-commit + post-merge + post-checkout
prevent/install-hooks.sh --template      # auto-protect all FUTURE clones (init.templateDir)
prevent/install-hooks.sh --all ~/dev     # install into every existing repo under a root
prevent/install-hooks.sh --force         # overwrite a foreign hook instead of backing it up
```

- **pre-commit** blocks committing worm artifacts (outgoing).
- **post-merge / post-checkout** scan code that *arrives* via pull/merge or clone — the
  layer that catches **evil merges**, the worm's real spread vector. They use
  `--diff-filter=ACMR`, so a payload introduced via a rename is caught too.
- An existing non-StayAwakeBot hook is backed up to `<hook>.pre-stayawake.bak` (never
  silently destroyed); the default install warns if future clones aren't yet protected.

Audit the machine's security posture (cached GitHub credential, VS Code auto-run /
Workspace Trust), and optionally a repo's branch-protection gate:

```bash
stayawake-security-audit                       # advisory; add --fail-on-issues for scripts/CI
stayawake-security-audit --repo owner/name     # also check that Worm Guard is a required check
```

`--repo` needs `GH_SECURITY_TOKEN` (or `GITHUB_TOKEN`) and warns if the default branch
is unprotected or the Worm Guard status check isn't required.

## Environment / secrets

- `SLACK_WEBHOOK_URL` — enables Slack alerts (both bots).
- `GH_SECURITY_TOKEN` (or `GITHUB_TOKEN`) — required for remote scans and opening issues / PRs.

## In GitHub Actions

The bundled workflows run these for you:

- `stayawake-sentinel.yml` — health checks on a `*/5` cron.
- `security-sentinel.yml` — security scan on push to `main` + manual dispatch + weekly backstop.
- `security-remediate.yml` — remediation (dispatch + weekly).
- `worm-guard.yml` — blocks infected / evil-merge changes on every PR and push.

## Deploy your own monitor

1. Fork the repo.
2. Edit `config/urls.yml` with your URLs and settings (see [CONFIGURATION.md](CONFIGURATION.md)).
3. (Optional) Add `SLACK_WEBHOOK_URL` and `GITHUB_TOKEN` to repository secrets.
4. Push — the workflow runs on schedule and on push to `config/urls.yml`.

## Local development

```bash
python -m venv .venv && source .venv/bin/activate
pip install -e .
python -m unittest discover -s tests       # run the test suite (package must be installed)
```

`pyproject.toml` is the single source of truth for dependencies and packaging.
For contribution guidelines and layout, see [CONTRIBUTING.md](../CONTRIBUTING.md).
