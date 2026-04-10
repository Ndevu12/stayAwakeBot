<!-- STAYAWAKEBOT_BADGE -->
![Health](https://img.shields.io/badge/health-0%2F3%20up-red)
<!-- STAYAWAKEBOT_BADGE_END -->


# StayAwakeBot

A GitHub Actions-native URL health monitoring bot. Runs entirely on GitHub Actions and writes reports back to the repository.

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

## Local development

Use Pipenv to create an isolated environment and install dependencies.

```bash
pip install pipenv
pipenv shell
pipenv install
pipenv run python scripts/checker.py --config config/urls.yml
pipenv run python scripts/reporter.py
pipenv run python scripts/alerter.py
```

This project uses `Pipfile` for dependency management; do not rely on a `requirements.txt` file.
