# StayAwakeBot — Usage

StayAwakeBot installs as a Python package and exposes both bots as **console scripts**.
The same commands run locally or inside the bundled GitHub Actions workflows.

## Install

```bash
pip install stayawakebot                                                          # released versions, from PyPI
pip install "stayawakebot @ git+https://github.com/Ndevu12/stayAwakeBot@main"     # latest from source (or pipx install "…")
# from a clone, for development:
pip install -e .
```

The PyPI distribution is named **`stayawakebot`** because `stayawake` is already taken on
PyPI by an unrelated project. The import package (`stayawake`) and the `stayawake-*` console
scripts are unchanged.

### Container image (no local Python needed)

The same code ships as a digest-pinned, non-root image on GHCR. Any console script is the
command; mount the repository to scan at `/repo`:

```bash
docker run --rm -v "$PWD:/repo:ro" ghcr.io/ndevu12/stayawakebot \
  stayawake-security-scan --local-only --fail-on-findings
docker run --rm ghcr.io/ndevu12/stayawakebot stayawake-health-check --help
```

Pin a version (`ghcr.io/ndevu12/stayawakebot:0.1.0`) or a commit (`:sha-<commit>`) for
reproducibility; `:latest` tracks the newest release. To build it yourself:

```bash
docker build --build-arg VERSION=0.1.0 -t stayawakebot:local .
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

### Ad-hoc local scanning (no token, no config)

Scanning local code needs **no GitHub token and no config file** — a token is only
for cloning private remotes or opening PRs. Point the scanner at paths, or just run it
inside a repo:

```bash
stayawake-security-scan                      # no args → scans the repo you're standing in
stayawake-security-scan ~/dev/some-project   # scan a specific repo (or a folder of repos)
stayawake-security-scan ./a ./b --path ./c   # several at once (positional and/or --path)
```

A path may be a single repository or a directory containing many — the scanner walks it
for git repos. Explicit paths imply `--local-only` (nothing is sent to GitHub). With no
paths and nothing configured, it scans the current repository (found by walking up to the
nearest `.git`), so a bare `stayawake-security-scan` "just works" after `pip install`.

Remediation is **safe by default (dry-run)**:

```bash
stayawake-security-remediate                    # dry-run: show what would be fixed
stayawake-security-remediate --apply            # strip/quarantine worm artifacts on a security/auto-clean branch
stayawake-security-remediate --apply --open-pr  # also open one rolling PR per repo
stayawake-security-remediate --remote           # operate on remote GitHub targets from config
```

**Read-only fallback (remediation ladder):** when `--open-pr` / `--remote` can't push a
fix branch (you only have read access to the target), StayAwakeBot doesn't discard the
fix — it degrades down a ladder:

1. **Fork → cross-fork PR** — if the token can fork, it pushes the fix to a fork under
   your account and opens a PR from the fork into the upstream (de-duplicated; handles
   the fork's asynchronous creation).
2. Otherwise it writes the fix as a `git am`-able **patch** under `sab-patches/` **and**
   (if the token has `issues: write`) opens a **de-duplicated issue** on the target repo
   with the findings, so the owner is notified.

So remediation always produces something actionable — a fork PR, a patch, a heads-up, or
some combination — even without write access to the target.

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

`--repo` needs a GitHub credential (an env token or a `gh auth login` session — see
[Authentication](#authentication)) and warns if the default branch is unprotected or
the Worm Guard status check isn't required.

## Authentication

**Local scanning needs no credential** — a GitHub token is only used to clone *private*
remotes and to write (open PRs / issues, read branch protection). However it's supplied,
the token is handed to git via `GIT_ASKPASS` — never embedded in a clone/push URL or the
process arguments, so it can't leak through `ps`, git's error output, or CI logs.

**You only ever configure one token: `GH_SECURITY_TOKEN`.** When a token is needed,
StayAwakeBot resolves one in this order:

1. **`GH_SECURITY_TOKEN`** — the one token you set up (a PAT). Export it on a dev
   machine, or add it as a repo secret in CI. This is the only credential you configure,
   and the only one that can reach **other** repos (the `--remote` org sweep).
2. **`GITHUB_TOKEN`** — the token GitHub Actions mints automatically for every run. You
   never set this up: the `GITHUB_` prefix is reserved, so you *can't* even create a
   secret with that name. It's the zero-config fallback for **same-repo** work inside
   Actions, and it can't reach other repos.
3. A **GitHub App** installation token — for org-wide automation (see below). Minted on
   demand from the App's key, scoped to exactly what the App was granted, and rotated
   every hour. Preferred over a PAT for continuous/org use.
4. Your **GitHub CLI** session — `gh auth token` — short-lived and never stored by
   StayAwakeBot, which is what the hygiene audit recommends over a cached PAT.

In short: in CI, same-repo jobs ride the automatic `GITHUB_TOKEN` for free and only
cross-repo work needs the `GH_SECURITY_TOKEN` secret; on a dev machine, the simplest
setup is `gh auth login` once (nothing to export, nothing persisted), or export
`GH_SECURITY_TOKEN`. If `gh` isn't installed, get it from <https://cli.github.com>
(StayAwakeBot never installs software for you). A `gh` that is missing, logged out, or
slow never breaks a run — local scans still work, and remote / write operations print
exactly what to do.

### Minimal token scopes per command

Grant the least privilege the task needs (fine-grained PAT permission shown; the classic
scope is in parentheses):

| Command | Needs a token? | Permission (classic) |
| --- | --- | --- |
| `stayawake-security-scan <path>` / public remotes | no | — |
| `stayawake-security-scan` private remotes | read | Contents + Metadata: Read (`repo`) |
| `stayawake-security-remediate --open-pr` / `--remote` | write | Contents + Pull requests: R/W (`repo`) |
| ↳ fork fallback (cross-fork PR when you can't push upstream) | fork + PR | Pull requests: R/W on your fork (`public_repo` / `repo`) |
| ↳ patch/issue fallback (no write at all) | none / issues | Issues: R/W for the notify issue (`repo` / `public_repo`); patch needs nothing |
| `stayawake-security-alert` (GitHub issue) | write | Issues: R/W (`repo` / `public_repo`) |
| `stayawake-security-audit --repo` | read | Administration: Read (`repo`) |

### GitHub App (organization **or** personal account)

A **GitHub App** is the hardened credential for continuous scanning/remediation, and it
is **not org-only** — GitHub Apps install on either a personal (user) account or an
organization, and StayAwakeBot treats both the same. You (or an org admin) install it
once on the chosen repos and it mints a fresh **1-hour installation token** per run,
scoped to exactly the App's granted permissions — nothing long-lived to leak, fully
revocable, and the install itself defines which repos are in scope (no `targets.github`
list needed). The private key stays in memory; signing is delegated to a vetted crypto
library (never hand-rolled).

For a personal account with a handful of repos, `gh auth login` or a fine-grained PAT is
simpler. Reach for an App when you want that same rotating, narrowly-scoped, revocable
token model on your own repos — or when you manage many.

It's an **opt-in extra** so the base install stays stdlib-only:

```bash
pip install "stayawake[app]"          # adds PyJWT[crypto] — only needed for App auth
export GH_APP_ID=123456
export GH_APP_PRIVATE_KEY="$(cat your-app.private-key.pem)"   # or GH_APP_PRIVATE_KEY_PATH=…
# optional; auto-detected when the App has exactly one installation:
export GH_APP_INSTALLATION_ID=98765
stayawake-security-scan               # scans every repo the installation can see
stayawake-security-remediate --remote # opens a dedup'd fix PR per infected install repo
```

If the App env is set without the extra installed, StayAwakeBot prints a clear
`pip install "stayawake[app]"` hint rather than failing obscurely. An explicit
`GH_SECURITY_TOKEN` still takes precedence (handy for a one-off human override).

**Minimal App permissions** (Repository permissions): **Metadata: Read** (always) +
**Contents: Read** to scan; add **Contents: Read & write** and **Pull requests: Read &
write** to open remediation PRs.

Other secrets:

- `SLACK_WEBHOOK_URL` — enables Slack alerts (both bots).

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
