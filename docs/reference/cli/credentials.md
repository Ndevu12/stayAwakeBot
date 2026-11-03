---
description: Which saw operations need a GitHub token, the least privilege each one requires, and how the token is handled.
---

# Credentials

Local scanning needs **no credential**. A GitHub token is only used to clone private repositories and
to write — open PRs or issues, read branch protection. However it is supplied, the token reaches git
through `GIT_ASKPASS`, never through a URL or process arguments, so it cannot leak via `ps`, git's
error output, or CI logs.

You configure only `GH_SECURITY_TOKEN`. When a token is needed, `saw` resolves one in this order:

1. **`GH_SECURITY_TOKEN`** — the one you set up. The only credential that can reach *other*
   repositories, so the one an org-wide sweep needs.
2. **`GITHUB_TOKEN`** — minted automatically for every GitHub Actions run; the zero-config fallback
   for same-repo work in CI. It cannot reach other repositories.
3. A **GitHub App** installation token — minted on demand, scoped to what the App was granted, and
   rotated hourly. Preferred for continuous or org-wide use; signing is built in, so App auth needs
   no extra install. Apps install on a personal account as well as an organisation, and the
   installation itself defines which repositories are in scope.
4. Your **GitHub CLI** session (`gh auth token`) — short-lived and never stored by `saw`.

Point `saw` at an existing App with `GH_APP_ID` and `GH_APP_PRIVATE_KEY` (or
`GH_APP_PRIVATE_KEY_PATH`), plus `GH_APP_INSTALLATION_ID` when the App has more than one
installation. An explicit `GH_SECURITY_TOKEN` still wins, for a one-off human override.

## Least privilege per command

Fine-grained permission first; the classic scope in parentheses.

| Command | Needs a token? | Permission (classic) |
| --- | --- | --- |
| `saw scan <path>`, public remotes | no | — |
| `saw scan --remote` (private) | read | Contents + Metadata: Read (`repo`) |
| `saw fix`, `saw fix --remote` | write | Contents + Pull requests: R/W (`repo`) |
| ↳ fork fallback | fork + PR | Pull requests: R/W on your fork (`public_repo` / `repo`) |
| ↳ patch / issue fallback | none / issues | Issues: R/W (`repo` / `public_repo`); a patch needs nothing |
| `saw guard setup --pr` / `--user` / `--org` | write + **workflows** | Contents + Pull requests + **Workflows**: R/W (`repo` + **`workflow`**) |
| `saw scan --alert` | write | Issues: R/W (`repo` / `public_repo`) |
| `saw audit --repo` | read | Administration: Read (`repo`) |

Missing the `workflow` permission is **not** "no write access" — GitHub rejects pushes that touch
`.github/workflows/*` without it. Fix it with `gh auth refresh -h github.com -s repo,workflow`, or
use `saw auth app register`.
